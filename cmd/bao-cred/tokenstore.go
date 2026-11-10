package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	// keyringService is the stable keyring address of Named Tokens (account
	// = identity name), so other tools such as secretspec can reference it.
	keyringService = "bao-cred"
	// keyringProbeAccount is read, never written, to learn whether the
	// keyring answers.
	keyringProbeAccount = "bao-cred-probe"

	storeAuto    = "auto"
	storeKeyring = "keyring"
	storeFile    = "file"

	// staleSessionAge prunes session token files untouched for this long;
	// session tokens unused for a whole period are dead anyway.
	staleSessionAge = 48 * time.Hour
)

// keyringTimeout bounds each keyring call: a locked keyring may wait for an
// unlock prompt nobody sees in a headless agent shell.
var keyringTimeout = 5 * time.Second

var (
	errNoNamedToken   = errors.New("no Named Token stored")
	errNoSessionToken = errors.New("no session token stored")
	errKeyringTimeout = errors.New("keyring did not answer in time (locked, or waiting for an unlock prompt)")
)

type keyringProvider interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (systemKeyring) Set(service, user, secret string) error {
	return keyring.Set(service, user, secret)
}
func (systemKeyring) Delete(service, user string) error { return keyring.Delete(service, user) }

// keyringBackend is a package variable so tests can replace the OS keyring.
var keyringBackend keyringProvider = systemKeyring{}

// tokenStore keeps every token bao-cred stores. Named Tokens go to the OS
// keyring when it answers, else to a file; session tokens, one per agent
// conversation and short-lived, always go to files. A non-secret index
// records where each Named Token went, so a token in a keyring that is now
// locked is reported as such instead of looking missing, and a stale keyring
// copy left behind while it was locked never shadows a newer file.
type tokenStore struct {
	probeOnce sync.Once
	probeErr  error
}

var (
	currentTokensMu sync.Mutex
	currentTokens   *tokenStore
)

// tokens returns the process's token store; the keyring is probed once, on
// first use.
func tokens() *tokenStore {
	currentTokensMu.Lock()
	defer currentTokensMu.Unlock()
	if currentTokens == nil {
		currentTokens = &tokenStore{}
	}

	return currentTokens
}

// resetTokens forgets the keyring probe; tests use it after replacing the
// keyring.
func resetTokens() {
	currentTokensMu.Lock()
	defer currentTokensMu.Unlock()
	currentTokens = nil
}

func withKeyringTimeout[T any](call func() (T, error)) (T, error) {
	type result struct {
		value T
		err   error
	}

	// The backend is read before starting, because a timed-out call keeps
	// running in the background.
	done := make(chan result, 1)
	go func() {
		value, err := call()
		done <- result{value, err}
	}()

	select {
	case got := <-done:
		return got.value, got.err
	case <-time.After(keyringTimeout):
		var zero T
		return zero, errKeyringTimeout
	}
}

// keyringAvailable reports why the keyring can't be used, or nil. A missing
// probe entry means the keyring answered.
func (s *tokenStore) keyringAvailable() error {
	s.probeOnce.Do(func() {
		backend := keyringBackend
		_, err := withKeyringTimeout(func() (string, error) { return backend.Get(keyringService, keyringProbeAccount) })
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			s.probeErr = err
		}
	})

	return s.probeErr
}

func (s *tokenStore) keyringGet(name string) (string, error) {
	backend := keyringBackend
	return withKeyringTimeout(func() (string, error) { return backend.Get(keyringService, name) })
}

func (s *tokenStore) keyringSet(name, token string) error {
	backend := keyringBackend
	_, err := withKeyringTimeout(func() (struct{}, error) { return struct{}{}, backend.Set(keyringService, name, token) })
	return err
}

func (s *tokenStore) keyringDelete(name string) error {
	backend := keyringBackend
	_, err := withKeyringTimeout(func() (struct{}, error) { return struct{}{}, backend.Delete(keyringService, name) })
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}

	return err
}

func stateDir() (string, error) {
	if state := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(state) {
		return filepath.Join(state, "bao-cred"), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate state directory: %w", err)
	}

	return filepath.Join(home, ".local", "state", "bao-cred"), nil
}

func namedTokenPath(name string) (string, error) {
	directory, err := stateDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, name+".token"), nil
}

func sessionTokenPath(project, session string) (string, error) {
	directory, err := stateDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, "sessions", project, session+".token"), nil
}

// tokenIndex maps Named Identity names to the store holding their token.
type tokenIndex struct {
	Named map[string]string `json:"named"`
}

func indexPath() (string, error) {
	directory, err := stateDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, "index.json"), nil
}

func readIndex() (tokenIndex, error) {
	index := tokenIndex{Named: map[string]string{}}
	path, err := indexPath()
	if err != nil {
		return index, err
	}

	contents, err := os.ReadFile(path) // #nosec G304 -- bao-cred's own state.
	if errors.Is(err, fs.ErrNotExist) {
		return index, nil
	}

	if err != nil {
		return index, fmt.Errorf("read token index: %w", err)
	}

	if err := json.Unmarshal(contents, &index); err != nil {
		return index, fmt.Errorf("decode token index %s: %w", path, err)
	}

	if index.Named == nil {
		index.Named = map[string]string{}
	}

	return index, nil
}

func writeIndex(index tokenIndex) error {
	path, err := indexPath()
	if err != nil {
		return err
	}

	contents, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode token index: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	return writeFile(path, append(contents, '\n'))
}

func readTokenFile(path string) (string, error) {
	contents, err := os.ReadFile(path) // #nosec G304 -- validated names under bao-cred's own state.
	if err != nil {
		return "", err
	}

	token := strings.TrimSpace(string(contents))
	if token == "" {
		return "", fs.ErrNotExist
	}

	return token, nil
}

func writeTokenFile(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	return writeFile(path, []byte(token+"\n"))
}

// loadNamed returns the Named Token of name and the store it came from.
func (s *tokenStore) loadNamed(name string) (string, string, error) {
	index, err := readIndex()
	if err != nil {
		return "", "", err
	}

	path, err := namedTokenPath(name)
	if err != nil {
		return "", "", err
	}

	missing := fmt.Errorf("%w for identity %q; run bao-cred auth %s", errNoNamedToken, name, name)
	switch index.Named[name] {
	case storeKeyring:
		if err := s.keyringAvailable(); err != nil {
			return "", "", fmt.Errorf("the Named Token for %q is in the OS keyring, which is unavailable: %w\n"+
				"hint: unlock the keyring, or mint a file copy with bao-cred auth --store file %s", name, err, name)
		}

		token, err := s.keyringGet(name)
		if errors.Is(err, keyring.ErrNotFound) || (err == nil && strings.TrimSpace(token) == "") {
			return "", "", missing
		}

		if err != nil {
			return "", "", fmt.Errorf("read the Named Token for %q from the keyring: %w", name, err)
		}

		return strings.TrimSpace(token), storeKeyring, nil
	case storeFile:
		token, err := readTokenFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			return "", "", missing
		}

		if err != nil {
			return "", "", fmt.Errorf("read Named Token: %w", err)
		}

		return token, storeFile, nil
	}

	// Not indexed, e.g. after the index was deleted: look in both stores.
	if token, err := readTokenFile(path); err == nil {
		return token, storeFile, nil
	}

	keyringErr := s.keyringAvailable()
	if keyringErr == nil {
		if token, err := s.keyringGet(name); err == nil && strings.TrimSpace(token) != "" {
			return strings.TrimSpace(token), storeKeyring, nil
		}

		return "", "", missing
	}

	return "", "", fmt.Errorf("%w (the OS keyring is unavailable, so a token stored there can't be read: %w)", missing, keyringErr)
}

// saveNamed stores token in prefer's store, falling back from the keyring to
// a file in auto mode with a warning, and records the choice in the index.
func (s *tokenStore) saveNamed(name, token, prefer string, warn progressFunc) (string, error) {
	path, err := namedTokenPath(name)
	if err != nil {
		return "", err
	}

	index, err := readIndex()
	if err != nil {
		return "", err
	}

	store := storeFile
	if prefer != storeFile {
		err := s.keyringAvailable()
		if err == nil {
			err = s.keyringSet(name, token)
		}

		switch {
		case err == nil:
			store = storeKeyring
		case prefer == storeKeyring:
			return "", fmt.Errorf("store the Named Token in the keyring: %w", err)
		default:
			warn(fmt.Sprintf("warning: the OS keyring is unavailable (%v); storing the Named Token in %s", err, path))
		}
	}

	if store == storeFile {
		if err := writeTokenFile(path, token); err != nil {
			return "", fmt.Errorf("store Named Token: %w", err)
		}

		// The index makes a keyring copy irrelevant; remove it when the
		// keyring answers, or the next time it does.
		if s.keyringAvailable() == nil {
			_ = s.keyringDelete(name)
		}
	} else if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		warn(fmt.Sprintf("warning: could not remove the old token file %s: %v", path, err))
	}

	index.Named[name] = store
	if err := writeIndex(index); err != nil {
		return "", err
	}

	return store, nil
}

// deleteNamed removes name's Named Token from both stores and the index.
func (s *tokenStore) deleteNamed(name string, warn progressFunc) error {
	path, err := namedTokenPath(name)
	if err != nil {
		return err
	}

	index, err := readIndex()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete token file: %w", err)
	}

	if err := s.keyringAvailable(); err != nil {
		if index.Named[name] == storeKeyring {
			warn(fmt.Sprintf("warning: the OS keyring is unavailable (%v); its entry for %q stays until you delete it "+
				"(e.g. secret-tool clear service %s username %s), but bao-cred no longer uses it", err, name, keyringService, name))
		}
	} else if err := s.keyringDelete(name); err != nil {
		return fmt.Errorf("delete keyring entry: %w", err)
	}

	delete(index.Named, name)
	return writeIndex(index)
}

// loadSession returns the stored token of project's agent session.
func (s *tokenStore) loadSession(project, session string) (string, error) {
	path, err := sessionTokenPath(project, session)
	if err != nil {
		return "", err
	}

	token, err := readTokenFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", errNoSessionToken
	}

	if err != nil {
		return "", fmt.Errorf("read session token: %w", err)
	}

	return token, nil
}

// saveSession stores a session token and prunes the project's stale ones. A
// pruned session that comes back mints a new token for the same entity, so
// nothing is lost.
func (s *tokenStore) saveSession(project, session, token string) error {
	path, err := sessionTokenPath(project, session)
	if err != nil {
		return err
	}

	if err = writeTokenFile(path, token); err != nil {
		return fmt.Errorf("store session token: %w", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return nil //nolint:nilerr // Pruning is best effort.
	}

	for _, entry := range entries {
		other := filepath.Join(filepath.Dir(path), entry.Name())
		info, err := entry.Info()
		if err != nil || other == path || !strings.HasSuffix(entry.Name(), ".token") || time.Since(info.ModTime()) < staleSessionAge {
			continue
		}

		_ = os.Remove(other)
	}

	return nil
}

// touchSession marks a session token as in use, so pruning keeps it.
func (s *tokenStore) touchSession(project, session string) {
	if path, err := sessionTokenPath(project, session); err == nil {
		now := time.Now()
		_ = os.Chtimes(path, now, now)
	}
}

// deleteSessions removes every stored session token of project.
func (s *tokenStore) deleteSessions(project string) error {
	directory, err := stateDir()
	if err != nil {
		return err
	}

	if err := os.RemoveAll(filepath.Join(directory, "sessions", project)); err != nil {
		return fmt.Errorf("delete session tokens: %w", err)
	}

	return nil
}
