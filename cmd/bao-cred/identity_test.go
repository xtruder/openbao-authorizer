package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

const loginTestToken = "login-token"

type fakeKeyring struct {
	mu      sync.Mutex
	entries map[string]string
	err     error
	block   chan struct{}
	probes  int
}

func (k *fakeKeyring) wait() error {
	if k.block != nil {
		<-k.block
	}

	return k.err
}

func (k *fakeKeyring) Get(service, user string) (string, error) {
	if user == keyringProbeAccount {
		k.mu.Lock()
		k.probes++
		k.mu.Unlock()
	}

	if err := k.wait(); err != nil {
		return "", err
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	value, ok := k.entries[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}

	return value, nil
}

func (k *fakeKeyring) Set(service, user, secret string) error {
	if err := k.wait(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	k.entries[service+"/"+user] = secret
	return nil
}

func (k *fakeKeyring) Delete(service, user string) error {
	if err := k.wait(); err != nil {
		return err
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.entries[service+"/"+user]; !ok {
		return keyring.ErrNotFound
	}

	delete(k.entries, service+"/"+user)
	return nil
}

func (k *fakeKeyring) get(name string) string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.entries[keyringService+"/"+name]
}

// useKeyring replaces the OS keyring; a non-nil err makes it unreachable.
func useKeyring(t *testing.T, err error) *fakeKeyring {
	t.Helper()
	fake := &fakeKeyring{entries: map[string]string{}, err: err}
	previous := keyringBackend
	keyringBackend = fake
	resetTokens()
	t.Cleanup(func() {
		keyringBackend = previous
		resetTokens()
	})
	return fake
}

// fakeTokenStore serves the token endpoints that Named Tokens use.
type fakeTokenStore struct {
	*httptest.Server

	mu       sync.Mutex
	minted   int
	sessions int
	valid    map[string]bool
	// parents maps session tokens to the Named Token that minted them, so
	// revoking a Named Token revokes its sessions, as in OpenBao.
	parents        map[string]string
	ttls           map[string]int
	revoked        []string
	renewed        []string
	creates        []map[string]any
	sessionCreates []map[string]any
}

func newFakeTokenStore(t *testing.T) *fakeTokenStore {
	t.Helper()
	store := &fakeTokenStore{valid: map[string]bool{}, parents: map[string]string{}, ttls: map[string]int{}}
	store.Server = httptest.NewServer(http.HandlerFunc(store.serve))
	t.Cleanup(store.Close)
	return store
}

func (s *fakeTokenStore) serve(response http.ResponseWriter, request *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := request.Header.Get("X-Vault-Token")
	response.Header().Set("Content-Type", "application/json")
	if request.URL.Path == "/v1/auth/token/create/named-identity" {
		if token != loginTestToken {
			forbidden(response)
			return
		}

		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		s.creates = append(s.creates, body)
		s.minted++
		minted := fmt.Sprintf("named-%d", s.minted)
		s.valid[minted] = true
		_, _ = fmt.Fprintf(response, `{"auth":{"client_token":%q,"renewable":true,"lease_duration":7776000}}`, minted)
		return
	}

	if !s.valid[token] {
		forbidden(response)
		return
	}

	switch request.URL.Path {
	case "/v1/auth/token/create/agent-session":
		if !strings.HasPrefix(token, "named-") {
			forbidden(response)
			return
		}

		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		s.sessionCreates = append(s.sessionCreates, body)
		s.sessions++
		minted := fmt.Sprintf("session-%d", s.sessions)
		s.valid[minted] = true
		s.parents[minted] = token
		_, _ = fmt.Fprintf(response, `{"auth":{"client_token":%q,"renewable":true,"lease_duration":86400}}`, minted)
	case "/v1/auth/token/lookup-self":
		ttl, ok := s.ttls[token]
		if !ok {
			ttl = 7776000
		}

		_, _ = fmt.Fprintf(response, `{"data":{"entity_id":"entity-1","ttl":%d,"renewable":true}}`, ttl)
	case "/v1/auth/token/renew-self":
		s.renewed = append(s.renewed, token)
		_, _ = fmt.Fprint(response, `{"auth":{"client_token":"","renewable":true,"lease_duration":7776000}}`)
	case "/v1/auth/token/revoke-self":
		s.revoked = append(s.revoked, token)
		delete(s.valid, token)
		for child, parent := range s.parents {
			if parent == token {
				delete(s.valid, child)
			}
		}

		response.WriteHeader(http.StatusNoContent)
	default:
		http.Error(response, "unexpected request", http.StatusBadRequest)
	}
}

func (s *fakeTokenStore) snapshot() (revoked, renewed []string, creates []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.revoked...), append([]string(nil), s.renewed...), s.creates
}

func forbidden(response http.ResponseWriter) {
	response.WriteHeader(http.StatusForbidden)
	_, _ = fmt.Fprint(response, `{"errors":["permission denied"]}`)
}

// setupIdentityEnvironment isolates HOME and the state directory, logs the
// human in, and clears every token variable.
func setupIdentityEnvironment(t *testing.T, openBaoURL string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	setupEnvironment(t, "", openBaoURL)
	t.Setenv("BAO_TOKEN", "")
	t.Setenv("BAO_IDENTITY", "")
	t.Setenv("BAO_NO_TOKEN_FILE", "")
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte(loginTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return home
}

func TestAuthStoresInKeyringAndRevokesPrevious(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	// A Named Token in BAO_TOKEN, as an .envrc exports it, must not mint.
	t.Setenv("BAO_TOKEN", "named-from-envrc")

	for range 2 {
		var stdout bytes.Buffer
		if err := run([]string{"auth", "myproject"}, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}

		var status identityStatus
		if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
			t.Fatal(err)
		}

		if status.Identity != "myproject" || status.Store != storeKeyring || status.EntityID != "entity-1" || !status.Renewable {
			t.Fatalf("status = %+v", status)
		}
	}

	if got := ring.get("myproject"); got != "named-2" {
		t.Fatalf("keyring holds %q, want named-2", got)
	}

	revoked, _, creates := bao.snapshot()
	if len(revoked) != 1 || revoked[0] != "named-1" {
		t.Fatalf("revoked = %v, want the previous token", revoked)
	}

	meta, _ := creates[0]["meta"].(map[string]any)
	if creates[0]["entity_alias"] != "myproject" || meta["identity"] != "myproject" {
		t.Fatalf("create request = %v", creates[0])
	}
}

func TestAuthFallsBackToFileWithoutKeyring(t *testing.T) {
	bao := newFakeTokenStore(t)
	home := setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, errors.New("no secret service"))

	var stderr bytes.Buffer
	if err := run([]string{"auth", "--identity", "myproject"}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stderr.String(), "keyring is unavailable") {
		t.Fatalf("stderr = %q, want a fallback warning", stderr.String())
	}

	path := filepath.Join(home, "state", "bao-cred", "myproject.token")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %v", info.Mode().Perm())
	}

	token, store, err := tokens().loadNamed("myproject")
	if err != nil || token != "named-1" || store != storeFile {
		t.Fatalf("load = %q, %q, %v", token, store, err)
	}

	if err := run([]string{"auth", "--store", "keyring", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("--store keyring succeeded without a keyring")
	}
}

func TestAuthStoreFileRemovesKeyringCopy(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"auth", "--store", "file", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if got := ring.get("myproject"); got != "" {
		t.Fatalf("keyring still holds %q", got)
	}

	if token, store, err := tokens().loadNamed("myproject"); err != nil || token != "named-2" || store != storeFile {
		t.Fatalf("load = %q, %q, %v", token, store, err)
	}
}

func TestKeyringTimeoutFallsBackToFile(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	ring.block = make(chan struct{})
	t.Cleanup(func() { close(ring.block) })
	previous := keyringTimeout
	keyringTimeout = 10 * time.Millisecond
	t.Cleanup(func() { keyringTimeout = previous })

	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if token, store, err := tokens().loadNamed("myproject"); err != nil || token != "named-1" || store != storeFile {
		t.Fatalf("load = %q, %q, %v", token, store, err)
	}
}

func TestAuthRequiresLoginAndValidName(t *testing.T) {
	bao := newFakeTokenStore(t)
	home := setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)

	for _, arguments := range [][]string{{"auth"}, {"auth", "My_Project"}, {"auth", "a", "b"}, {"auth", "--store", "disk", "a"}} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
			t.Fatalf("%v: error = %v, want usage error", arguments, err)
		}
	}

	if err := os.Remove(filepath.Join(home, ".vault-token")); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "bao login") {
		t.Fatalf("error = %v, want a bao login hint", err)
	}
}

func TestRequesterTokenUsesNamedIdentity(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)

	// A selected identity without a token fails closed instead of using
	// ~/.vault-token.
	if _, err := requesterToken(t.Context(), "myproject"); !errors.Is(err, errNoNamedToken) {
		t.Fatalf("error = %v, want errNoNamedToken", err)
	}

	ring.entries[keyringService+"/myproject"] = "named-stored"
	if got, err := requesterToken(t.Context(), "myproject"); err != nil || got != "named-stored" {
		t.Fatalf("got %q, %v", got, err)
	}

	t.Setenv("VAULT_TOKEN", "explicit")
	if got, err := requesterToken(t.Context(), "myproject"); err != nil || got != "explicit" {
		t.Fatalf("explicit token: got %q, %v", got, err)
	}

	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_IDENTITY", "myproject")
	root := newRootCommand(runCredentials)
	root.SetArgs([]string{"read", "secret/app"})
	command, _, err := root.Find([]string{"read"})
	if err != nil {
		t.Fatal(err)
	}

	if got := identityFlag(command); got != "myproject" {
		t.Fatalf("identity from BAO_IDENTITY = %q", got)
	}
}

func TestEnvExportsAndRenewsNamedToken(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	t.Setenv("BAO_IDENTITY", "myproject")
	if err := run([]string{"auth"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := run([]string{"env"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	want := "export BAO_TOKEN='named-1'\nexport VAULT_TOKEN='named-1'\nexport BAO_NO_TOKEN_FILE='1'\n"
	if stdout.String() != want {
		t.Fatalf("env output = %q, want %q", stdout.String(), want)
	}

	if _, renewed, _ := bao.snapshot(); len(renewed) != 1 || renewed[0] != "named-1" {
		t.Fatalf("renewed = %v", renewed)
	}

	stdout.Reset()
	if err := run([]string{"status"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), `"store": "keyring"`) {
		t.Fatalf("status = %q, %v", stdout.String(), err)
	}
}

func TestEnvFailsClosedWithInvalidToken(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	ring.entries[keyringService+"/myproject"] = "named-expired"

	var stdout bytes.Buffer
	err := run([]string{"env", "myproject"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "bao-cred auth myproject") {
		t.Fatalf("error = %v, want an auth hint", err)
	}

	if stdout.String() != "unset BAO_TOKEN VAULT_TOKEN\nexport BAO_NO_TOKEN_FILE='1'\n" {
		t.Fatalf("env output = %q", stdout.String())
	}

	if err := run([]string{"status", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("status succeeded with an invalid token")
	}
}

func TestEnvExportsWhenOpenBaoIsUnreachable(t *testing.T) {
	setupIdentityEnvironment(t, "http://127.0.0.1:1")
	ring := useKeyring(t, nil)
	ring.entries[keyringService+"/myproject"] = "named-stored"

	var stdout, stderr bytes.Buffer
	if err := run([]string{"env", "myproject"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout.String(), "export BAO_TOKEN='named-stored'") || !strings.Contains(stderr.String(), "warning: renew") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestLogoutRevokesAndDeletes(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"logout", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if revoked, _, _ := bao.snapshot(); len(revoked) != 1 || revoked[0] != "named-1" {
		t.Fatalf("revoked = %v", revoked)
	}

	if _, _, err := tokens().loadNamed("myproject"); !errors.Is(err, errNoNamedToken) {
		t.Fatalf("token still stored: %v", err)
	}

	var stderr bytes.Buffer
	if err := run([]string{"logout", "myproject"}, &bytes.Buffer{}, &stderr); err != nil || !strings.Contains(stderr.String(), "no Named Token") {
		t.Fatalf("second logout = %v, %q", err, stderr.String())
	}
}

func TestLogoutWarnsWhenRevocationFails(t *testing.T) {
	setupIdentityEnvironment(t, "http://127.0.0.1:1")
	ring := useKeyring(t, nil)
	ring.entries[keyringService+"/myproject"] = "named-stored"

	var stderr bytes.Buffer
	if err := run([]string{"logout", "--quiet", "myproject"}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stderr.String(), "could not revoke the Named Token") {
		t.Fatalf("stderr = %q, want a revocation warning", stderr.String())
	}

	if ring.get("myproject") != "" {
		t.Fatal("token still stored")
	}
}
