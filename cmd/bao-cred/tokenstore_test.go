package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

var errLocked = errors.New("collection is locked")

func TestKeyringIsProbedOncePerProcess(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if _, _, err := tokens().loadNamed("myproject"); err != nil {
			t.Fatal(err)
		}
	}

	if ring.probes != 1 {
		t.Fatalf("keyring probed %d times, want 1", ring.probes)
	}
}

// A token stored in the keyring while it worked is reported, not treated as
// missing, once the keyring is locked.
func TestLockedKeyringHoldingTheTokenIsReported(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	ring.err = errLocked
	resetTokens()
	_, err := requesterToken(t.Context(), "myproject")
	if err == nil || errors.Is(err, errNoNamedToken) || !strings.Contains(err.Error(), "in the OS keyring, which is unavailable") ||
		!strings.Contains(err.Error(), "--store file") {
		t.Fatalf("error = %v, want a locked-keyring report", err)
	}

	// Logout still removes bao-cred's record, and says the entry stays.
	var stderr bytes.Buffer
	if err := tokens().deleteNamed("myproject", newProgress(&stderr, false)); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stderr.String(), "its entry for \"myproject\" stays") {
		t.Fatalf("stderr = %q, want a leftover-entry warning", stderr.String())
	}
}

// Without an index entry a locked keyring might hold the token, so the error
// says so.
func TestUnindexedTokenWithLockedKeyring(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, errLocked)
	_, _, err := tokens().loadNamed("myproject")
	if !errors.Is(err, errNoNamedToken) || !strings.Contains(err.Error(), "keyring is unavailable") {
		t.Fatalf("error = %v", err)
	}
}

// A keyring copy left behind while the keyring was locked never shadows the
// newer file copy.
func TestStaleKeyringCopyIsIgnored(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	ring.err = errLocked
	resetTokens()
	if err := run([]string{"auth", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	ring.err = nil
	resetTokens()
	if ring.get("myproject") != "named-1" {
		t.Fatalf("keyring holds %q, want the stale named-1", ring.get("myproject"))
	}

	token, store, err := tokens().loadNamed("myproject")
	if err != nil || token != "named-2" || store != storeFile {
		t.Fatalf("load = %q, %q, %v; want the file's named-2", token, store, err)
	}
}
