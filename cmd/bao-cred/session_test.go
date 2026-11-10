package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// setupSession mints app's Named Token and enters an agent session.
func setupSession(t *testing.T, session string) (*fakeTokenStore, string) {
	t.Helper()
	bao := newFakeTokenStore(t)
	home := setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	if err := run([]string{"auth", "app"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_IDENTITY", "app")
	t.Setenv("OPENCODE_SESSION_ID", session)
	return bao, home
}

func TestAuthMintsWithGrantPolicies(t *testing.T) {
	bao, _ := setupSession(t, "")
	_, _, creates := bao.snapshot()
	policies, _ := creates[0]["policies"].([]any)
	want := []any{"named-identity", "agent-grant-project-app", "agent-grant-global"}
	if !slices.Equal(policies, want) {
		t.Fatalf("policies = %v, want %v", policies, want)
	}
}

func TestSessionTokenIsMintedOnceAndReused(t *testing.T) {
	bao, home := setupSession(t, "ses_Abc123")
	for range 2 {
		token, err := commandToken(t)
		if err != nil || token != "session-1" {
			t.Fatalf("token = %q, %v", token, err)
		}
	}

	bao.mu.Lock()
	creates := bao.sessionCreates
	bao.mu.Unlock()
	if len(creates) != 1 {
		t.Fatalf("session mints = %d, want 1", len(creates))
	}

	meta, _ := creates[0]["meta"].(map[string]any)
	policies, _ := creates[0]["policies"].([]any)
	if creates[0]["entity_alias"] != "app.ses_Abc123" || meta["session"] != "ses_Abc123" || meta["identity"] != "app" ||
		!slices.Equal(policies, []any{"agent-session", "agent-grant-project-app", "agent-grant-global"}) {
		t.Fatalf("session create = %v", creates[0])
	}

	info, err := os.Stat(filepath.Join(home, "state", "bao-cred", "sessions", "app", "ses_Abc123.token"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("session token file = %v, %v", info, err)
	}

	// Each session, a subagent's too, has its own token.
	t.Setenv("OPENCODE_SESSION_ID", "ses_Subagent")
	if token, err := commandToken(t); err != nil || token != "session-2" {
		t.Fatalf("subagent token = %q, %v", token, err)
	}
}

func TestSessionSelection(t *testing.T) {
	setupSession(t, "ses_opencode")
	t.Setenv("BAO_SESSION_ID", "ses_override")
	if session, err := agentSession(); err != nil || session != "ses_override" {
		t.Fatalf("session = %q, %v", session, err)
	}

	t.Setenv("BAO_NO_SESSION", "1")
	if token, err := commandToken(t); err != nil || token != "named-1" {
		t.Fatalf("token with sessions off = %q, %v", token, err)
	}

	t.Setenv("BAO_NO_SESSION", "")
	t.Setenv("BAO_SESSION_ID", "../escape")
	if _, err := commandToken(t); err == nil || !strings.Contains(err.Error(), "session ID must match") {
		t.Fatalf("invalid session ID error = %v", err)
	}
}

func TestSessionTokenIsRenewedAndReminted(t *testing.T) {
	bao, _ := setupSession(t, "ses_1")
	if _, err := commandToken(t); err != nil {
		t.Fatal(err)
	}

	// Under half a period left: renew it, and the project token with it.
	bao.mu.Lock()
	bao.ttls["session-1"] = int((6 * time.Hour).Seconds())
	bao.mu.Unlock()
	if token, err := commandToken(t); err != nil || token != "session-1" {
		t.Fatalf("token = %q, %v", token, err)
	}

	if _, renewed, _ := bao.snapshot(); !slices.Contains(renewed, "session-1") || !slices.Contains(renewed, "named-1") {
		t.Fatalf("renewed = %v", renewed)
	}

	// Rotating the project token revokes its sessions; the next command
	// mints a new session token from the new Named Token.
	if err := run([]string{"auth", "app"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if token, err := commandToken(t); err != nil || token != "session-2" {
		t.Fatalf("token after rotation = %q, %v", token, err)
	}
}

func TestEnvStatusAndRunUseTheSessionToken(t *testing.T) {
	setupSession(t, "ses_1")
	var stdout bytes.Buffer
	if err := run([]string{"env"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), "export BAO_TOKEN='session-1'") {
		t.Fatalf("env = %q, %v", stdout.String(), err)
	}

	stdout.Reset()
	if err := run([]string{"status"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), `"session": "ses_1"`) {
		t.Fatalf("status = %q, %v", stdout.String(), err)
	}

	stdout.Reset()
	if err := run([]string{"run", "--", "sh", "-c", `printf '%s %s' "$BAO_TOKEN" "$VAULT_TOKEN"`}, &stdout, &bytes.Buffer{}); err != nil ||
		stdout.String() != "session-1 session-1" {
		t.Fatalf("run = %q, %v", stdout.String(), err)
	}

	if err := run([]string{"run", "--", "sh", "-c", "exit 5"}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != 5 {
		t.Fatalf("run exit = %v", err)
	}

	if err := run([]string{"run", "sh"}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
		t.Fatalf("run without -- = %v", err)
	}
}

func TestLogoutDeletesSessionTokens(t *testing.T) {
	_, home := setupSession(t, "ses_1")
	if _, err := commandToken(t); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"logout"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(home, "state", "bao-cred", "sessions", "app")); !os.IsNotExist(err) {
		t.Fatalf("session directory still exists: %v", err)
	}
}

func TestStaleSessionTokensArePruned(t *testing.T) {
	_, home := setupSession(t, "ses_new")
	stale := filepath.Join(home, "state", "bao-cred", "sessions", "app", "ses_old.token")
	if err := os.MkdirAll(filepath.Dir(stale), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(stale, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-3 * staleSessionAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	if _, err := commandToken(t); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale session token kept: %v", err)
	}
}

// commandToken resolves the token as commands do, with BAO_IDENTITY.
func commandToken(t *testing.T) (string, error) {
	t.Helper()
	return requesterToken(t.Context(), selectedIdentity(""))
}
