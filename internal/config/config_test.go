package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretRejectsAmbiguousSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_TOKEN", "env-token")
	t.Setenv("TEST_TOKEN_FILE", path)
	if _, err := readSecret("TEST_TOKEN", "TEST_TOKEN_FILE"); err == nil {
		t.Fatal("expected ambiguous secret source error")
	}
}

func TestLoadUsesEmbeddedFrontendUnlessOverrideIsExplicit(t *testing.T) {
	t.Setenv("APP_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("OPENBAO_SCANNER_TOKEN", "scanner-token")
	t.Setenv("OPENBAO_SCANNER_TOKEN_FILE", "")
	t.Setenv("APPROVER_POLICY", "approver")
	t.Setenv("INSECURE_COOKIES", "true")
	t.Setenv("VAPID_PUBLIC_KEY", "")
	t.Setenv("VAPID_PRIVATE_KEY", "")
	t.Setenv("VAPID_SUBJECT", "")
	t.Setenv("STATIC_DIRECTORY", "")

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.StaticDirectory != "" {
		t.Fatalf("StaticDirectory = %q, want embedded frontend", configuration.StaticDirectory)
	}

	t.Setenv("STATIC_DIRECTORY", "/tmp/frontend-dev")
	configuration, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.StaticDirectory != "/tmp/frontend-dev" {
		t.Fatalf("StaticDirectory = %q, want explicit override", configuration.StaticDirectory)
	}
}
