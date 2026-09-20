package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHCLConfigurationAndSecretFiles(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, directory, "encryption-key", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	writeTestFile(t, directory, "scanner-token", "scanner-secret")
	configPath := writeTestFile(t, directory, "app.hcl", `
server {
  listen_address    = "127.0.0.1:9090"
  public_origin     = ""
  insecure_cookies  = true
  static_directory  = ""
}
storage {
  database_path       = "state/app.db"
  encryption_key_file = "encryption-key"
}
openbao {
  address            = "https://bao.example.test"
  namespace          = "engineering"
  ca_file            = ""
  scanner_token_file = "scanner-token"
  approver_policy    = "approver"
}
scanner {
  interval    = "5s"
  concurrency = 4
}
requests {
  expose_data = false
}
approval_context "github-token" {
  match_path = "github/token/{name}"
  read_path  = "github/permissionset/{name}"
}
`)

	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if configuration.OpenBaoScannerToken != "scanner-secret" || configuration.ScanConcurrency != 4 {
		t.Fatalf("configuration = %#v", configuration)
	}

	if configuration.DatabasePath != filepath.Join(directory, "state/app.db") {
		t.Fatalf("DatabasePath = %q", configuration.DatabasePath)
	}

	if path, ok := configuration.ApprovalContext.Resolve("github/token/project-authorizer"); !ok || path != "github/permissionset/project-authorizer" {
		t.Fatalf("resolved path = %q, matched = %v", path, ok)
	}
}

func TestLoadRejectsInvalidEncryptionKey(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, directory, "encryption-key", "short")
	writeTestFile(t, directory, "scanner-token", "scanner-secret")
	configPath := writeTestFile(t, directory, "app.hcl", `
server {
  listen_address = "127.0.0.1:8080"
  public_origin = ""
  insecure_cookies = true
  static_directory = ""
}
storage {
  database_path = "app.db"
  encryption_key_file = "encryption-key"
}
openbao {
  address = "http://127.0.0.1:8200"
  namespace = ""
  ca_file = ""
  scanner_token_file = "scanner-token"
  approver_policy = "approver"
}
scanner {
  interval = "15s"
  concurrency = 8
}
requests {
  expose_data = false
}
`)
	_, err := Load(configPath)
	if err == nil || err.Error() != "storage.encryption_key_file must contain base64 encoding of exactly 32 bytes" {
		t.Fatal("expected invalid encryption key error")
	}
}

func writeTestFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
