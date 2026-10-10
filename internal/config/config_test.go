package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/grants"
)

func TestLoadHCLConfigurationAndSecretFiles(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("AUTHORIZER_ORIGIN", "https://authorizer.example.test")
	writeTestFile(t, directory, "encryption-key", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	writeTestFile(t, directory, "authorizer-token", "authorizer-secret")
	configPath := writeTestFile(t, directory, "app.hcl", `
server {
  listen_address    = "127.0.0.1:9090"
  public_origin     = env.AUTHORIZER_ORIGIN
  insecure_cookies  = false
  static_directory  = ""
  session_ttl       = "12h"
}
storage {
  database_path       = "state/app.db"
  encryption_key_file = "encryption-key"
}
openbao {
  address               = "https://bao.example.test"
  namespace             = "engineering"
  authorizer_token_file = "authorizer-token"
  approver_policy       = "approver"
}
approver_login {
  openbao_address = "https://bao.example.test/"
  namespace       = "engineering"
  method "userpass" {}
  method "oidc" {
    mount = "/sso/"
    label = "Company SSO"
    role  = "approver"
  }
}
requester "opencode" {
  token_role = "agent-session"
}
requester "ci" {
  auth_mount = "approle/"
}
grants {
  default_ttl = "12h"
  pending_ttl = "30m"
}
grantable "github-token" {
  path         = "github/token/project-*"
  capabilities = ["read"]
  max_ttl      = "8h"
}
grantable "kv" {
  path         = "kv/data/+/config"
  capabilities = ["read", "update"]
}
`)

	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if configuration.OpenBaoAuthorizerToken != "authorizer-secret" || configuration.OpenBaoCAFile != "" {
		t.Fatalf("configuration = %#v", configuration)
	}

	if configuration.PublicOrigin != "https://authorizer.example.test" {
		t.Fatalf("PublicOrigin = %q", configuration.PublicOrigin)
	}

	if configuration.DatabasePath != filepath.Join(directory, "state/app.db") {
		t.Fatalf("DatabasePath = %q", configuration.DatabasePath)
	}

	if configuration.SessionTTL != 12*time.Hour {
		t.Fatalf("SessionTTL = %s", configuration.SessionTTL)
	}

	wantRequesters := []grants.RequesterRule{{Name: "opencode", TokenRole: "agent-session"}, {Name: "ci", AuthMount: "approle"}}
	if !slices.Equal(configuration.Requesters, wantRequesters) {
		t.Fatalf("Requesters = %#v", configuration.Requesters)
	}

	login := configuration.ApproverLogin
	wantMethods := []LoginMethod{{Type: "userpass", Mount: "userpass", Label: "Username & password"}, {Type: "oidc", Mount: "sso", Label: "Company SSO", OIDCRole: "approver"}}
	if login.OpenBaoAddress != "https://bao.example.test" || login.Namespace != "engineering" || !slices.Equal(login.Methods, wantMethods) {
		t.Fatalf("ApproverLogin = %#v", login)
	}

	if configuration.GrantPolicy.DefaultTTL != 12*time.Hour || configuration.PendingTTL != 30*time.Minute {
		t.Fatalf("TTLs = %s %s", configuration.GrantPolicy.DefaultTTL, configuration.PendingTTL)
	}

	rules := configuration.GrantPolicy.Rules
	if len(rules) != 2 || rules[0].Name != "github-token" || rules[0].MaxTTL != 8*time.Hour || rules[1].MaxTTL != 0 || len(rules[1].Capabilities) != 2 {
		t.Fatalf("rules = %#v", rules)
	}
}

func TestLoadAppliesGrantDefaults(t *testing.T) {
	directory := t.TempDir()
	configPath := writeMinimalConfig(t, directory, "")

	configuration, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if configuration.GrantPolicy.DefaultTTL != 72*time.Hour || configuration.PendingTTL != 24*time.Hour {
		t.Fatalf("TTLs = %s %s", configuration.GrantPolicy.DefaultTTL, configuration.PendingTTL)
	}

	if configuration.SessionTTL != 168*time.Hour || len(configuration.GrantPolicy.Rules) != 0 {
		t.Fatalf("configuration = %#v", configuration)
	}

	if methods := configuration.ApproverLogin.Methods; !slices.Equal(methods, []LoginMethod{{Type: "token", Label: "Token"}}) {
		t.Fatalf("default login methods = %#v", methods)
	}
}

func TestLoadRejectsInvalidGrantableRules(t *testing.T) {
	rule := func(path, capabilities, extra string) string {
		return fmt.Sprintf("grantable \"x\" {\n  path = %q\n  capabilities = %s\n  %s\n}\n", path, capabilities, extra)
	}
	cases := map[string]struct{ extra, message string }{
		"sys path":         {rule("sys/policies/acl/*", `["read"]`, ""), "hard denylist"},
		"identity glob":    {rule("iden*", `["read"]`, ""), "hard denylist"},
		"leading wildcard": {rule("+/data/a", `["read"]`, ""), "hard denylist"},
		"bare glob":        {rule("*", `["read"]`, ""), "hard denylist"},
		"auth path":        {rule("auth/token/create", `["update"]`, ""), "hard denylist"},
		"cubbyhole":        {rule("cubbyhole/secret", `["read"]`, ""), "hard denylist"},
		"sudo":             {rule("kv/data/a", `["read", "sudo"]`, ""), "sudo"},
		"unknown cap":      {rule("kv/data/a", `["deny"]`, ""), "capability \"deny\""},
		"no caps":          {rule("kv/data/a", `[]`, ""), "capabilities are required"},
		"inner glob":       {rule("kv/*/a", `["read"]`, ""), "only allowed at the end"},
		"partial plus":     {rule("kv/data/a+", `["read"]`, ""), "complete path segment"},
		"bad max_ttl":      {rule("kv/data/a", `["read"]`, `max_ttl = "soon"`), "max_ttl"},
		"duplicate":        {rule("kv/data/a", `["read"]`, "") + rule("kv/data/b", `["read"]`, ""), "more than once"},
		"bad pending_ttl":  {"grants {\n  pending_ttl = \"0s\"\n}\n", "grants.pending_ttl"},
		"bad default_ttl":  {"grants {\n  default_ttl = \"forever\"\n}\n", "grants.default_ttl"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			configPath := writeMinimalConfig(t, t.TempDir(), testCase.extra)
			_, err := Load(configPath)
			if err == nil || !strings.Contains(err.Error(), testCase.message) {
				t.Fatalf("error = %v, want %q", err, testCase.message)
			}
		})
	}
}

func TestLoadRejectsInvalidLoginAndRequesters(t *testing.T) {
	cases := map[string]struct{ replace, with, message string }{
		"no requesters":   {"requester \"opencode\" {\n  token_role = \"opencode-session\"\n}", "", "at least one requester"},
		"two matchers":    {`token_role = "opencode-session"`, `token_role = "a"` + "\n" + `auth_mount = "b"`, "exactly one of token_role or auth_mount"},
		"no matcher":      {`token_role = "opencode-session"`, ``, "exactly one of token_role or auth_mount"},
		"bad address":     {`openbao_address = "http://127.0.0.1:8200"`, `openbao_address = "127.0.0.1:8200"`, "approver_login.openbao_address"},
		"unknown method":  {`method "token" {}`, `method "kerberos" {}`, "not one of"},
		"role not oidc":   {`method "token" {}`, `method "userpass" { role = "x" }`, "does not take a role"},
		"duplicate rules": {`requester "opencode" {`, `requester "opencode" { token_role = "x" }` + "\n" + `requester "opencode" {`, "more than once"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			configPath := writeMinimalConfig(t, t.TempDir(), "")
			contents, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}

			if !strings.Contains(string(contents), testCase.replace) {
				t.Fatalf("minimal config lacks %q", testCase.replace)
			}

			writeTestFile(t, filepath.Dir(configPath), "app.hcl", strings.Replace(string(contents), testCase.replace, testCase.with, 1))
			if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), testCase.message) {
				t.Fatalf("error = %v, want %q", err, testCase.message)
			}
		})
	}
}

func TestExampleConfigurationLoads(t *testing.T) {
	directory := t.TempDir()
	example, err := os.ReadFile("../../config/openbao-authorizer.example.hcl")
	if err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, directory, "encryption-key", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	writeTestFile(t, directory, "authorizer-token", "authorizer-secret")
	contents := strings.NewReplacer(
		"/run/secrets/openbao-authorizer-key", "encryption-key",
		"/run/secrets/openbao-authorizer-token", "authorizer-token",
	).Replace(string(example))
	configuration, err := Load(writeTestFile(t, directory, "app.hcl", contents))
	if err != nil {
		t.Fatal(err)
	}

	if len(configuration.GrantPolicy.Rules) != 2 || len(configuration.Requesters) != 2 || len(configuration.ApproverLogin.Methods) != 3 {
		t.Fatalf("configuration = %#v", configuration)
	}
}

func TestLoadRejectsInvalidEncryptionKey(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, directory, "encryption-key", "short")
	writeTestFile(t, directory, "authorizer-token", "authorizer-secret")
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
  authorizer_token_file = "authorizer-token"
  approver_policy = "approver"
}
approver_login {
  openbao_address = "http://127.0.0.1:8200"
}
requester "opencode" {
  token_role = "opencode-session"
}
`)
	_, err := Load(configPath)
	if err == nil || err.Error() != "storage.encryption_key_file must contain base64 encoding of exactly 32 bytes" {
		t.Fatal("expected invalid encryption key error")
	}
}

func writeMinimalConfig(t *testing.T, directory, extra string) string {
	t.Helper()
	writeTestFile(t, directory, "encryption-key", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	writeTestFile(t, directory, "authorizer-token", "authorizer-secret")
	return writeTestFile(t, directory, "app.hcl", `
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
  authorizer_token_file = "authorizer-token"
  approver_policy = "approver"
}
approver_login {
  openbao_address = "http://127.0.0.1:8200"
  method "token" {}
}
requester "opencode" {
  token_role = "opencode-session"
}
`+extra+"\n")
}

func writeTestFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
