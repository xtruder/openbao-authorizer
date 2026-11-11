package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCommandArgumentsUnderTheTokenHelperName(t *testing.T) {
	for _, test := range []struct{ argv, want []string }{
		{[]string{"/usr/local/bin/bao-cred", "read", "x"}, []string{"read", "x"}},
		{[]string{"/home/me/.local/bin/" + tokenHelperName, "get"}, []string{"token-helper", "get"}},
		{[]string{tokenHelperName, "store"}, []string{"token-helper", "store"}},
	} {
		if got := commandArguments(test.argv); !slices.Equal(got, test.want) {
			t.Errorf("commandArguments(%v) = %v, want %v", test.argv, got, test.want)
		}
	}
}

// runTokenHelper runs one token helper operation with stdin and returns its
// stdout.
func runTokenHelper(t *testing.T, operation, stdin string) (string, error) {
	t.Helper()
	root := newRootCommand(runCredentials)
	root.SetArgs([]string{"token-helper", operation})
	root.SetIn(strings.NewReader(stdin))
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(t.Context())
	return stdout.String(), err
}

func TestTokenHelperGetsTheIdentityTokenInProjects(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)

	// Outside projects it is the built-in helper: the bao login token.
	if token, err := runTokenHelper(t, "get", ""); err != nil || token != loginTestToken {
		t.Fatalf("outside a project: %q, %v", token, err)
	}

	t.Setenv("BAO_NO_TOKEN_FILE", "1")
	if token, err := runTokenHelper(t, "get", ""); err != nil || token != "" {
		t.Fatalf("with BAO_NO_TOKEN_FILE: %q, %v", token, err)
	}

	t.Setenv("BAO_NO_TOKEN_FILE", "")
	root := newProject(t, "app", "src")
	writeTestFile(t, filepath.Join(root, ".git", repositoryFileName), "app-k7q2xm\n")
	ring.entries[keyringService+"/app-k7q2xm"] = "named-app"
	bao.valid["named-app"] = true
	if token, err := runTokenHelper(t, "get", ""); err != nil || token != "named-app" {
		t.Fatalf("in a project: %q, %v", token, err)
	}

	// Inside an agent session, the session's token.
	t.Setenv("BAO_SESSION_ID", "ses-1")
	if token, err := runTokenHelper(t, "get", ""); err != nil || token != "session-1" {
		t.Fatalf("in a session: %q, %v", token, err)
	}

	// A selected identity without a token fails rather than handing out the
	// human's token.
	t.Setenv("BAO_SESSION_ID", "")
	writeTestFile(t, filepath.Join(root, ".git", repositoryFileName), "unminted\n")
	if token, err := runTokenHelper(t, "get", ""); err == nil || token != "" {
		t.Fatalf("unminted identity: %q, %v", token, err)
	}
}

func TestTokenHelperStoresAndErasesTheLoginToken(t *testing.T) {
	bao := newFakeTokenStore(t)
	home := setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	loginFile := filepath.Join(home, ".vault-token")

	if _, err := runTokenHelper(t, "store", "s.new-login\n"); err != nil {
		t.Fatal(err)
	}

	if contents, err := os.ReadFile(loginFile); err != nil || string(contents) != "s.new-login" {
		t.Fatalf("~/.vault-token = %q, %v", contents, err)
	}

	if info, err := os.Stat(loginFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("~/.vault-token mode %v, %v", info.Mode(), err)
	}

	if _, err := runTokenHelper(t, "store", "  \n"); err == nil {
		t.Fatal("stored an empty token")
	}

	// In a project, the token revoked was the identity's: the login stays.
	root := newProject(t, "app", "")
	writeTestFile(t, filepath.Join(root, ".git", repositoryFileName), "app-k7q2xm\n")
	if _, err := runTokenHelper(t, "erase", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(loginFile); err != nil {
		t.Fatalf("erase in a project removed the login token: %v", err)
	}

	t.Chdir(t.TempDir())
	for range 2 {
		if _, err := runTokenHelper(t, "erase", ""); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := os.Stat(loginFile); !os.IsNotExist(err) {
		t.Fatalf("erase outside projects kept the login token: %v", err)
	}
}

func TestTokenHelperUsageErrors(t *testing.T) {
	for _, arguments := range [][]string{{"token-helper"}, {"token-helper", "list"}, {"token-helper", "get", "extra"}} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
			t.Errorf("%v: error = %v", arguments, err)
		}
	}
}

func TestTokenHelperSetup(t *testing.T) {
	bin := t.TempDir()
	executable := filepath.Join(bin, "bao-cred")
	writeTestFile(t, executable, "#!/bin/sh\n")
	config := filepath.Join(t.TempDir(), ".bao")
	link := filepath.Join(bin, tokenHelperName)
	want := `token_helper = "` + link + `"` + "\n"

	// Setup links the helper name and names the link in the config; a rerun
	// changes nothing.
	for range 2 {
		if err := setupTokenHelper(executable, config, false, func(string) {}); err != nil {
			t.Fatal(err)
		}
	}

	if target, err := os.Readlink(link); err != nil || target != "bao-cred" {
		t.Fatalf("link = %q, %v", target, err)
	}

	if contents, err := os.ReadFile(config); err != nil || string(contents) != want {
		t.Fatalf("config = %q, %v", contents, err)
	}

	// A different config or link is replaced only with force.
	writeTestFile(t, config, `token_helper = "/usr/local/bin/other"`+"\n")
	if err := setupTokenHelper(executable, config, false, func(string) {}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("other config: %v", err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("/usr/local/bin/other", link); err != nil {
		t.Fatal(err)
	}

	if err := setupTokenHelper(executable, config, false, func(string) {}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("other link: %v", err)
	}

	if err := setupTokenHelper(executable, config, true, func(string) {}); err != nil {
		t.Fatal(err)
	}

	target, linkErr := os.Readlink(link)
	contents, configErr := os.ReadFile(config)
	if linkErr != nil || target != "bao-cred" || configErr != nil || string(contents) != want {
		t.Fatalf("after --force: link %q (%v), config %q (%v)", target, linkErr, contents, configErr)
	}
}

func TestTokenHelperSetupUsageErrors(t *testing.T) {
	for _, arguments := range [][]string{{"token-helper", "--setup", "get"}, {"token-helper", "--force", "get"}} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
			t.Errorf("%v: error = %v", arguments, err)
		}
	}
}
