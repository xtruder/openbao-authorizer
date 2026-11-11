package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newProject creates a git project root under a fresh directory, enters
// subdirectory, and returns the root.
func newProject(t *testing.T, name, subdirectory string, gitFile bool) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(filepath.Join(root, subdirectory), 0o755); err != nil {
		t.Fatal(err)
	}

	// A worktree has a .git file instead of a directory.
	if gitFile {
		if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Chdir(filepath.Join(root, subdirectory))
	return root
}

func TestDefaultIdentityName(t *testing.T) {
	for directory, want := range map[string]string{
		"/src/My_Project.v2":              "my-project-v2",
		"/src/--api--":                    "api",
		"/src/" + strings.Repeat("a", 70): strings.Repeat("a", 63),
		"/src/___":                        "",
	} {
		if got := defaultIdentityName(directory); got != want {
			t.Errorf("defaultIdentityName(%q) = %q, want %q", directory, got, want)
		}
	}
}

func TestInitWritesProjectFileAndMints(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	root := newProject(t, "My_App", "cmd/tool", true)

	var stdout bytes.Buffer
	if err := run([]string{"init"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	contents, err := os.ReadFile(filepath.Join(root, projectFileName))
	if err != nil || parseProjectFile(string(contents)) != "my-app" {
		t.Fatalf("%s = %q, %v", projectFileName, contents, err)
	}

	var status identityStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil || status.Identity != "my-app" {
		t.Fatalf("status = %s, %v", stdout.String(), err)
	}

	if ring.get("my-app") != "named-1" {
		t.Fatalf("keyring holds %q", ring.get("my-app"))
	}

	// Rerunning keeps the valid token instead of rotating it.
	if err := run([]string{"init"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if ring.get("my-app") != "named-1" {
		t.Fatalf("rerun replaced the token with %q", ring.get("my-app"))
	}

	// Another name needs --force.
	if err := run([]string{"init", "other"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("init with another name = %v", err)
	}

	if err := run([]string{"init", "--force", "other"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if name, err := projectIdentity(); err != nil || name != "other" {
		t.Fatalf("project identity = %q, %v", name, err)
	}
}

func TestInitRequiresGitProject(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	if err := run([]string{"init", "myproject"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "git") {
		t.Fatalf("init outside git = %v", err)
	}

	newProject(t, "___", "", false)
	if err := run([]string{"init"}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
		t.Fatalf("init with no usable default name = %v, want usage error", err)
	}
}

func TestProjectFileInParentDirectorySelectsIdentity(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	ring.entries[keyringService+"/personal"] = "named-personal"
	ring.entries[keyringService+"/app"] = "named-app"
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, projectFileName), []byte("personal\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A file above the working directory applies, past a git root without one.
	for _, directory := range []string{home, filepath.Join(home, "notes", "2026"), filepath.Join(home, "code", "tool", "cmd")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Mkdir(filepath.Join(home, "code", "tool", ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, directory := range []string{home, filepath.Join(home, "notes", "2026"), filepath.Join(home, "code", "tool", "cmd")} {
		t.Chdir(directory)
		if got, err := requesterToken(t.Context(), ""); err != nil || got != "named-personal" {
			t.Fatalf("%s: token %q, %v; want the parent's identity", directory, got, err)
		}
	}

	// The nearest file wins.
	if err := os.WriteFile(filepath.Join(home, "code", "tool", projectFileName), []byte("app\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got, err := requesterToken(t.Context(), ""); err != nil || got != "named-app" {
		t.Fatalf("token %q, %v; want the nearest identity", got, err)
	}
}

func TestProjectFileSelectsIdentity(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	root := newProject(t, "app", "deep/dir", false)
	if err := os.WriteFile(filepath.Join(root, projectFileName), []byte("# comment\n\nmyproject\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without a stored token the project fails closed, even though
	// ~/.vault-token holds the human's token.
	if _, err := requesterToken(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "bao-cred auth myproject") {
		t.Fatalf("error = %v, want an auth hint", err)
	}

	ring.entries[keyringService+"/myproject"] = "named-project"
	ring.entries[keyringService+"/explicit"] = "named-explicit"
	if got, err := requesterToken(t.Context(), ""); err != nil || got != "named-project" {
		t.Fatalf("project token = %q, %v", got, err)
	}

	// Explicit selections and tokens win over the file.
	if got, err := requesterToken(t.Context(), "explicit"); err != nil || got != "named-explicit" {
		t.Fatalf("explicit identity = %q, %v", got, err)
	}

	t.Setenv("BAO_TOKEN", "env-token")
	if got, err := requesterToken(t.Context(), ""); err != nil || got != "env-token" {
		t.Fatalf("BAO_TOKEN = %q, %v", got, err)
	}

	t.Setenv("BAO_TOKEN", "")
	var stdout bytes.Buffer
	if err := run([]string{"env"}, &stdout, &bytes.Buffer{}); err == nil {
		// named-project isn't valid on the fake server, so env must refuse it.
		t.Fatalf("env with an invalid token succeeded: %s", stdout.String())
	}

	if err := os.WriteFile(filepath.Join(root, projectFileName), []byte("Bad Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := requesterToken(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "identity name must match") {
		t.Fatalf("malformed file = %v", err)
	}
}
