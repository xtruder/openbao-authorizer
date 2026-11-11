package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// newProject creates a git repository root under a fresh directory, enters
// subdirectory, and returns the root.
func newProject(t *testing.T, name, subdirectory string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	for _, directory := range []string{filepath.Join(root, ".git"), filepath.Join(root, subdirectory)} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Chdir(filepath.Join(root, subdirectory))
	return root
}

// newWorktree adds a linked worktree of repository at path, laid out as git
// worktree add does: a .git file naming the worktree's gitdir, whose
// commondir file points back to the repository's .git.
func newWorktree(t *testing.T, repository, path string) {
	t.Helper()
	gitDir := filepath.Join(repository, ".git", "worktrees", filepath.Base(path))
	for _, directory := range []string{gitDir, path} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeTestFile(t, filepath.Join(gitDir, "commondir"), "../..\n")
	writeTestFile(t, filepath.Join(path, ".git"), "gitdir: "+gitDir+"\n")
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
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

func TestGeneratedIdentityName(t *testing.T) {
	for base, prefix := range map[string]string{
		"My_App":                "my-app-",
		"___":                   "identity-",
		strings.Repeat("a", 70): strings.Repeat("a", 56) + "-",
	} {
		name := generatedIdentityName(base)
		if !strings.HasPrefix(name, prefix) || len(name) != len(prefix)+6 || validateIdentityName(name) != nil {
			t.Errorf("generatedIdentityName(%q) = %q, want %s plus 6 characters", base, name, prefix)
		}
	}

	if first, second := generatedIdentityName("app"), generatedIdentityName("app"); first == second {
		t.Fatal("two generated names are equal")
	}
}

func TestInitInRepositoryWritesTheGitDirectory(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	root := newProject(t, "My_App", "cmd/tool")

	var stdout bytes.Buffer
	if err := run([]string{"init"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	name, found, err := readIdentityFile(filepath.Join(root, ".git", repositoryFileName))
	if err != nil || !found || !regexp.MustCompile(`^my-app-[a-z2-7]{6}$`).MatchString(name) {
		t.Fatalf(".git/%s names %q, %v", repositoryFileName, name, err)
	}

	if _, err := os.Stat(filepath.Join(root, directoryFileName)); !os.IsNotExist(err) {
		t.Fatalf("init wrote %s into the working tree: %v", directoryFileName, err)
	}

	var status identityStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil || status.Identity != name {
		t.Fatalf("status = %s, %v", stdout.String(), err)
	}

	if ring.get(name) != "named-1" {
		t.Fatalf("keyring holds %q", ring.get(name))
	}

	// Rerunning keeps the name and the valid token.
	if err := run([]string{"init"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if again, _, _ := readIdentityFile(filepath.Join(root, ".git", repositoryFileName)); again != name || ring.get(name) != "named-1" {
		t.Fatalf("rerun changed the identity to %q, token %q", again, ring.get(name))
	}

	// Another name needs --force.
	if err := run([]string{"init", "other"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("init with another name = %v", err)
	}

	if err := run([]string{"init", "--force", "other"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if selected, err := projectIdentity(); err != nil || selected != "other" {
		t.Fatalf("project identity = %q, %v", selected, err)
	}
}

func TestWorktreesAndSubmodulesUseTheCommonGitDirectory(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	useKeyring(t, nil)
	repository := newProject(t, "app", "")
	worktree := filepath.Join(t.TempDir(), "app-feature")
	newWorktree(t, repository, worktree)
	if err := os.MkdirAll(filepath.Join(worktree, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	// init in a worktree writes the repository's file.
	t.Chdir(worktree)
	if err := run([]string{"init", "app-shared"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if name, _, err := readIdentityFile(filepath.Join(repository, ".git", repositoryFileName)); err != nil || name != "app-shared" {
		t.Fatalf("repository file names %q, %v", name, err)
	}

	for _, directory := range []string{repository, filepath.Join(worktree, "src")} {
		t.Chdir(directory)
		if name, err := projectIdentity(); err != nil || name != "app-shared" {
			t.Fatalf("%s: identity %q, %v", directory, name, err)
		}
	}

	// A submodule's gitdir has no commondir and is its own common directory.
	submodule := filepath.Join(repository, "vendor", "lib")
	moduleGitDir := filepath.Join(repository, ".git", "modules", "lib")
	for _, directory := range []string{submodule, moduleGitDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	writeTestFile(t, filepath.Join(submodule, ".git"), "gitdir: ../../.git/modules/lib\n")
	writeTestFile(t, filepath.Join(moduleGitDir, repositoryFileName), "lib-identity\n")
	t.Chdir(submodule)
	if name, err := projectIdentity(); err != nil || name != "lib-identity" {
		t.Fatalf("submodule identity %q, %v", name, err)
	}
}

func TestIdentityFileInTheWorkingTreeIsIgnored(t *testing.T) {
	home := t.TempDir()
	repository := filepath.Join(home, "code", "cloned")
	for _, directory := range []string{filepath.Join(repository, ".git"), filepath.Join(repository, "sub")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// A clone can carry a committed .bao-identity naming someone's identity.
	writeTestFile(t, filepath.Join(repository, directoryFileName), "victim\n")
	writeTestFile(t, filepath.Join(repository, "sub", directoryFileName), "victim\n")
	t.Chdir(filepath.Join(repository, "sub"))
	if name, err := projectIdentity(); err != nil || name != "" {
		t.Fatalf("identity %q, %v; want none", name, err)
	}

	// Above the repository, the user's own file still applies.
	writeTestFile(t, filepath.Join(home, directoryFileName), "personal\n")
	if name, err := projectIdentity(); err != nil || name != "personal" {
		t.Fatalf("identity %q, %v; want the home directory's", name, err)
	}
}

func TestInitOutsideRepositoriesCoversTheTreeBelow(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	home := filepath.Join(t.TempDir(), "home")
	for _, directory := range []string{filepath.Join(home, "notes"), filepath.Join(home, "code", "tool", ".git"), filepath.Join(home, "code", "tool", "cmd")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Chdir(home)
	if err := run([]string{"init"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	name, found, err := readIdentityFile(filepath.Join(home, directoryFileName))
	if err != nil || !found || !strings.HasPrefix(name, "home-") {
		t.Fatalf("%s names %q, %v", directoryFileName, name, err)
	}

	// Subdirectories and repositories without their own identity use it.
	for _, directory := range []string{filepath.Join(home, "notes"), filepath.Join(home, "code", "tool", "cmd")} {
		t.Chdir(directory)
		if got, err := requesterToken(t.Context(), ""); err != nil || got != ring.get(name) {
			t.Fatalf("%s: token %q, %v; want the home identity's", directory, got, err)
		}
	}

	// The repository's own identity wins.
	ring.entries[keyringService+"/tool"] = "named-tool"
	bao.valid["named-tool"] = true
	writeTestFile(t, filepath.Join(home, "code", "tool", ".git", repositoryFileName), "tool\n")
	if got, err := requesterToken(t.Context(), ""); err != nil || got != "named-tool" {
		t.Fatalf("token %q, %v; want the repository's", got, err)
	}
}

func TestProjectFileSelectsIdentity(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	root := newProject(t, "app", "deep/dir")
	identityFile := filepath.Join(root, ".git", repositoryFileName)
	writeTestFile(t, identityFile, "# comment\n\nmyproject\n")

	// An identity this machine never minted fails closed, even though
	// ~/.vault-token holds the human's token.
	if _, err := requesterToken(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "bao-cred auth myproject") {
		t.Fatalf("error = %v, want an auth hint", err)
	}

	bao.valid["named-project"] = true
	ring.entries[keyringService+"/myproject"] = "named-project"
	ring.entries[keyringService+"/explicit"] = "named-explicit"
	bao.valid["named-explicit"] = true
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
	writeTestFile(t, identityFile, "Bad Name\n")
	if _, err := requesterToken(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "identity name must match") {
		t.Fatalf("malformed file = %v", err)
	}

	writeTestFile(t, identityFile, "# nothing\n")
	if _, err := requesterToken(t.Context(), ""); err == nil || !strings.Contains(err.Error(), "names no identity") {
		t.Fatalf("empty file = %v", err)
	}
}
