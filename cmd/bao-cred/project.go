package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

const (
	// repositoryFileName names the identity file inside a repository's common
	// git directory, which every worktree shares and git never transfers, so
	// no clone can bring one along.
	repositoryFileName = "bao-identity"
	// directoryFileName names the identity file of a directory outside any
	// repository, such as the home directory; it covers the tree below it.
	directoryFileName = ".bao-identity"
)

// gitRoot returns the nearest directory at or above start that contains a
// .git entry: a directory in a clone, a file in a worktree or submodule.
func gitRoot(start string) (string, bool) {
	directory := start
	for {
		if _, err := os.Lstat(filepath.Join(directory, ".git")); err == nil {
			return directory, true
		}

		parent := filepath.Dir(directory)
		if parent == directory {
			return "", false
		}

		directory = parent
	}
}

// gitRepository returns the nearest worktree root at or above start and the
// repository's common git directory, which all its worktrees share: .git in
// a clone, or the directory that the commondir file in a linked worktree's
// gitdir names. A submodule's gitdir has no commondir and is its own common
// directory. common is empty when .git is unreadable or malformed.
func gitRepository(start string) (root, common string, ok bool) {
	root, ok = gitRoot(start)
	if !ok {
		return "", "", false
	}

	gitDir := filepath.Join(root, ".git")
	info, err := os.Stat(gitDir)
	if err != nil {
		return root, "", true
	}

	if !info.IsDir() {
		contents, readErr := os.ReadFile(gitDir) // #nosec G304 -- the .git file of a worktree.
		path, found := strings.CutPrefix(strings.TrimSpace(string(contents)), "gitdir:")
		if readErr != nil || !found || strings.TrimSpace(path) == "" {
			return root, "", true
		}

		gitDir = resolvePath(root, strings.TrimSpace(path))
	}

	common = gitDir
	// #nosec G304,G703 -- the commondir file of the gitdir that .git names.
	if contents, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		if path := strings.TrimSpace(string(contents)); path != "" {
			common = resolvePath(gitDir, path)
		}
	}

	return root, common, true
}

func resolvePath(base, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	return filepath.Join(base, path)
}

// projectIdentity returns the Named Identity selected for the working
// directory, or "". Inside a repository only the bao-identity file in its
// common git directory counts, so every worktree shares it; a .bao-identity
// in the working tree is ignored, because it may have come with a clone.
// Outside repositories the nearest .bao-identity counts. Without a file the
// search continues above the repository, so ~/.bao-identity covers
// repositories that have none. The name is returned unvalidated so callers
// report a malformed file.
func projectIdentity() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", nil //nolint:nilerr // No working directory means no project.
	}

	for {
		path := filepath.Join(directory, directoryFileName)
		root, common, inRepository := gitRepository(directory)
		if inRepository {
			path = ""
			if common != "" {
				path = filepath.Join(common, repositoryFileName)
			}

			directory = root
		}

		if path != "" {
			name, found, err := readIdentityFile(path)
			if err != nil {
				return "", err
			}

			if found && name == "" {
				return "", fmt.Errorf("%s names no identity", path)
			}

			if found {
				return name, nil
			}
		}

		parent := filepath.Dir(directory)
		if parent == directory {
			return "", nil
		}

		directory = parent
	}
}

// readIdentityFile returns the name in an identity file, empty when the file
// names none, and whether the file exists.
func readIdentityFile(path string) (string, bool, error) {
	contents, err := os.ReadFile(path) // #nosec G304 -- an identity file at a fixed name.
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}

	return parseProjectFile(string(contents)), true, nil
}

// parseProjectFile returns the first line that is neither blank nor a comment.
func parseProjectFile(contents string) string {
	for line := range strings.SplitSeq(contents, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return line
		}
	}

	return ""
}

// defaultIdentityName turns a directory name into a valid identity name.
func defaultIdentityName(directory string) string {
	var name strings.Builder
	for _, character := range strings.ToLower(filepath.Base(directory)) {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			name.WriteRune(character)
		case name.Len() > 0 && !strings.HasSuffix(name.String(), "-"):
			name.WriteByte('-')
		}
	}

	result := strings.TrimSuffix(name.String(), "-")
	if len(result) > 63 {
		result = strings.TrimSuffix(result[:63], "-")
	}

	return result
}

type initFlags struct {
	authFlags

	force bool
}

func newInitCommand() *cobra.Command {
	var flags initFlags
	command := &cobra.Command{
		Use:   "init [name]",
		Short: "Create a Named Identity for this repository or directory and mint its token",
		Long: `Creates a Named Identity for the current repository, or for the current
directory outside repositories, and mints its Named Token as bao-cred auth
does, unless a valid one is already stored.

The name defaults to the repository's or directory's name plus a random
suffix, such as my-app-k7q2xm, so no other checkout can name the same
identity. Inside a repository it is written to bao-identity in the common git
directory (.git/bao-identity in a clone), which all worktrees share and git
never commits or transfers. Outside repositories it is written to
.bao-identity in the current directory and covers everything below it without
a closer identity, so init in your home directory creates a personal identity.

Rerunning init keeps the identity and a valid token. BAO_TOKEN, VAULT_TOKEN,
--identity and BAO_IDENTITY take precedence over the files.`,
		Example: `  bao-cred init
  cd ~ && bao-cred init`,
		RunE: func(command *cobra.Command, arguments []string) error {
			if len(arguments) > 1 {
				return usageError(errors.New("init accepts at most one identity name"))
			}

			return runInit(command.Context(), arguments, flags, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	set := command.Flags()
	set.StringVar(&flags.store, "store", storeAuto, "where to store the token: auto (keyring, else file), keyring, or file")
	set.StringVar(&flags.role, "role", defaultIdentityRole, "token role that mints Named Tokens")
	set.BoolVar(&flags.force, "force", false, "replace an identity file that names another identity")
	set.BoolVar(&flags.quiet, "quiet", false, "suppress progress messages")
	return command
}

// identityFileFor returns where init writes the identity of directory and
// the name the default identity name starts with.
func identityFileFor(directory string) (string, string, error) {
	_, common, inRepository := gitRepository(directory)
	if !inRepository {
		return filepath.Join(directory, directoryFileName), filepath.Base(directory), nil
	}

	if common == "" {
		return "", "", fmt.Errorf("cannot find the git directory of the repository at or above %s", directory)
	}

	// A clone's common directory is its .git; a bare repository's is the
	// repository itself, often named like name.git.
	name := common
	if filepath.Base(common) == ".git" {
		name = filepath.Dir(common)
	}

	return filepath.Join(common, repositoryFileName), strings.TrimSuffix(filepath.Base(name), ".git"), nil
}

// generatedIdentityName is base made valid plus a random suffix, so no other
// checkout or machine names the same identity by accident or on purpose.
func generatedIdentityName(base string) string {
	suffix := strings.ToLower(rand.Text()[:6])
	prefix := defaultIdentityName(base)
	if limit := 63 - len(suffix) - 1; len(prefix) > limit {
		prefix = strings.TrimSuffix(prefix[:limit], "-")
	}

	if prefix == "" {
		prefix = "identity"
	}

	return prefix + "-" + suffix
}

func runInit(ctx context.Context, arguments []string, flags initFlags, stdout, stderr io.Writer) error {
	working, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("locate working directory: %w", err)
	}

	path, base, err := identityFileFor(working)
	if err != nil {
		return err
	}

	existing, _, err := readIdentityFile(path)
	if err != nil {
		return err
	}

	name := existing
	switch {
	case len(arguments) == 1:
		name = strings.TrimSpace(arguments[0])
	case existing == "":
		name = generatedIdentityName(base)
	}

	if err = validateIdentityName(name); err != nil {
		return usageError(err)
	}

	progress := newProgress(stderr, flags.quiet)
	switch {
	case existing == name:
	case existing != "" && !flags.force:
		return fmt.Errorf("%s already names %q; pass --force to replace it", path, existing)
	default:
		body := "# Named Identity for bao-cred; see bao-cred init --help.\n" + name + "\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}

		progress(fmt.Sprintf("wrote %s naming %q", path, name))
	}

	// A valid stored token is kept, so init can be rerun safely; bao-cred auth
	// is the way to rotate it.
	if token, store, err := tokens().loadNamed(name); err == nil {
		if client, err := newOpenBaoClient(token); err == nil && renewNamedToken(ctx, client) == nil {
			status, err := lookupStatus(ctx, client, name, store)
			if err != nil {
				return err
			}

			progress(fmt.Sprintf("kept the stored Named Token for %q", name))
			return writeIndentedJSON(stdout, status)
		}
	}

	return runAuth(ctx, name, flags.authFlags, stdout, stderr)
}
