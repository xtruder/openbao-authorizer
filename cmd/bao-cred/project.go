package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// projectFileName names the committed file at a git root that selects the
// project's Named Identity, so no environment variable is needed.
const projectFileName = ".bao-identity"

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

// projectIdentity returns the name in the git root's .bao-identity, or "".
// The name is returned unvalidated so callers report a malformed file.
func projectIdentity() (string, error) {
	working, err := os.Getwd()
	if err != nil {
		return "", nil //nolint:nilerr // No working directory means no project.
	}

	root, ok := gitRoot(working)
	if !ok {
		return "", nil
	}

	contents, err := os.ReadFile(filepath.Join(root, projectFileName)) // #nosec G304 -- fixed name at the git root.
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("read %s: %w", projectFileName, err)
	}

	name := parseProjectFile(string(contents))
	if name == "" {
		return "", fmt.Errorf("%s at %s names no identity", projectFileName, root)
	}

	return name, nil
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
		Short: "Select a Named Identity for this git project and mint its token",
		Long: `Writes ` + projectFileName + ` at the git root of the current directory, naming the
project's Named Identity (default: the root directory's name), then mints its
Named Token as bao-cred auth does, unless a valid one is already stored.

Commit the file. Inside the project, bao-cred then uses that identity's token
without BAO_IDENTITY, and never falls back to your ~/.vault-token. BAO_TOKEN,
VAULT_TOKEN, --identity and BAO_IDENTITY still take precedence.`,
		Example: `  bao-cred init
  bao-cred init myproject`,
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
	set.BoolVar(&flags.force, "force", false, "replace a "+projectFileName+" that names another identity")
	set.BoolVar(&flags.quiet, "quiet", false, "suppress progress messages")
	return command
}

func runInit(ctx context.Context, arguments []string, flags initFlags, stdout, stderr io.Writer) error {
	working, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("locate working directory: %w", err)
	}

	root, ok := gitRoot(working)
	if !ok {
		return errors.New("not inside a git repository; run bao-cred init from a project, or use bao-cred auth")
	}

	name := defaultIdentityName(root)
	if len(arguments) == 1 {
		name = strings.TrimSpace(arguments[0])
	}

	if err = validateIdentityName(name); err != nil {
		return usageError(err)
	}

	progress := newProgress(stderr, flags.quiet)
	path := filepath.Join(root, projectFileName)
	contents, err := os.ReadFile(path) // #nosec G304 -- fixed name at the git root.
	switch existing := parseProjectFile(string(contents)); {
	case err == nil && existing == name:
	case err == nil && existing != "" && !flags.force:
		return fmt.Errorf("%s already names %q; pass --force to replace it", path, existing)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("read %s: %w", projectFileName, err)
	default:
		body := "# Named Identity of this project for bao-cred; see bao-cred init --help.\n" + name + "\n"
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil { // #nosec G306 -- committed, not secret.
			return fmt.Errorf("write %s: %w", projectFileName, err)
		}

		progress(fmt.Sprintf("wrote %s naming %q; commit it", path, name))
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
