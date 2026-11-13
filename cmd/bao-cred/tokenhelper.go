package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// tokenHelperName is the name bao-cred answers to as the bao CLI's token
// helper. The CLI runs `<token_helper> get|store|erase` and requires
// token_helper to be an existing file, so it can't name a subcommand; a
// symlink to bao-cred with this name works instead.
const tokenHelperName = "bao-cred-token-helper" // #nosec G101 -- a program name, not a credential.

// commandArguments maps a run under the token helper's or ssh-keygen's name
// to its subcommand: the bao and git programs that run them can't pass one.
func commandArguments(argv []string) []string {
	if len(argv) > 0 {
		switch filepath.Base(argv[0]) {
		case tokenHelperName:
			return append([]string{"token-helper"}, argv[1:]...)
		case sshKeygenName:
			return append([]string{"ssh-keygen"}, argv[1:]...)
		}
	}

	return argv[1:]
}

func newTokenHelperCommand() *cobra.Command {
	var setup, force bool
	command := &cobra.Command{
		Use:   "token-helper get|store|erase | --setup",
		Short: "Act as the bao CLI's token helper",
		Long: `Implements the bao CLI's token helper protocol, so plain bao commands use the
token bao-cred would: inside a project with an identity, its Session Token in
an Agent Session, else its Named Token; elsewhere, your bao login token.

The CLI needs a file path, so bao-cred answers to the name ` + tokenHelperName + `
as bao-cred token-helper. --setup links that name next to the bao-cred you
run and names the link as token_helper in ~/.bao (or $BAO_CONFIG_PATH). It is
safe to rerun; --force replaces a different link or config.

get prints the token. store, called by bao login, writes the login token to
~/.vault-token, where bao-cred mints Named Tokens from. erase, called by bao
logout and bao token revoke -self, deletes ~/.vault-token, unless an identity
is selected: the token revoked was then the identity's, which bao-cred mints
again on next use. BAO_TOKEN and VAULT_TOKEN bypass the helper, as always.`,
		Example: `  bao-cred token-helper --setup
  bao read kv/data/app        # in a project: as the project's identity
  BAO_TOKEN=$(cat ~/.vault-token) bao policy list   # as yourself inside a project`,
		Args: func(command *cobra.Command, arguments []string) error {
			if setup {
				if len(arguments) != 0 {
					return usageError(errors.New("--setup takes no operation"))
				}

				return nil
			}

			if force {
				return usageError(errors.New("--force only applies to --setup"))
			}

			if len(arguments) != 1 {
				return usageError(fmt.Errorf("%s needs exactly one operation: get, store, or erase", command.Name()))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
			if setup {
				executable, err := invokedExecutable()
				if err != nil {
					return err
				}

				config, err := baoConfigPath()
				if err != nil {
					return err
				}

				return setupTokenHelper(executable, config, force, newProgress(command.ErrOrStderr(), false))
			}

			identity := identityFlag(command)
			switch arguments[0] {
			case "get":
				return tokenHelperGet(command.Context(), identity, command.OutOrStdout())
			case "store":
				return tokenHelperStore(command.InOrStdin())
			case "erase":
				return tokenHelperErase(identity)
			default:
				return usageError(fmt.Errorf("unknown token helper operation %q: use get, store, or erase", arguments[0]))
			}
		},
	}

	command.Flags().BoolVar(&setup, "setup", false, "link "+tokenHelperName+" and name it as token_helper in ~/.bao")
	command.Flags().BoolVar(&force, "force", false, "with --setup, replace a different link or token_helper")
	return command
}

// invokedExecutable is the bao-cred that was run, as invoked: through PATH
// that is the stable path of a package manager's link, such as Homebrew's,
// where os.Executable would resolve to a versioned file an upgrade removes.
func invokedExecutable() (string, error) {
	path, err := exec.LookPath(os.Args[0])
	if err != nil {
		if path, err = os.Executable(); err != nil {
			return "", fmt.Errorf("locate bao-cred: %w", err)
		}
	}

	return filepath.Abs(path)
}

func sameFile(first, second string) bool {
	firstResolved, firstErr := filepath.EvalSymlinks(first)
	secondResolved, secondErr := filepath.EvalSymlinks(second)
	return firstErr == nil && secondErr == nil && firstResolved == secondResolved
}

// baoConfigPath is the bao CLI's config file: $BAO_CONFIG_PATH, else ~/.bao.
func baoConfigPath() (string, error) {
	if path := os.Getenv("BAO_CONFIG_PATH"); path != "" {
		return filepath.Abs(path)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}

	return filepath.Join(home, ".bao"), nil
}

// setupTokenHelper names a tokenHelperName link to executable as the bao
// CLI's token_helper in config. It uses an existing link that resolves to
// executable, next to it or on PATH, as release archives and package
// managers ship one, and otherwise creates one next to executable. A link to
// another program, or a different config, is replaced only with force.
func setupTokenHelper(executable, config string, force bool, progress progressFunc) error {
	link, err := tokenHelperLink(executable, force, progress)
	if err != nil {
		return err
	}

	want := fmt.Sprintf("token_helper = %q\n", link)
	switch contents, err := os.ReadFile(config); { // #nosec G304 -- the bao CLI's own config file.
	case err == nil && string(contents) == want:
		progress(fmt.Sprintf("%s already names %s", config, link))
		return nil
	case err == nil && !force:
		return fmt.Errorf("%s already exists with other settings; pass --force to replace it with: %s", config, strings.TrimSpace(want))
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("read %s: %w", config, err)
	}

	if err := writeFile(config, []byte(want)); err != nil {
		return err
	}

	progress(fmt.Sprintf("wrote %s: bao now gets its token from bao-cred", config))
	return nil
}

// tokenHelperLink returns the tokenHelperName link that runs executable,
// creating it next to executable when neither that directory nor PATH has
// one. A link on PATH to another bao-cred is not used: bao would run a
// different version than the one being set up.
func tokenHelperLink(executable string, force bool, progress progressFunc) (string, error) {
	link := filepath.Join(filepath.Dir(executable), tokenHelperName)
	if sameFile(link, executable) {
		return link, nil
	}

	if found, err := exec.LookPath(tokenHelperName); err == nil {
		if found, err = filepath.Abs(found); err == nil && sameFile(found, executable) {
			progress(fmt.Sprintf("using %s on PATH", found))
			return found, nil
		}
	}

	// A relative target keeps working when the directory moves.
	target := filepath.Base(executable)
	switch _, err := os.Lstat(link); {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return "", fmt.Errorf("check %s: %w", link, err)
	case !force:
		return "", fmt.Errorf("%s already exists and doesn't run %s; pass --force to replace it", link, executable)
	default:
		if err := os.Remove(link); err != nil {
			return "", fmt.Errorf("replace %s: %w", link, err)
		}
	}

	if err := os.Symlink(target, link); err != nil {
		return "", fmt.Errorf("link %s: %w", link, err)
	}

	progress(fmt.Sprintf("linked %s to %s", link, target))
	return link, nil
}

// tokenHelperGet prints the token without a newline, or nothing when there is
// none, as the CLI's built-in helper does. The CLI handles BAO_TOKEN itself,
// so the environment's token is not consulted.
func tokenHelperGet(ctx context.Context, identity string, stdout io.Writer) error {
	identity, err := selectIdentity(identity)
	if err != nil {
		return err
	}

	token := ""
	switch {
	case identity != "":
		token, _, err = identityToken(ctx, identity, newProgress(os.Stderr, false))
		if err != nil {
			return err
		}
	case os.Getenv("BAO_NO_TOKEN_FILE") == "":
		token, _ = loginToken()
	}

	_, err = io.WriteString(stdout, token)
	return err
}

func tokenHelperStore(stdin io.Reader) error {
	contents, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}

	token := strings.TrimSpace(string(contents))
	if token == "" {
		return errors.New("no token on stdin")
	}

	path, err := loginTokenPath()
	if err != nil {
		return err
	}

	return writeFile(path, []byte(token))
}

func tokenHelperErase(identity string) error {
	identity, err := selectIdentity(identity)
	if err != nil || identity != "" {
		return err
	}

	path, err := loginTokenPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("erase %s: %w", path, err)
	}

	return nil
}
