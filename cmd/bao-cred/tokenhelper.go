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

// tokenHelperName is the name bao-cred answers to as the bao CLI's token
// helper. The CLI runs `<token_helper> get|store|erase` and requires
// token_helper to be an existing file, so it can't name a subcommand; a
// symlink to bao-cred with this name works instead.
const tokenHelperName = "bao-cred-token-helper" // #nosec G101 -- a program name, not a credential.

// commandArguments maps a run under the token helper's name to the
// token-helper subcommand.
func commandArguments(argv []string) []string {
	if len(argv) > 0 && filepath.Base(argv[0]) == tokenHelperName {
		return append([]string{"token-helper"}, argv[1:]...)
	}

	return argv[1:]
}

func newTokenHelperCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "token-helper get|store|erase",
		Short: "Act as the bao CLI's token helper",
		Long: `Implements the bao CLI's token helper protocol, so plain bao commands use the
token bao-cred would: inside a project with an identity, its Session Token in
an Agent Session, else its Named Token; elsewhere, your bao login token.

The CLI needs a file path, so link bao-cred under the name ` + tokenHelperName + `
and name that link in ~/.bao (or $BAO_CONFIG_PATH):

  ln -s bao-cred ~/.local/bin/` + tokenHelperName + `
  echo 'token_helper = "'$HOME'/.local/bin/` + tokenHelperName + `"' > ~/.bao

get prints the token. store, called by bao login, writes the login token to
~/.vault-token, where bao-cred mints Named Tokens from. erase, called by bao
logout and bao token revoke -self, deletes ~/.vault-token, unless an identity
is selected: the token revoked was then the identity's, which bao-cred mints
again on next use. BAO_TOKEN and VAULT_TOKEN bypass the helper, as always.`,
		Example: `  bao read kv/data/app        # in a project: as the project's identity
  BAO_TOKEN=$(cat ~/.vault-token) bao policy list   # as yourself inside a project`,
		Args: func(command *cobra.Command, arguments []string) error {
			if len(arguments) != 1 {
				return usageError(fmt.Errorf("%s needs exactly one operation: get, store, or erase", command.Name()))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
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
