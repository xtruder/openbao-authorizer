package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newGitCredentialCommand() *cobra.Command {
	var field string
	command := &cobra.Command{
		Use:   "git-credential [--field FIELD] <openbao-path> get|store|erase",
		Short: "Act as a git credential helper that answers with an OpenBao credential",
		Long: `Implements git's credential helper protocol: get reads <openbao-path> and
answers with username x-access-token and the field FIELD (default token) as
the password, such as a GitHub App installation token from
github/token/project-<name>. An expires_at field becomes password_expiry_utc,
so git doesn't reuse an expired token. Nothing is stored: store and erase do
nothing, and every get reads OpenBao again.

On permission denied it files a Grant Request for <openbao-path>=read with the
reason from BAO_REASON, else "git access to <url>", and waits for a decision.

git passes the operation after the arguments in the helper's command, and
picks the most specific credential section for a URL, so the path can follow
the organization or repository:

  [credential "https://github.com/example-org"]
      helper = "!bao-cred git-credential github/token/project-example"
      useHttpPath = true`,
		Example: `  git config --global credential.https://github.com/example-org.helper \
    '!bao-cred git-credential github/token/project-example'`,
		Args: func(_ *cobra.Command, arguments []string) error {
			if len(arguments) != 2 {
				return usageError(errors.New("git-credential needs an OpenBao path and an operation: get, store, or erase"))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
			switch arguments[1] {
			case "get":
				return runGitCredentialGet(command.Context(), identityFlag(command), arguments[0], field,
					command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			case "store", "erase":
				// Credentials expire within the hour; there is nothing to keep.
				_, err := io.Copy(io.Discard, command.InOrStdin())
				return err
			default:
				return usageError(fmt.Errorf("unknown git credential operation %q: use get, store, or erase", arguments[1]))
			}
		},
	}

	command.Flags().StringVar(&field, "field", "token", "dot path of the field that holds the password")
	return command
}

func runGitCredentialGet(ctx context.Context, identity, path, field string, stdin io.Reader, stdout, stderr io.Writer) error {
	request, err := readGitCredentialRequest(stdin)
	if err != nil {
		return err
	}

	reason := grantReason("")
	if reason == "" {
		reason = "git access to " + gitCredentialURL(request)
	}

	data, err := credentials(ctx, options{
		identity: identity, path: path, reason: reason,
		capabilities: []string{"read"}, timeout: defaultApprovalTimeout,
	}, stderr)
	if err != nil {
		return err
	}

	value, err := selectValue(data, field)
	if err != nil {
		return err
	}

	password, err := scalar(value)
	if err != nil || password == "" || strings.ContainsAny(password, "\n\x00") {
		return fmt.Errorf("%s at %s is not a usable password", field, path)
	}

	answer := "username=x-access-token\npassword=" + password + "\n"
	if expires, ok := data["expires_at"].(string); ok {
		if at, parseErr := time.Parse(time.RFC3339, expires); parseErr == nil {
			answer += fmt.Sprintf("password_expiry_utc=%d\n", at.Unix())
		}
	}

	_, err = io.WriteString(stdout, answer)
	return err
}

// readGitCredentialRequest reads git's key=value lines up to a blank line.
func readGitCredentialRequest(stdin io.Reader) (map[string]string, error) {
	request := map[string]string{}
	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}

		if key, value, ok := strings.Cut(line, "="); ok {
			request[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read the credential request: %w", err)
	}

	return request, nil
}

func gitCredentialURL(request map[string]string) string {
	url := request["protocol"] + "://" + request["host"]
	if path := request["path"]; path != "" {
		url += "/" + path
	}

	return url
}
