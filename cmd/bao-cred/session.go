package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
	"github.com/spf13/cobra"
)

const (
	defaultSessionRole = "agent-session"
	// Grant policy names, which the authorizer writes; see internal/grants.
	projectPolicyPrefix = "agent-grant-project-"
	globalPolicy        = "agent-grant-global"

	// renewBelow renews a session token once less than this remains of its
	// period, so an active session never expires.
	renewBelow = 12 * time.Hour
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$`)

// tokenPolicies are the policies a Named or session token is minted with:
// the role's baseline policy, by convention named like the role, plus the
// project and global Grant policies. The Grant policies may not exist yet;
// OpenBao evaluates policies by name on every request, so Grants the
// authorizer writes later apply to the token at once.
func tokenPolicies(role, project string) []string {
	return []string{role, projectPolicyPrefix + project, globalPolicy}
}

// agentSession returns the agent session the command runs in: BAO_SESSION_ID,
// else opencode's OPENCODE_SESSION_ID. BAO_NO_SESSION turns sessions off.
// Subagents have session IDs of their own, so they get their own sessions.
func agentSession() (string, error) {
	if os.Getenv("BAO_NO_SESSION") != "" {
		return "", nil
	}

	session := strings.TrimSpace(os.Getenv("BAO_SESSION_ID"))
	if session == "" {
		session = strings.TrimSpace(os.Getenv("OPENCODE_SESSION_ID"))
	}

	if session != "" && !sessionIDPattern.MatchString(session) {
		return "", fmt.Errorf("session ID must match %s: %q", sessionIDPattern, session)
	}

	return session, nil
}

// sessionToken returns the session token of project's agent session, minting
// it with the project's Named Token when it is missing or no longer valid.
// Session tokens live in files only: there is one per conversation, too many
// for the keyring. The same session always maps to the same entity alias, so
// a re-minted token keeps the session's Grants.
func sessionToken(ctx context.Context, project, session string, progress progressFunc) (string, error) {
	token, err := tokens().loadSession(project, session)
	if err == nil {
		valid, renewed, refreshErr := refreshSessionToken(ctx, token)
		if refreshErr != nil {
			return "", refreshErr
		}

		if renewed {
			tokens().touchSession(project, session)
			if projectToken, _, loadErr := tokens().loadNamed(project); loadErr == nil {
				if client, clientErr := newOpenBaoClient(projectToken); clientErr == nil {
					renewProjectToken(ctx, client)
				}
			}
		}

		if valid {
			return token, nil
		}
	} else if !errors.Is(err, errNoSessionToken) {
		return "", err
	}

	projectToken, _, err := tokens().loadNamed(project)
	if err != nil {
		return "", err
	}

	client, err := newOpenBaoClient(projectToken)
	if err != nil {
		return "", err
	}

	secret, err := client.Auth().Token().CreateWithRoleWithContext(ctx, &openbao.TokenCreateRequest{
		Policies:    tokenPolicies(sessionRole(), project),
		EntityAlias: project + "." + session,
		DisplayName: project + "." + session,
		Metadata:    map[string]string{"identity": project, "session": session},
	}, sessionRole())
	if isPermissionDenied(err) {
		return "", fmt.Errorf("mint session token: %w\nhint: the Named Token for %q may be invalid or minted before sessions existed; run bao-cred auth %s", err, project, project)
	}

	if err != nil {
		return "", fmt.Errorf("mint session token: %w", err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", errors.New("mint session token: empty response")
	}

	if err := tokens().saveSession(project, session, secret.Auth.ClientToken); err != nil {
		return "", err
	}

	progress(fmt.Sprintf("minted a session token for %s in %q", session, project))
	renewProjectToken(ctx, client)
	return secret.Auth.ClientToken, nil
}

// renewProjectToken keeps the project's Named Token alive while its sessions
// are in use: session tokens are its children and die with it. Failures are
// ignored; the next mint or renewal tries again.
func renewProjectToken(ctx context.Context, client *openbao.Client) {
	_, _ = client.Auth().Token().RenewSelfWithContext(ctx, 0)
}

func sessionRole() string {
	if role := strings.TrimSpace(os.Getenv("BAO_SESSION_ROLE")); role != "" {
		return role
	}

	return defaultSessionRole
}

// refreshSessionToken reports whether token is still valid and whether it
// was renewed because its period was running out.
func refreshSessionToken(ctx context.Context, token string) (bool, bool, error) {
	client, err := newOpenBaoClient(token)
	if err != nil {
		return false, false, err
	}

	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if isPermissionDenied(err) {
		return false, false, nil
	}

	if err != nil {
		return false, false, fmt.Errorf("look up session token: %w", err)
	}

	if ttl, _ := secret.TokenTTL(); ttl >= renewBelow {
		return true, false, nil
	}

	if _, err := client.Auth().Token().RenewSelfWithContext(ctx, 0); err != nil {
		return false, false, fmt.Errorf("renew session token: %w", err)
	}

	return true, true, nil
}

func newRunCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "run [flags] -- command [args...]",
		Short: "Run a command with the Requester's token in its environment",
		Long: `Runs a command with BAO_TOKEN and VAULT_TOKEN set to the token bao-cred itself
would use: BAO_TOKEN or VAULT_TOKEN when set, else the agent session's token
of the selected Named Identity (minted on first use), else its Named Token.
Use it for tools that read the token only from the environment, such as
secretspec and the bao CLI, so the token reaches that one command only.
The command's exit status is returned.`,
		Example: `  bao-cred run -- secretspec run -- make test
  bao-cred run -- bao kv get -mount=kv app/config`,
		Args: cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, arguments []string) error {
			dash := command.ArgsLenAtDash()
			if dash != 0 || len(arguments) == 0 {
				return usageError(errors.New("run needs -- followed by a command"))
			}

			token, err := requesterToken(command.Context(), identityFlag(command))
			if err != nil {
				return err
			}

			return runWithToken(command.Context(), token, arguments, command.OutOrStdout(), command.ErrOrStderr())
		},
	}
}

func runWithToken(ctx context.Context, token string, arguments []string, stdout, stderr io.Writer) error {
	// #nosec G204 -- executing the command after -- is the explicit purpose of run.
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	command.Env = mergeEnvironment(os.Environ(), []string{"BAO_TOKEN=" + token, "VAULT_TOKEN=" + token})
	command.Stdin = os.Stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if processExit, ok := errors.AsType[*exec.ExitError](err); ok {
			return &exitError{code: commandExitCode(processExit)}
		}

		return fmt.Errorf("run command: %w", err)
	}

	return nil
}
