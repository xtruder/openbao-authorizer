package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	openbao "github.com/openbao/openbao/api/v2"
	"github.com/spf13/cobra"
)

const defaultIdentityRole = "named-identity"

var identityNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func validateIdentityName(name string) error {
	if !identityNamePattern.MatchString(name) {
		return fmt.Errorf("identity name must match %s: %q", identityNamePattern, name)
	}

	return nil
}

// selectedIdentity returns the --identity flag, else BAO_IDENTITY.
func selectedIdentity(flag string) string {
	if flag = strings.TrimSpace(flag); flag != "" {
		return flag
	}

	return strings.TrimSpace(os.Getenv("BAO_IDENTITY"))
}

// loginToken is the human's own token from bao login, which mints Named
// Tokens. It ignores BAO_TOKEN, VAULT_TOKEN and BAO_NO_TOKEN_FILE because a
// project's .envrc sets those to the Named Token itself.
func loginToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}

	// `bao login` stores the token here with the default token helper.
	contents, err := os.ReadFile(filepath.Join(home, ".vault-token")) // #nosec G304 -- fixed file in the user's home.
	if token := strings.TrimSpace(string(contents)); err == nil && token != "" {
		return token, nil
	}

	return "", errors.New("no login token: run bao login first; bao-cred auth mints with the token in ~/.vault-token")
}

type identityStatus struct {
	Identity string `json:"identity"`
	// Session is set when the status is of an agent session's token.
	Session   string `json:"session,omitempty"`
	Store     string `json:"store"`
	EntityID  string `json:"entity_id"`
	TTL       string `json:"ttl"`
	Renewable bool   `json:"renewable"`
}

func lookupStatus(ctx context.Context, client *openbao.Client, name, store string) (identityStatus, error) {
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return identityStatus{}, fmt.Errorf("look up Named Token: %w", err)
	}

	ttl, _ := secret.TokenTTL()
	renewable, _ := secret.TokenIsRenewable()
	entityID, _ := secret.Data["entity_id"].(string)
	return identityStatus{Identity: name, Store: store, EntityID: entityID, TTL: ttl.String(), Renewable: renewable}, nil
}

// renewNamedToken extends a periodic Named Token by its full period.
func renewNamedToken(ctx context.Context, client *openbao.Client) error {
	if _, err := client.Auth().Token().RenewSelfWithContext(ctx, 0); err != nil {
		return fmt.Errorf("renew Named Token: %w", err)
	}

	return nil
}

func invalidTokenError(name string, err error) error {
	return fmt.Errorf("the Named Token for %q is invalid or expired; run bao-cred auth %s: %w", name, name, err)
}

func identityArgument(command *cobra.Command, arguments []string) (string, error) {
	if len(arguments) > 1 {
		return "", usageError(fmt.Errorf("%s accepts at most one identity name", command.Name()))
	}

	name := identityFlag(command)
	if len(arguments) == 1 {
		name = strings.TrimSpace(arguments[0])
	}

	if name == "" {
		var err error
		if name, err = projectIdentity(); err != nil {
			return "", err
		}
	}

	if name == "" {
		return "", usageError(errors.New("an identity name is required: pass it, --identity, set BAO_IDENTITY, or run bao-cred init in the project"))
	}

	if err := validateIdentityName(name); err != nil {
		return "", usageError(err)
	}

	return name, nil
}

type authFlags struct {
	store string
	role  string
	quiet bool
}

func newAuthCommand() *cobra.Command {
	var flags authFlags
	command := &cobra.Command{
		Use:   "auth [name]",
		Short: "Mint and store a Named Token with your bao login token",
		Long: `Mints a Named Token for the Named Identity <name> (default --identity,
$BAO_IDENTITY or the project's .bao-identity) through the named-identity token
role, using your own token from bao login (~/.vault-token). The new token replaces and revokes any stored one;
Grants stay on the identity. It is stored in the OS keyring (service bao-cred,
account <name>) when reachable, else in $XDG_STATE_HOME/bao-cred/<name>.token.
Prints the token's status as JSON.`,
		Example: `  bao-cred auth myproject
  BAO_IDENTITY=myproject bao-cred auth --store file`,
		RunE: func(command *cobra.Command, arguments []string) error {
			name, err := identityArgument(command, arguments)
			if err != nil {
				return err
			}

			return runAuth(command.Context(), name, flags, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	set := command.Flags()
	set.StringVar(&flags.store, "store", storeAuto, "where to store the token: auto (keyring, else file), keyring, or file")
	set.StringVar(&flags.role, "role", defaultIdentityRole, "token role that mints Named Tokens")
	set.BoolVar(&flags.quiet, "quiet", false, "suppress progress messages")
	return command
}

func runAuth(ctx context.Context, name string, flags authFlags, stdout, stderr io.Writer) error {
	switch flags.store {
	case storeAuto, storeKeyring, storeFile:
	default:
		return usageError(fmt.Errorf("unsupported store %q", flags.store))
	}

	client, err := loginClient(ctx)
	if err != nil {
		return err
	}

	token, store, err := mintNamedToken(ctx, client, name, flags.role, flags.store, newProgress(stderr, flags.quiet), newProgress(stderr, false))
	if err != nil {
		return err
	}

	client.SetToken(token)
	status, err := lookupStatus(ctx, client, name, store)
	if err != nil {
		return err
	}

	return writeIndentedJSON(stdout, status)
}

// loginClient returns an OpenBao client with the bao login token, renewed so
// that a periodic login lives on while it keeps minting. A failed renewal is
// ignored: minting reports an unusable login.
func loginClient(ctx context.Context) (*openbao.Client, error) {
	login, err := loginToken()
	if err != nil {
		return nil, err
	}

	client, err := newOpenBaoClient(login)
	if err != nil {
		return nil, err
	}

	_, _ = client.Auth().Token().RenewSelfWithContext(ctx, 0)
	return client, nil
}

// mintNamedToken mints a Named Token for name through role with the login
// token of client, stores it, and revokes the token it replaces. It returns
// the token and the store that holds it.
func mintNamedToken(
	ctx context.Context, client *openbao.Client, name, role, store string, progress, warn progressFunc,
) (string, string, error) {
	secret, err := client.Auth().Token().CreateWithRoleWithContext(ctx, &openbao.TokenCreateRequest{
		Policies:    tokenPolicies(role, name),
		EntityAlias: name,
		DisplayName: name,
		Metadata:    map[string]string{"identity": name},
	}, role)
	if err != nil {
		return "", "", fmt.Errorf("mint Named Token: %w", err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", "", errors.New("mint Named Token: empty response")
	}

	previous, _, _ := tokens().loadNamed(name)
	store, err = tokens().saveNamed(name, secret.Auth.ClientToken, store, warn)
	if err != nil {
		_ = revokeToken(ctx, secret.Auth.ClientToken)
		return "", "", err
	}

	progress(fmt.Sprintf("stored the Named Token for %q in the %s store", name, store))
	if previous != "" && previous != secret.Auth.ClientToken {
		// Revoking it revokes its session tokens too; sessions mint new ones
		// from the new token and keep their Grants.
		reportRevocation(revokeToken(ctx, previous), "the previous Named Token", progress, warn)
		if deleteErr := tokens().deleteSessions(name); deleteErr != nil {
			warn("warning: " + deleteErr.Error())
		}
	}

	return secret.Auth.ClientToken, store, nil
}

// namedToken returns name's stored Named Token and renews it, so a token in
// use never expires. When the token is invalid, or gone from its store, and
// this machine minted name before, it mints a new one with the bao login
// token. That is safe because the name comes from the caller's own selection
// or identity file, never from a checkout. A token OpenBao can't be asked
// about, such as while it is unreachable, is returned as it is.
func namedToken(ctx context.Context, name string, progress progressFunc) (string, error) {
	token, store, err := tokens().loadNamed(name)
	if err == nil {
		client, clientErr := newOpenBaoClient(token)
		if clientErr != nil {
			return "", clientErr
		}

		renewErr := renewNamedToken(ctx, client)
		if !isPermissionDenied(renewErr) {
			return token, nil
		}

		err = invalidTokenError(name, renewErr)
	} else if !errors.Is(err, errNoNamedToken) {
		return "", err
	}

	index, indexErr := readIndex()
	if indexErr != nil {
		return "", indexErr
	}

	known, minted := index.Named[name]
	if !minted {
		return "", err
	}

	if store == "" {
		store = known
	}

	client, loginErr := loginClient(ctx)
	if loginErr != nil {
		return "", fmt.Errorf("the Named Token for %q is invalid or missing, and there is no bao login to mint a new one: run bao login, then retry: %w", name, loginErr)
	}

	token, _, err = mintNamedToken(ctx, client, name, defaultIdentityRole, store, progress, progress)
	if err != nil {
		return "", fmt.Errorf("the Named Token for %q is invalid or missing; minting a new one failed (run bao login, then retry): %w", name, err)
	}

	return token, nil
}

// revokeToken revokes token with itself.
func revokeToken(ctx context.Context, token string) error {
	client, err := newOpenBaoClient(token)
	if err != nil {
		return err
	}

	return client.Auth().Token().RevokeSelfWithContext(ctx, "")
}

// reportRevocation treats permission denied as an already invalid token and
// warns about other failures, which leave the token valid.
func reportRevocation(err error, what string, progress, warn progressFunc) {
	switch {
	case err == nil:
		progress("revoked " + what)
	case isPermissionDenied(err):
		progress(what + " was already invalid")
	default:
		warn(fmt.Sprintf("warning: could not revoke %s, which stays valid until it expires: %v", what, err))
	}
}

func newStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status [name]",
		Short: "Renew the Named Token and print its status as JSON",
		Long: `Renews the stored Named Token of <name> (default --identity, $BAO_IDENTITY
or the project's .bao-identity) and prints the identity, its store, entity ID
and remaining TTL as JSON.`,
		RunE: func(command *cobra.Command, arguments []string) error {
			name, err := identityArgument(command, arguments)
			if err != nil {
				return err
			}

			return runStatus(command.Context(), name, command.OutOrStdout(), command.ErrOrStderr())
		},
	}
}

func runStatus(ctx context.Context, name string, stdout, stderr io.Writer) error {
	token, store, err := tokens().loadNamed(name)
	if err != nil {
		return err
	}

	client, err := newOpenBaoClient(token)
	if err != nil {
		return err
	}

	if err = renewNamedToken(ctx, client); err != nil {
		if isPermissionDenied(err) {
			return invalidTokenError(name, err)
		}

		return err
	}

	session, err := agentSession()
	if err != nil {
		return err
	}

	if session != "" {
		sessionTokenValue, sessionErr := sessionToken(ctx, name, session, newProgress(stderr, false))
		if sessionErr != nil {
			return sessionErr
		}

		client.SetToken(sessionTokenValue)
		store = storeFile
	}

	status, err := lookupStatus(ctx, client, name, store)
	if err != nil {
		return err
	}

	status.Session = session
	return writeIndentedJSON(stdout, status)
}

func newEnvCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "env [name]",
		Short: "Print shell exports of the Named Token for .envrc",
		Long: `Renews the stored Named Token of <name> (default --identity, $BAO_IDENTITY
or the project's .bao-identity) and prints shell exports of BAO_TOKEN,
VAULT_TOKEN and BAO_NO_TOKEN_FILE=1, for tools that read the token only from
the environment, such as the bao CLI and secretspec. Renewal failures other
than an invalid token are only warnings.

Without a valid token it still prints BAO_NO_TOKEN_FILE=1 and unsets BAO_TOKEN
and VAULT_TOKEN, so nothing falls back to your own token, and exits 1.`,
		Example: `  # .envrc of a project with .bao-identity
  eval "$(bao-cred env)"`,
		RunE: func(command *cobra.Command, arguments []string) error {
			name, err := identityArgument(command, arguments)
			if err != nil {
				return err
			}

			return runEnv(command.Context(), name, command.OutOrStdout(), command.ErrOrStderr())
		},
	}
}

func runEnv(ctx context.Context, name string, stdout, stderr io.Writer) error {
	token, err := envToken(ctx, name, newProgress(stderr, false))
	if err != nil {
		_, _ = io.WriteString(stdout, "unset BAO_TOKEN VAULT_TOKEN\nexport BAO_NO_TOKEN_FILE='1'\n")
		return err
	}

	_, err = stdout.Write(renderShell([]string{"BAO_TOKEN=" + token, "VAULT_TOKEN=" + token, "BAO_NO_TOKEN_FILE=1"}))
	return err
}

func envToken(ctx context.Context, name string, warn progressFunc) (string, error) {
	session, err := agentSession()
	if err != nil {
		return "", err
	}

	if session != "" {
		return envSessionToken(ctx, name, session, warn)
	}

	token, _, err := tokens().loadNamed(name)
	if err != nil {
		return "", err
	}

	client, err := newOpenBaoClient(token)
	if err != nil {
		return "", err
	}

	if err := renewNamedToken(ctx, client); err != nil {
		if isPermissionDenied(err) {
			return "", invalidTokenError(name, err)
		}

		// OpenBao may be unreachable when direnv loads; the token likely
		// still works, so export it anyway.
		warn("warning: " + err.Error())
	}

	return token, nil
}

func newLogoutCommand() *cobra.Command {
	var quiet bool
	command := &cobra.Command{
		Use:   "logout [name]",
		Short: "Revoke and delete the stored Named Token",
		Long: `Revokes the stored Named Token of <name> (default --identity,
$BAO_IDENTITY or the project's .bao-identity) and deletes it from the keyring
and the file store. Grants stay on the Named Identity until they expire, and
bao-cred auth can mint a new token.`,
		RunE: func(command *cobra.Command, arguments []string) error {
			name, err := identityArgument(command, arguments)
			if err != nil {
				return err
			}

			return runLogout(command.Context(), name, newProgress(command.ErrOrStderr(), quiet), newProgress(command.ErrOrStderr(), false))
		},
	}

	command.Flags().BoolVar(&quiet, "quiet", false, "suppress progress messages")
	return command
}

// envSessionToken is the session token to export. When OpenBao can't be
// reached to check it, a stored one is exported anyway, like a Named Token.
func envSessionToken(ctx context.Context, name, session string, warn progressFunc) (string, error) {
	token, err := sessionToken(ctx, name, session, warn)
	if err == nil {
		return token, nil
	}

	if stored, loadErr := tokens().loadSession(name, session); loadErr == nil && !isPermissionDenied(err) {
		warn("warning: " + err.Error())
		return stored, nil
	}

	return "", err
}

func runLogout(ctx context.Context, name string, progress, warn progressFunc) error {
	token, _, err := tokens().loadNamed(name)
	if errors.Is(err, errNoNamedToken) {
		progress(fmt.Sprintf("no Named Token stored for %q", name))
		return nil
	}

	if err != nil {
		return err
	}

	// Revoking the Named Token revokes its session tokens too.
	reportRevocation(revokeToken(ctx, token), "the Named Token", progress, warn)

	if err := tokens().deleteNamed(name, warn); err != nil {
		return err
	}

	if err := tokens().deleteSessions(name); err != nil {
		return err
	}

	progress(fmt.Sprintf("deleted the Named Token for %q", name))
	return nil
}
