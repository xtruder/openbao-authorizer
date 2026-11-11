// Command bao-cred reads and writes OpenBao credentials and requests Grants for the current Requester.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

const rootLong = `Reads and writes credentials in OpenBao with the Requester's token from BAO_TOKEN,
VAULT_TOKEN, the stored Named Token of --identity, BAO_IDENTITY or the
identity file of the working directory (see bao-cred init --help), or else the token file
~/.vault-token written by bao login (skipped when BAO_NO_TOKEN_FILE is set). When the token lacks access, bao-cred can file a Grant Request with
the authorizer at BAO_AUTHORIZER_ADDR and wait for an Approver to decide it;
bao-cred grantable lists the paths that may be requested.

bao-cred init selects a Named Identity for a git project and mints its Named
Token with your bao login token; bao-cred auth mints one for any name. Tokens
are stored in the OS keyring or a file; bao-cred env exports one for .envrc.

Request outcomes are printed as JSON on stdout; progress goes to stderr.

Exit status:
  0  success; every Permission Item is approved or already granted
  1  error
  2  usage error
  3  a Permission Item was rejected, refused, expired, or revoked
  4  a Permission Item is still pending (timeout or --no-wait)
  In command mode, the command's own exit status is returned.`

const rootExample = `  bao-cred init
  bao-cred grantable
  bao-cred read --field token github/token/project-example
  bao-cred read --reason "open a PR in org/repo" --field token github/token/project-example
  bao-cred request --reason "migrate app schema" --item database/creds/app=read --item kv/data/app=read,update
  bao-cred read --format dotenv --map DB_USER=username --map DB_PASSWORD=password database/creds/app
  bao-cred read --map GH_TOKEN=token github/token/project-example -- gh repo view org/repo
  bao-cred write --reason "ssh to jarvis" --field signed_key --output key-cert.pub ssh/sign/jarvis-core public_key=@key.pub
  bao-cred ssh --reason "check disk usage on jarvis" core@jarvis df -h`

const (
	exitFailure    = 1
	exitUsage      = 2
	exitNotGranted = 3
	exitPending    = 4
)

type options struct {
	identity string
	path     string
	// write selects a write of data instead of a read.
	write bool
	data  map[string]any
	// fields are the raw key=value arguments of write, before parseWriteData.
	fields []string
	// capabilities are requested on permission denied: read, or those of write.
	capabilities []string
	format       string
	field        string
	template     string
	output       string
	reason       string
	scope        string
	authorizer   string
	timeout      time.Duration
	quiet        bool
	mappings     []mapping
	command      []string
	// beforeRequest, if set, runs before a Grant Request is filed on
	// permission denied, and its error stops the request.
	beforeRequest func(ctx context.Context, authorizer *authorizerClient) error
}

// exitError carries a specific exit status. A nil err means the status came
// from a child command, which has already reported its own failure.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("command exited with status %d", e.code)
	}

	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func usageError(err error) error { return &exitError{code: exitUsage, err: err} }

func main() {
	err := run(commandArguments(os.Args), os.Stdout, os.Stderr)
	if err == nil {
		return
	}

	code := exitFailure
	if coded, ok := errors.AsType[*exitError](err); ok {
		code = coded.code
		err = coded.err
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "bao-cred:", err)
	}

	os.Exit(code)
}

func run(arguments []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := newRootCommand(runCredentials)
	root.SetArgs(arguments)
	root.SetOut(stdout)
	root.SetErr(stderr)
	command, err := root.ExecuteContextC(ctx)
	if coded, ok := errors.AsType[*exitError](err); ok && coded.code == exitUsage {
		coded.err = fmt.Errorf("%w\nrun '%s --help' for usage", coded.err, command.CommandPath())
	}

	return err
}

// credentialsFunc runs the read and write commands; tests replace it to
// inspect parsed options.
type credentialsFunc func(ctx context.Context, opts options, stdout, stderr io.Writer) error

func newRootCommand(run credentialsFunc) *cobra.Command {
	root := &cobra.Command{
		Use:     "bao-cred",
		Short:   "Read and write OpenBao credentials and request Grants",
		Long:    rootLong,
		Example: rootExample,
		Args:    cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, arguments []string) error {
			if len(arguments) > 0 {
				return usageError(fmt.Errorf("unknown command %q", arguments[0]))
			}

			return usageError(errors.New("a command is required"))
		},
		// main reports errors with the right exit status; cobra would print
		// them a second time, and print usage after runtime failures.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetFlagErrorFunc(flagError)
	root.PersistentFlags().String("identity", "", "Named Identity whose stored token to use (default $BAO_IDENTITY)")
	root.AddCommand(
		newReadCommand(run), newWriteCommand(run), newSSHCommand(), newRequestCommand(), newGrantsCommand(), newRevokeCommand(), newGrantableCommand(),
		newInitCommand(), newAuthCommand(), newStatusCommand(), newEnvCommand(), newLogoutCommand(), newRunCommand(),
		newTokenHelperCommand(),
	)
	return root
}

// flagError makes flag parsing failures usage errors. Earlier versions took
// single-dash long flags such as -reason, which pflag reads as a group of
// shorthands, so those get a pointer to the double-dash form.
func flagError(command *cobra.Command, err error) error {
	if notExist, ok := errors.AsType[*pflag.NotExistError](err); ok {
		name, _, _ := strings.Cut(notExist.GetSpecifiedShortnames(), "=")
		if len(name) > 1 && command.Flags().Lookup(name) != nil {
			return usageError(fmt.Errorf("%w; long flags take two dashes: --%s", err, name))
		}
	}

	return usageError(err)
}

func newReadCommand(run credentialsFunc) *cobra.Command {
	var (
		opts        options
		rawMappings []string
	)

	command := &cobra.Command{
		Use:   "read [flags] <openbao-path> [-- command [args...]]",
		Short: "Read credentials from an OpenBao path",
		Long: `Reads <openbao-path> and prints its data object, or runs a command with
mapped fields in its environment.

On permission denied, --reason files a Grant Request for PATH=read, waits for
a decision, and retries the read once. Without --reason the read fails with a
hint.`,
		Example: `  bao-cred read --field token github/token/project-example
  bao-cred read --reason "open a PR in org/repo" --field token github/token/project-example
  bao-cred read --map GH_TOKEN=token github/token/project-example -- gh repo view org/repo`,
		RunE: func(command *cobra.Command, arguments []string) error {
			opts.capabilities = []string{"read"}
			parsed, err := parseOptions(opts, rawMappings, arguments, command.ArgsLenAtDash())
			if err != nil {
				return err
			}

			parsed.identity = identityFlag(command)

			return run(command.Context(), parsed, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	addCredentialFlags(command.Flags(), &opts, &rawMappings, "read")
	return command
}

func newWriteCommand(run credentialsFunc) *cobra.Command {
	var (
		opts        options
		rawMappings []string
	)

	command := &cobra.Command{
		Use:   "write [flags] <openbao-path> [key=value ...] [-- command [args...]]",
		Short: "Write data to an OpenBao path",
		Long: `Writes the key=value pairs to <openbao-path> and prints the data object of
the response, or runs a command with mapped fields in its environment. Use it
for endpoints that take parameters and return credentials, such as
ssh/sign/<role>. As with bao write, key=@file reads a value from a file and
key=- from stdin.

On permission denied, --reason files a Grant Request for PATH with
--capabilities (default update), waits for a decision, and retries the write
once. Without --reason the write fails with a hint.`,
		Example: `  bao-cred write --reason "ssh to jarvis" --field signed_key --output key-cert.pub \
    ssh/sign/jarvis-core public_key=@key.pub
  bao-cred write --reason "rotate the webhook secret" --capabilities create,update \
    kv/data/app/webhook data=@secret.json`,
		RunE: func(command *cobra.Command, arguments []string) error {
			opts.write = true
			parsed, err := parseOptions(opts, rawMappings, arguments, command.ArgsLenAtDash())
			if err != nil {
				return err
			}

			parsed.data, err = parseWriteData(parsed.fields, command.InOrStdin())
			if err != nil {
				return err
			}

			parsed.identity = identityFlag(command)

			return run(command.Context(), parsed, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	flags := command.Flags()
	addCredentialFlags(flags, &opts, &rawMappings, "write")
	flags.StringSliceVar(&opts.capabilities, "capabilities", []string{"update"},
		"with --reason, the capabilities to request: create, update, or both")
	return command
}

// addCredentialFlags adds the output and Grant Request flags that read and
// write share; verb names the operation in their help.
func addCredentialFlags(flags *pflag.FlagSet, opts *options, rawMappings *[]string, verb string) {
	flags.StringVar(&opts.format, "format", "json", "output format: json, template, dotenv, or shell")
	flags.StringVar(&opts.field, "field", "", "print one scalar field at this dot path with no trailing newline")
	flags.StringVar(&opts.template, "template", "", "render the data object with a Go template")
	flags.StringArrayVar(rawMappings, "map", nil,
		"NAME=path mapping for dotenv, shell, or command execution; repeatable")
	flags.StringVar(&opts.output, "output", "", "atomically overwrite this file with mode 0600 instead of stdout")
	flags.StringVar(&opts.reason, "reason", "",
		fmt.Sprintf("on permission denied, request %s access with this reason and retry once", verb))
	flags.StringVar(&opts.scope, "scope", "", "with --reason, the suggested scope: session, project, or global")
	flags.StringVar(&opts.authorizer, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	flags.DurationVar(&opts.timeout, "timeout", 15*time.Minute, "approval wait timeout")
	flags.BoolVar(&opts.quiet, "quiet", false, "suppress progress messages")
}

func runCredentials(ctx context.Context, opts options, stdout, stderr io.Writer) error {
	data, err := credentials(ctx, opts, stderr)
	if err != nil {
		return err
	}

	if len(opts.command) > 0 {
		return execute(ctx, opts.command, data, opts.mappings, stdout, stderr)
	}

	contents, err := render(opts, data)
	if err != nil {
		return err
	}

	if opts.output != "" {
		return writeFile(opts.output, contents)
	}

	_, err = stdout.Write(contents)
	return err
}

// credentials reads or writes opts.path with the Requester's token. On
// permission denied with a reason, it requests access and retries once.
func credentials(ctx context.Context, opts options, stderr io.Writer) (map[string]any, error) {
	token, err := requesterToken(ctx, opts.identity)
	if err != nil {
		return nil, err
	}

	client, err := newOpenBaoClient(token)
	if err != nil {
		return nil, err
	}

	// A denied write changed nothing, so retrying it after approval is safe.
	access := func() (map[string]any, error) {
		if opts.write {
			return writeCredentials(ctx, client, opts.path, opts.data)
		}

		return readCredentials(ctx, client, opts.path)
	}

	progress := newProgress(stderr, opts.quiet)
	item := opts.path + "=" + strings.Join(opts.capabilities, ",")
	data, err := access()
	if isPermissionDenied(err) {
		if opts.reason == "" {
			return nil, fmt.Errorf(
				"%w\nhint: rerun with --reason TEXT to request access, or file a Grant Request with "+
					"bao-cred request --reason TEXT --item %s",
				err, item,
			)
		}

		if err = requestAccess(ctx, opts, token, progress); err != nil {
			return nil, err
		}

		data, err = access()
	}

	return data, err
}

func requestAccess(ctx context.Context, opts options, token string, progress progressFunc) error {
	item := opts.path + "=" + strings.Join(opts.capabilities, ",")
	authorizer, err := newAuthorizerClient(opts.authorizer, token)
	if err != nil {
		return fmt.Errorf("request %s: %w", item, err)
	}

	if opts.beforeRequest != nil {
		if err = opts.beforeRequest(ctx, authorizer); err != nil {
			return err
		}
	}

	scope, err := parseScope(opts.scope)
	if err != nil {
		return usageError(err)
	}

	request, err := authorizer.createGrantRequest(ctx, &authorizerv1.CreateGrantRequestRequest{
		Reason: opts.reason,
		Items:  []*authorizerv1.PermissionItemInput{{Path: opts.path, Capabilities: opts.capabilities, Scope: scope}},
	})
	if err != nil {
		return fmt.Errorf("request %s: %w", item, err)
	}

	progress(fmt.Sprintf("permission denied; filed Grant Request %s for %s", request.ID, item))
	request, err = waitForGrantRequest(ctx, authorizer, request, opts.timeout, progress)
	if err != nil {
		return err
	}

	return request.outcomeError(opts.timeout)
}

// parseOptions completes the flag values with the positional arguments.
// dash is cobra's ArgsLenAtDash: the number of arguments before "--", or -1.
func parseOptions(opts options, rawMappings, arguments []string, dash int) (options, error) {
	if dash < 0 {
		dash = len(arguments)
	} else {
		opts.command = arguments[dash:]
		if len(opts.command) == 0 {
			return options{}, usageError(errors.New("-- must be followed by a command"))
		}
	}

	switch {
	case opts.write && dash < 1:
		return options{}, usageError(errors.New("an OpenBao path is required"))
	case !opts.write && dash != 1:
		return options{}, usageError(errors.New("exactly one OpenBao path is required"))
	}

	opts.path = arguments[0]
	opts.fields = arguments[1:dash]
	opts.reason = strings.TrimSpace(opts.reason)
	if opts.timeout <= 0 {
		return options{}, usageError(errors.New("timeout must be positive"))
	}

	opts.mappings = make([]mapping, 0, len(rawMappings))
	for _, raw := range rawMappings {
		parsedMapping, err := parseMapping(raw)
		if err != nil {
			return options{}, usageError(err)
		}

		opts.mappings = append(opts.mappings, parsedMapping)
	}

	if err := validateOptions(opts); err != nil {
		return options{}, usageError(err)
	}

	return opts, nil
}

func validateOptions(options options) error {
	if options.scope != "" {
		if options.reason == "" {
			return errors.New("--scope requires --reason")
		}

		if _, err := parseScope(options.scope); err != nil {
			return err
		}
	}

	if options.write {
		if len(options.capabilities) == 0 {
			return errors.New("--capabilities must name create, update, or both")
		}

		for _, capability := range options.capabilities {
			if capability != "create" && capability != "update" {
				return fmt.Errorf("unsupported write capability %q: use create, update, or both", capability)
			}
		}
	}

	seenMappings := make(map[string]struct{}, len(options.mappings))
	for _, mapping := range options.mappings {
		if _, duplicate := seenMappings[mapping.Name]; duplicate {
			return fmt.Errorf("duplicate mapping %q", mapping.Name)
		}

		seenMappings[mapping.Name] = struct{}{}
	}

	if len(options.command) > 0 {
		if options.output != "" || options.field != "" || options.template != "" || options.format != "json" {
			return errors.New("command execution cannot be combined with output format flags")
		}

		if len(options.mappings) == 0 {
			return errors.New("command execution requires at least one --map")
		}

		return nil
	}

	if options.field != "" {
		if options.format != "json" || options.template != "" || len(options.mappings) > 0 {
			return errors.New("--field cannot be combined with --format, --template, or --map")
		}

		return nil
	}

	if options.template != "" && options.format == "json" {
		options.format = "template"
	}

	switch options.format {
	case "json":
		if options.template != "" || len(options.mappings) > 0 {
			return errors.New("json output cannot be combined with --template or --map")
		}
	case "template":
		if options.template == "" {
			return errors.New("template output requires --template")
		}

		if len(options.mappings) > 0 {
			return errors.New("template output cannot be combined with --map")
		}
	case "dotenv", "shell":
		if options.template != "" {
			return fmt.Errorf("%s output cannot be combined with --template", options.format)
		}

		if len(options.mappings) == 0 {
			return fmt.Errorf("%s output requires at least one --map", options.format)
		}
	default:
		return fmt.Errorf("unsupported format %q", options.format)
	}

	return nil
}

func render(options options, data map[string]any) ([]byte, error) {
	if options.field != "" {
		return renderField(data, options.field)
	}

	if options.template != "" {
		return renderTemplate(data, options.template)
	}

	if options.format == "json" {
		return renderJSON(data)
	}

	values, err := resolveMappings(data, options.mappings)
	if err != nil {
		return nil, err
	}

	if options.format == "dotenv" {
		return renderDotenv(values), nil
	}

	return renderShell(values), nil
}

func execute(ctx context.Context, arguments []string, data map[string]any, mappings []mapping, stdout, stderr io.Writer) error {
	values, err := resolveMappings(data, mappings)
	if err != nil {
		return err
	}

	// #nosec G204 -- executing the command after -- is the explicit purpose of exec mode.
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	command.Env = mergeEnvironment(os.Environ(), values)
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

// mergeEnvironment withholds the Requester's token from the child: exec mode
// hands it only the mapped credentials, not the access to request more.
func mergeEnvironment(environment, mapped []string) []string {
	names := map[string]struct{}{"BAO_TOKEN": {}, "VAULT_TOKEN": {}}
	for _, value := range mapped {
		name, _, _ := strings.Cut(value, "=")
		names[name] = struct{}{}
	}

	result := make([]string, 0, len(environment)+len(mapped))
	for _, value := range environment {
		name, _, _ := strings.Cut(value, "=")
		if _, replaced := names[name]; !replaced {
			result = append(result, value)
		}
	}

	return append(result, mapped...)
}

func environmentToken() string {
	for _, name := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token
		}
	}

	return ""
}

// identityToken returns the token commands use for the Named Identity name:
// the session token inside an agent session, else the Named Token, plus the
// session ID, if any.
func identityToken(ctx context.Context, name string, progress progressFunc) (string, string, error) {
	session, err := agentSession()
	if err != nil {
		return "", "", err
	}

	if session != "" {
		token, sessionErr := sessionToken(ctx, name, session, progress)
		return token, session, sessionErr
	}

	token, err := namedToken(ctx, name, progress)
	return token, "", err
}

// identityFlag returns the selected Named Identity: --identity, else
// BAO_IDENTITY.
func identityFlag(command *cobra.Command) string {
	flag, _ := command.Flags().GetString("identity")
	return selectedIdentity(flag)
}

// requesterToken finds the Requester's token. identity is the explicit
// selection; without one, the project's .bao-identity selects it. Inside an
// agent session the selected identity's session token is used. A selected
// identity without a stored token is an error rather than a fall back to the
// human's token.
func requesterToken(ctx context.Context, identity string) (string, error) {
	if token := environmentToken(); token != "" {
		return token, nil
	}

	identity, err := selectIdentity(identity)
	if err != nil {
		return "", err
	}

	if identity != "" {
		// Re-minting an invalid Named Token reports itself on stderr.
		token, _, err := identityToken(ctx, identity, newProgress(os.Stderr, false))
		return token, err
	}

	// BAO_NO_TOKEN_FILE keeps commands outside a project with an identity
	// from silently using the human's `bao login` token.
	if os.Getenv("BAO_NO_TOKEN_FILE") != "" {
		return "", errors.New("no token: run bao-cred init in the project, or set BAO_IDENTITY or BAO_TOKEN (or VAULT_TOKEN); the bao login token file is disabled by BAO_NO_TOKEN_FILE")
	}

	if token, err := loginToken(); err == nil {
		return token, nil
	}

	return "", errors.New("no token: run bao-cred init in the project, set BAO_IDENTITY or BAO_TOKEN (or VAULT_TOKEN), or run bao login")
}

// selectIdentity returns the selected Named Identity, validated: identity,
// else the working directory's identity file, else "".
func selectIdentity(identity string) (string, error) {
	if identity == "" {
		var err error
		if identity, err = projectIdentity(); err != nil {
			return "", err
		}
	}

	if identity == "" {
		return "", nil
	}

	return identity, validateIdentityName(identity)
}

func newOpenBaoClient(token string) (*openbao.Client, error) {
	config := openbao.DefaultConfig()
	if config.Error != nil {
		return nil, fmt.Errorf("configure OpenBao client: %w", config.Error)
	}

	client, err := openbao.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("configure OpenBao client: %w", err)
	}

	client.SetToken(token)
	return client, nil
}

type progressFunc func(string)

func newProgress(stderr io.Writer, quiet bool) progressFunc {
	if quiet {
		return func(string) {}
	}

	return func(message string) { _, _ = fmt.Fprintln(stderr, message) }
}
