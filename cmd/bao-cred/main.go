// Command bao-cred reads OpenBao credentials and requests Grants for the current Requester.
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

const rootLong = `Reads credentials from OpenBao with the Requester's token in BAO_TOKEN (or
VAULT_TOKEN). When the token lacks access, bao-cred can file a Grant Request
with the authorizer and wait for an Approver to decide it.

Request outcomes are printed as JSON on stdout; progress goes to stderr.

Exit status:
  0  success; every Permission Item is approved or already granted
  1  error
  2  usage error
  3  a Permission Item was rejected, refused, expired, or revoked
  4  a Permission Item is still pending (timeout or --no-wait)
  In command mode, the command's own exit status is returned.`

const rootExample = `  bao-cred read --field token github/token/project-example
  bao-cred read --reason "open a PR in org/repo" --field token github/token/project-example
  bao-cred request --reason "migrate app schema" --item database/creds/app=read --item kv/data/app=read,update
  bao-cred read --format dotenv --map DB_USER=username --map DB_PASSWORD=password database/creds/app
  bao-cred read --map GH_TOKEN=token github/token/project-example -- gh repo view org/repo`

const (
	exitFailure    = 1
	exitUsage      = 2
	exitNotGranted = 3
	exitPending    = 4
)

type options struct {
	path       string
	format     string
	field      string
	template   string
	output     string
	reason     string
	authorizer string
	timeout    time.Duration
	quiet      bool
	mappings   []mapping
	command    []string
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
	err := run(os.Args[1:], os.Stdout, os.Stderr)
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

	root := newRootCommand(runRead)
	root.SetArgs(arguments)
	root.SetOut(stdout)
	root.SetErr(stderr)
	command, err := root.ExecuteContextC(ctx)
	if coded, ok := errors.AsType[*exitError](err); ok && coded.code == exitUsage {
		coded.err = fmt.Errorf("%w\nrun '%s --help' for usage", coded.err, command.CommandPath())
	}

	return err
}

// readFunc runs the read command; tests replace it to inspect parsed options.
type readFunc func(ctx context.Context, opts options, stdout, stderr io.Writer) error

func newRootCommand(read readFunc) *cobra.Command {
	root := &cobra.Command{
		Use:     "bao-cred",
		Short:   "Read OpenBao credentials and request Grants",
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
	root.AddCommand(newReadCommand(read), newRequestCommand(), newGrantsCommand())
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

func newReadCommand(read readFunc) *cobra.Command {
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
			parsed, err := parseOptions(opts, rawMappings, arguments, command.ArgsLenAtDash())
			if err != nil {
				return err
			}

			return read(command.Context(), parsed, command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	flags := command.Flags()
	flags.StringVar(&opts.format, "format", "json", "output format: json, template, dotenv, or shell")
	flags.StringVar(&opts.field, "field", "", "print one scalar field at this dot path with no trailing newline")
	flags.StringVar(&opts.template, "template", "", "render the data object with a Go template")
	flags.StringArrayVar(&rawMappings, "map", nil,
		"NAME=path mapping for dotenv, shell, or command execution; repeatable")
	flags.StringVar(&opts.output, "output", "", "atomically overwrite this file with mode 0600 instead of stdout")
	flags.StringVar(&opts.reason, "reason", "",
		"on permission denied, request read access with this reason and retry once")
	flags.StringVar(&opts.authorizer, "authorizer", "", "authorizer base URL (default $OPENBAO_AUTHORIZER_URL)")
	flags.DurationVar(&opts.timeout, "timeout", 15*time.Minute, "approval wait timeout")
	flags.BoolVar(&opts.quiet, "quiet", false, "suppress progress messages")
	return command
}

func runRead(ctx context.Context, opts options, stdout, stderr io.Writer) error {
	token, err := requesterToken()
	if err != nil {
		return err
	}

	client, err := newOpenBaoClient(token)
	if err != nil {
		return err
	}

	progress := newProgress(stderr, opts.quiet)
	data, err := readCredentials(ctx, client, opts.path)
	if isPermissionDenied(err) {
		if opts.reason == "" {
			return fmt.Errorf(
				"%w\nhint: rerun with --reason TEXT to request read access, or file a Grant Request with "+
					"bao-cred request --reason TEXT --item %s=read",
				err, opts.path,
			)
		}

		err = requestReadAccess(ctx, opts, token, progress)
		if err != nil {
			return err
		}

		data, err = readCredentials(ctx, client, opts.path)
	}

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

func requestReadAccess(ctx context.Context, opts options, token string, progress progressFunc) error {
	authorizer, err := newAuthorizerClient(opts.authorizer, token)
	if err != nil {
		return fmt.Errorf("request read access: %w", err)
	}

	request, err := authorizer.createGrantRequest(ctx, &authorizerv1.CreateGrantRequestRequest{
		Reason: opts.reason,
		Items:  []*authorizerv1.PermissionItemInput{{Path: opts.path, Capabilities: []string{"read"}}},
	})
	if err != nil {
		return fmt.Errorf("request read access: %w", err)
	}

	progress(fmt.Sprintf("permission denied; filed Grant Request %s for %s=read", request.ID, opts.path))
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

	if dash != 1 {
		return options{}, usageError(errors.New("exactly one OpenBao path is required"))
	}

	opts.path = arguments[0]
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

func requesterToken() (string, error) {
	for _, name := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, nil
		}
	}

	return "", errors.New("no token: set BAO_TOKEN (or VAULT_TOKEN)")
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
