// Command bao-cred reads OpenBao credentials and requests Grants for the current Agent Session.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	openbao "github.com/openbao/openbao/api/v2"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

const usageText = `usage:
  bao-cred [flags] <openbao-path> [-- command [args...]]
  bao-cred request -reason TEXT -item PATH=CAP[,CAP] [-item ...] [-ttl D] [-timeout D] [-no-wait]
  bao-cred request -wait ID [-timeout D]
  bao-cred grants

Reads credentials from OpenBao with the Session Token in BAO_TOKEN (or
VAULT_TOKEN). When the token lacks access, bao-cred can file a Grant Request
with the authorizer and wait for an Approver to decide it.

Output flags:
  -format string       json (default), template, dotenv, or shell
  -field path          print one scalar field with no trailing newline
  -template string     render the data object with a Go template
  -map NAME=path       map a field for dotenv, shell, or command execution; repeatable
  -output path         atomically overwrite a file with mode 0600 instead of stdout

Access flags:
  -reason TEXT         on permission denied, request read access with this reason,
                       wait for a decision, and retry the read once
  -authorizer URL      authorizer base URL (default $OPENBAO_AUTHORIZER_URL)
  -timeout duration    approval wait timeout (default 15m)
  -quiet               suppress progress messages

Request flags:
  -reason TEXT         why the session needs access (required)
  -item PATH=CAPS      Permission Item; CAPS is a comma-separated list of
                       create, read, update, patch, delete, list; repeatable
  -ttl duration        requested Grant lifetime for every item
  -no-wait             print the filed request without waiting
  -wait ID             resume waiting on an existing Grant Request

Request outcomes are printed as JSON on stdout; progress goes to stderr.

Exit status:
  0  success; every Permission Item is approved or already granted
  1  error
  2  usage error
  3  a Permission Item was rejected, refused, expired, or revoked
  4  a Permission Item is still pending (timeout or -no-wait)
  In command mode, the command's own exit status is returned.

Examples:
  bao-cred -field token github/token/project-example
  bao-cred -reason "open a PR in org/repo" -field token github/token/project-example
  bao-cred request -reason "migrate app schema" -item database/creds/app=read -item kv/data/app=read,update
  bao-cred -format dotenv -map DB_USER=username -map DB_PASSWORD=password database/creds/app
  bao-cred -map GH_TOKEN=token github/token/project-example -- gh repo view org/repo
`

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

type repeatedFlag []string

func (m *repeatedFlag) String() string { return strings.Join(*m, ",") }
func (m *repeatedFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
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
	if err == nil || errors.Is(err, flag.ErrHelp) {
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

	if len(arguments) > 0 {
		switch arguments[0] {
		case "request":
			return runRequest(ctx, arguments[1:], stdout, stderr)
		case "grants":
			return runGrants(ctx, arguments[1:], stdout, stderr)
		}
	}

	return runRead(ctx, arguments, stdout, stderr)
}

func runRead(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	opts, err := parseOptions(arguments, stderr)
	if err != nil {
		return err
	}

	token, err := sessionToken()
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
				"%w\nhint: rerun with -reason TEXT to request read access, or file a Grant Request with "+
					"bao-cred request -reason TEXT -item %s=read",
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

func parseOptions(arguments []string, stderr io.Writer) (options, error) {
	var rawMappings repeatedFlag
	separator := len(arguments)
	for index, argument := range arguments {
		if argument == "--" {
			separator = index
			break
		}
	}

	flagArguments := arguments[:separator]
	var command []string
	if separator < len(arguments) {
		command = arguments[separator+1:]
		if len(command) == 0 {
			return options{}, usageError(errors.New("-- must be followed by a command"))
		}
	}

	flags := flag.NewFlagSet("bao-cred", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprint(stderr, usageText) }
	format := flags.String("format", "json", "output format")
	field := flags.String("field", "", "scalar field")
	templateSource := flags.String("template", "", "Go template")
	output := flags.String("output", "", "output file")
	reason := flags.String("reason", "", "Grant Request reason")
	authorizer := flags.String("authorizer", "", "authorizer URL")
	timeout := flags.Duration("timeout", 15*time.Minute, "approval timeout")
	quiet := flags.Bool("quiet", false, "suppress progress")
	flags.Var(&rawMappings, "map", "NAME=dot.path mapping")
	if err := flags.Parse(flagArguments); err != nil {
		return options{}, flagError(err)
	}

	if flags.NArg() != 1 {
		flags.Usage()
		return options{}, usageError(errors.New("exactly one OpenBao path is required"))
	}

	if *timeout <= 0 {
		return options{}, usageError(errors.New("timeout must be positive"))
	}

	mappings := make([]mapping, 0, len(rawMappings))
	for _, raw := range rawMappings {
		parsedMapping, err := parseMapping(raw)
		if err != nil {
			return options{}, usageError(err)
		}

		mappings = append(mappings, parsedMapping)
	}

	parsed := options{
		path: flags.Arg(0), format: *format, field: *field, template: *templateSource,
		output: *output, reason: strings.TrimSpace(*reason), authorizer: *authorizer, timeout: *timeout,
		quiet: *quiet, mappings: mappings, command: command,
	}
	if err := validateOptions(parsed); err != nil {
		return options{}, usageError(err)
	}

	return parsed, nil
}

// flagError keeps -h a clean exit while making other parse failures usage errors.
func flagError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return err
	}

	return usageError(err)
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
			return errors.New("command execution requires at least one -map")
		}

		return nil
	}

	if options.field != "" {
		if options.format != "json" || options.template != "" || len(options.mappings) > 0 {
			return errors.New("-field cannot be combined with -format, -template, or -map")
		}

		return nil
	}

	if options.template != "" && options.format == "json" {
		options.format = "template"
	}

	switch options.format {
	case "json":
		if options.template != "" || len(options.mappings) > 0 {
			return errors.New("json output cannot be combined with -template or -map")
		}
	case "template":
		if options.template == "" {
			return errors.New("template output requires -template")
		}

		if len(options.mappings) > 0 {
			return errors.New("template output cannot be combined with -map")
		}
	case "dotenv", "shell":
		if options.template != "" {
			return fmt.Errorf("%s output cannot be combined with -template", options.format)
		}

		if len(options.mappings) == 0 {
			return fmt.Errorf("%s output requires at least one -map", options.format)
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

// mergeEnvironment withholds the Session Token from the child: exec mode hands
// it only the mapped credentials, not the session's access to request more.
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

func sessionToken() (string, error) {
	for _, name := range []string{"BAO_TOKEN", "VAULT_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(name)); token != "" {
			return token, nil
		}
	}

	return "", errors.New("no Session Token: set BAO_TOKEN (or VAULT_TOKEN)")
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
