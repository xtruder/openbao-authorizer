// Command bao-cred reads OpenBao credentials and waits for control-group approval.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	openbao "github.com/openbao/openbao/api/v2"
	"golang.org/x/term"
)

const usageText = `usage:
  bao-cred login [flags]
  bao-cred logout [flags]
  bao-cred [flags] <openbao-path> [-- command [args...]]

Reads credentials from OpenBao. If the response requires control-group approval,
bao-cred waits for approval before unwrapping it.

Output flags:
  -format string       json (default), template, dotenv, or shell
  -field path          print one scalar field with no trailing newline
  -template string     render the data object with a Go template
  -map NAME=path       map a field for dotenv, shell, or command execution; repeatable
  -output path         atomically overwrite a file with mode 0600 instead of stdout

Request flags:
  -token-file path     read the request token from a file
  -timeout duration    approval timeout (default 15m)
  -poll-interval duration
                       approval polling interval (default 5s)
  -quiet               suppress approval progress messages

Examples:
	bao-cred -field token github/token/project-example
  bao-cred -format dotenv -map DB_USER=username -map DB_PASSWORD=password database/creds/app
  bao-cred -map GH_TOKEN=token github/token/project-example -- gh repo view org/repo
`

type options struct {
	path         string
	format       string
	field        string
	template     string
	output       string
	tokenFile    string
	timeout      time.Duration
	pollInterval time.Duration
	quiet        bool
	mappings     []mapping
	command      []string
}

type mappingFlags []string

func (m *mappingFlags) String() string { return strings.Join(*m, ",") }
func (m *mappingFlags) Set(value string) error {
	*m = append(*m, value)
	return nil
}

type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("command exited with status %d", e.code) }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if childExit, ok := errors.AsType[*exitError](err); ok {
			os.Exit(childExit.code)
		}

		fmt.Fprintln(os.Stderr, "bao-cred:", err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	return runWithInput(arguments, os.Stdin, stdout, stderr)
}

func runWithInput(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "login":
			return runLogin(arguments[1:], stdin, stdout, stderr)
		case "logout":
			return runLogout(arguments[1:], stdout, stderr)
		}
	}

	opts, err := parseOptions(arguments, stderr)
	if err != nil {
		return err
	}

	token, err := requestToken(opts.tokenFile)
	if err != nil {
		return err
	}

	client, err := newOpenBaoClient(opts.tokenFile, "")
	if err != nil {
		return fmt.Errorf("configure OpenBao client: %w", err)
	}

	client.SetToken(token)

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	approvalCtx, cancel := context.WithTimeout(rootCtx, opts.timeout)

	var progress progressFunc
	if !opts.quiet {
		progress = func(message string) { _, _ = fmt.Fprintln(stderr, message) }
	}

	data, err := readCredentials(approvalCtx, client, opts.path, opts.pollInterval, progress)
	cancel()
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("approval did not arrive within %s", opts.timeout)
		}

		return err
	}

	if len(opts.command) > 0 {
		return execute(rootCtx, opts.command, data, opts.mappings, stdout, stderr)
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

func runLogin(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bao-cred login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	username := flags.String("username", "", "OpenBao userpass username")
	address := flags.String("address", "", "OpenBao server address")
	tokenFile := flags.String("token-file", "", "token destination")
	passwordStdin := flags.Bool("password-stdin", false, "read the password from stdin")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("login accepts no positional arguments")
	}

	tokenPath, err := resolveTokenPath(*tokenFile)
	if err != nil {
		return err
	}

	resolvedAddress, err := resolveLoginAddress(*address, tokenPath, stdin, stderr, *passwordStdin)
	if err != nil {
		return err
	}

	resolvedUsername, err := resolveLoginUsername(*username, stdin, stderr, *passwordStdin)
	if err != nil {
		return err
	}

	password, err := readLoginPassword(stdin, stderr, *passwordStdin)
	if err != nil {
		return err
	}

	client, err := newOpenBaoClient(*tokenFile, resolvedAddress)
	if err != nil {
		return fmt.Errorf("configure OpenBao client: %w", err)
	}

	secret, err := client.Logical().WriteWithContext(
		context.Background(), "auth/userpass/login/"+url.PathEscape(resolvedUsername), map[string]any{"password": password},
	)
	if err != nil {
		return fmt.Errorf("userpass login: %w", err)
	}

	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return errors.New("OpenBao userpass login returned no token")
	}

	err = os.MkdirAll(filepath.Dir(tokenPath), 0o700)
	if err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}

	err = writeFile(tokenPath, []byte(secret.Auth.ClientToken+"\n"))
	if err != nil {
		return fmt.Errorf("store token: %w", err)
	}

	err = writeFile(filepath.Join(filepath.Dir(tokenPath), "address"), []byte(resolvedAddress+"\n"))
	if err != nil {
		return fmt.Errorf("store address: %w", err)
	}

	_, err = fmt.Fprintf(stdout, "Logged in as %s.\n", resolvedUsername)
	return err
}

func resolveLoginUsername(explicit string, stdin io.Reader, stderr io.Writer, passwordStdin bool) (string, error) {
	username := strings.TrimSpace(explicit)
	terminal, interactive := stdin.(*os.File)
	interactive = interactive && term.IsTerminal(int(terminal.Fd())) && !passwordStdin
	if username == "" && interactive {
		_, _ = fmt.Fprint(stderr, "Username [agent]: ")
		input, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read username: %w", err)
		}

		username = strings.TrimSpace(input)
	}

	if username == "" {
		username = "agent"
	}

	if strings.ContainsAny(username, "/\\") {
		return "", errors.New("invalid OpenBao username")
	}

	return username, nil
}

func resolveLoginAddress(explicit, tokenPath string, stdin io.Reader, stderr io.Writer, passwordStdin bool) (string, error) {
	address := strings.TrimSpace(explicit)
	if address == "" {
		address = strings.TrimSpace(os.Getenv("BAO_ADDR"))
	}

	if address == "" {
		contents, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "address"))
		if err == nil {
			address = strings.TrimSpace(string(contents))
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("read saved OpenBao address: %w", err)
		}
	}

	terminal, interactive := stdin.(*os.File)
	interactive = interactive && term.IsTerminal(int(terminal.Fd())) && !passwordStdin
	if explicit == "" && interactive {
		if address == "" {
			_, _ = fmt.Fprint(stderr, "OpenBao address: ")
		} else {
			_, _ = fmt.Fprintf(stderr, "OpenBao address [%s]: ", address)
		}

		input, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read OpenBao address: %w", err)
		}

		if input = strings.TrimSpace(input); input != "" {
			address = input
		}
	}

	if address == "" {
		return "", errors.New("OpenBao address is required; use -address or set BAO_ADDR")
	}

	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" || parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("OpenBao address must be an absolute HTTP or HTTPS URL")
	}

	return strings.TrimSuffix(address, "/"), nil
}

func newOpenBaoClient(tokenFile, explicitAddress string) (*openbao.Client, error) {
	config := openbao.DefaultConfig()
	if explicitAddress != "" {
		config.Address = explicitAddress
	} else if os.Getenv("BAO_ADDR") == "" {
		tokenPath, err := resolveTokenPath(tokenFile)
		if err != nil {
			return nil, err
		}

		contents, err := os.ReadFile(filepath.Join(filepath.Dir(tokenPath), "address"))
		if err == nil {
			config.Address = strings.TrimSpace(string(contents))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read saved OpenBao address: %w", err)
		}
	}

	client, err := openbao.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("configure OpenBao client: %w", err)
	}

	return client, nil
}

func runLogout(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("bao-cred logout", flag.ContinueOnError)
	flags.SetOutput(stderr)
	tokenFile := flags.String("token-file", "", "token file to remove")
	if err := flags.Parse(arguments); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("logout accepts no positional arguments")
	}

	path, err := resolveTokenPath(*tokenFile)
	if err != nil {
		return err
	}

	err = os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove token file: %w", err)
	}

	_, err = fmt.Fprintln(stdout, "Logged out.")
	return err
}

func readLoginPassword(stdin io.Reader, stderr io.Writer, fromStdin bool) (string, error) {
	if fromStdin {
		password, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read password: %w", err)
		}

		password = strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r")
		if password == "" {
			return "", errors.New("password is empty")
		}

		return password, nil
	}

	terminal, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(terminal.Fd())) {
		return "", errors.New("password prompt requires a terminal; use -password-stdin")
	}

	_, _ = fmt.Fprint(stderr, "Password: ")
	password, err := term.ReadPassword(int(terminal.Fd()))
	_, _ = fmt.Fprintln(stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	if len(password) == 0 {
		return "", errors.New("password is empty")
	}

	return string(password), nil
}

func parseOptions(arguments []string, stderr io.Writer) (options, error) {
	var rawMappings mappingFlags
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
			return options{}, errors.New("-- must be followed by a command")
		}
	}

	flags := flag.NewFlagSet("bao-cred", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _, _ = fmt.Fprint(stderr, usageText) }
	format := flags.String("format", "json", "output format")
	field := flags.String("field", "", "scalar field")
	templateSource := flags.String("template", "", "Go template")
	output := flags.String("output", "", "output file")
	tokenFile := flags.String("token-file", "", "request token file")
	timeout := flags.Duration("timeout", 15*time.Minute, "approval timeout")
	pollInterval := flags.Duration("poll-interval", 5*time.Second, "approval polling interval")
	quiet := flags.Bool("quiet", false, "suppress progress")
	flags.Var(&rawMappings, "map", "NAME=dot.path mapping")
	if err := flags.Parse(flagArguments); err != nil {
		return options{}, err
	}

	if flags.NArg() != 1 {
		flags.Usage()
		return options{}, errors.New("exactly one OpenBao path is required")
	}

	if *timeout <= 0 || *pollInterval <= 0 {
		return options{}, errors.New("timeout and poll interval must be positive")
	}

	mappings := make([]mapping, 0, len(rawMappings))
	for _, raw := range rawMappings {
		parsedMapping, err := parseMapping(raw)
		if err != nil {
			return options{}, err
		}

		mappings = append(mappings, parsedMapping)
	}

	parsed := options{
		path: flags.Arg(0), format: *format, field: *field, template: *templateSource,
		output: *output, tokenFile: *tokenFile, timeout: *timeout, pollInterval: *pollInterval,
		quiet: *quiet, mappings: mappings, command: command,
	}
	if err := validateOptions(parsed); err != nil {
		return options{}, err
	}

	return parsed, nil
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

func mergeEnvironment(environment, mapped []string) []string {
	names := map[string]struct{}{"BAO_TOKEN": {}}
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

func requestToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		return readTokenFile(tokenFile)
	}

	if token := os.Getenv("BAO_TOKEN"); token != "" {
		return token, nil
	}

	defaultPath, err := resolveTokenPath("")
	if err != nil {
		return "", err
	}

	token, err := readTokenFile(defaultPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", errors.New("no request token: run bao-cred login, set BAO_TOKEN, or use -token-file")
	}

	return token, err
}

func resolveTokenPath(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	configDirectory := os.Getenv("OPENBAO_CONTROL_GROUP_CONFIG_DIR")
	if configDirectory == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}

		configDirectory = filepath.Join(home, ".config", "openbao-authorizer")
	}

	return filepath.Join(configDirectory, "agent-token"), nil
}

func readTokenFile(path string) (string, error) {
	// #nosec G304,G703 -- token files are explicitly selected by the user or local configuration.
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}

	token := strings.TrimSpace(string(contents))
	if token == "" {
		return "", fmt.Errorf("token file %q is empty", path)
	}

	return token, nil
}
