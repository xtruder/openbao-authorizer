package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// sshRenewBefore is how long a cached certificate must still be valid for
// ssh cert to reuse it, so it doesn't expire during the login. Shorter
// certificates need a fifth of their lifetime instead, or every connection
// would sign a new one.
const sshRenewBefore = 5 * time.Minute

type sshCertOptions struct {
	credentials options
	role        string
	mount       string
	key         string
	destination string
}

// sshOptionsWithArgument are the ssh options that take an argument, as in
// OpenSSH 10's getopt string; the destination is the first other argument.
const sshOptionsWithArgument = "BbcDEeFIiJLlmOoPpQRSWw"

func newSSHCommand() *cobra.Command {
	var opts sshCertOptions

	command := &cobra.Command{
		Use:   "ssh [flags] [--] [ssh options] user@host [command [args...]]",
		Short: "Run ssh with an OpenBao-signed certificate of the Requester",
		Long: `Runs ssh with a key and certificate that OpenBao signs for the current
Requester: in a project, its Named Identity, or its Agent Session inside one.
Each Requester keeps its own pair in $XDG_RUNTIME_DIR/bao-cred/ssh/<identity>/
<session>/<role>, reused while it stays valid, so a login always carries the
Requester's own Grant and shows up under its name in the server's log.

The role defaults to <host>-<user> of what ssh would connect to, as ssh -G
resolves the destination with the ssh config: the first DNS label of the host
as given, or of the Host alias, and the login user. core@jarvis.example.ts.net
uses jarvis-core; an alias jarvis with User offlinehq uses jarvis-offlinehq.
Pass --role for addresses and aliases not named after their host. On
permission denied it files a Grant Request for <mount>/sign/<role>=update
with the reason from --reason, else $BAO_REASON, else "ssh user@host", and
waits for a decision.

bao-cred flags come before the destination; put ssh's own options after --.
Alias ssh to it in your shell (alias ssh='bao-cred ssh'), and use it for other
tools: GIT_SSH_COMMAND='bao-cred ssh' or rsync -e 'bao-cred ssh'.
bao-cred ssh cert only ensures the key and certificate, for tools that need
the files.`,
		Example: `  bao-cred ssh --reason "check disk usage on jarvis" core@jarvis df -h
  bao-cred ssh jarvis
  bao-cred ssh --role jarvis-core -- -L 8080:localhost:80 core@100.126.6.34
  GIT_SSH_COMMAND='bao-cred ssh' git fetch`,
		Args: cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, arguments []string) error {
			if len(arguments) == 0 {
				return usageError(errors.New("an ssh destination is required, or the subcommand cert"))
			}

			return runSSH(command.Context(), opts, identityFlag(command), arguments,
				command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
		},
	}

	// Everything from the destination on belongs to ssh, including options
	// of the remote command.
	command.Flags().SetInterspersed(false)
	flags := command.Flags()
	flags.StringVar(&opts.role, "role", "", "SSH role to sign with (default <host>-<user> of the destination)")
	flags.StringVar(&opts.mount, "mount", "ssh", "path of the OpenBao SSH secrets engine")
	flags.StringVar(&opts.credentials.reason, "reason", "",
		"reason of a Grant Request on permission denied (default $BAO_REASON, else \"ssh user@host\")")
	flags.StringVar(&opts.credentials.scope, "scope", "", "suggested Grant scope: session, project, or global")
	flags.StringVar(&opts.credentials.authorizer, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	flags.DurationVar(&opts.credentials.timeout, "timeout", 15*time.Minute, "approval wait timeout")
	flags.BoolVar(&opts.credentials.quiet, "quiet", false, "suppress progress messages")
	command.AddCommand(newSSHCertCommand())
	return command
}

func runSSH(
	ctx context.Context, opts sshCertOptions, identity string, arguments []string, stdin io.Reader, stdout, stderr io.Writer,
) error {
	destination, err := sshDestination(arguments)
	if err != nil {
		return usageError(err)
	}

	opts.credentials.identity = identity
	opts.destination = arguments[destination]
	if opts.role == "" {
		if opts.role, opts.destination, err = sshRole(ctx, arguments[:destination+1]); err != nil {
			return err
		}
	}

	resolved, err := resolveSSHCertOptions(opts)
	if err != nil {
		return usageError(err)
	}

	if err := runSSHCert(ctx, resolved, stderr); err != nil {
		return err
	}

	sshArguments := append([]string{
		"-i", resolved.key, "-o", "CertificateFile=" + resolved.key + "-cert.pub", "-o", "IdentitiesOnly=yes",
	}, arguments...)
	// Not cancelled with ctx: ssh handles Ctrl-C itself, for the remote side.
	// #nosec G204 -- running ssh with the caller's arguments is the purpose of this command.
	command := exec.CommandContext(context.WithoutCancel(ctx), "ssh", sshArguments...)
	command.Env = mergeEnvironment(os.Environ(), nil)
	command.Stdin = stdin
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if processExit, ok := errors.AsType[*exec.ExitError](err); ok {
			return &exitError{code: commandExitCode(processExit)}
		}

		return fmt.Errorf("run ssh: %w", err)
	}

	return nil
}

// requesterKeyDirectory is where bao-cred ssh keeps the current Requester's
// keys: per Named Identity and Agent Session, or per token when BAO_TOKEN or
// VAULT_TOKEN names one directly.
func requesterKeyDirectory(identity string) (string, error) {
	base, err := sshKeyDirectory()
	if err != nil {
		return "", err
	}

	if token := environmentToken(); token != "" {
		return filepath.Join(base, "tokens", fmt.Sprintf("%x", sha256.Sum256([]byte(token)))[:16]), nil
	}

	identity, err = selectIdentity(identity)
	if err != nil {
		return "", err
	}

	session, err := agentSession()
	if err != nil {
		return "", err
	}

	if identity == "" {
		identity = "_login"
	}

	if session == "" {
		session = "_named"
	}

	return filepath.Join(base, identity, session), nil
}

// sshDestination returns the index of the destination in ssh's arguments,
// skipping options and their arguments as ssh's getopt does.
func sshDestination(arguments []string) (int, error) {
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			if index+1 < len(arguments) {
				return index + 1, nil
			}

			break
		}

		if len(argument) < 2 || argument[0] != '-' {
			return index, nil
		}

		for position := 1; position < len(argument); position++ {
			if strings.IndexByte(sshOptionsWithArgument, argument[position]) < 0 {
				continue
			}

			if position == len(argument)-1 {
				index++
				if index == len(arguments) {
					return 0, fmt.Errorf("ssh option -%c needs an argument", argument[position])
				}
			}

			break
		}
	}

	return 0, errors.New("an ssh destination is required")
}

func newSSHCertCommand() *cobra.Command {
	var opts sshCertOptions

	command := &cobra.Command{
		Use:   "cert [flags] [destination]",
		Short: "Ensure a valid SSH certificate for a role, signing a new one if needed",
		Long: `Ensures that KEY and KEY-cert.pub hold a private key and an OpenBao-signed
certificate of the current Requester for the SSH role, valid for at least 5
more minutes, or a fifth of its lifetime when that is shorter. A valid cached
pair is reused without contacting OpenBao; otherwise a new Ed25519 key is
generated and signed at <mount>/sign/<role>. Use it for tools that need the
files; bao-cred ssh runs ssh with them.

The role defaults to <host>-<user> of the destination, as for bao-cred ssh.
KEY defaults to the Requester's pair, $XDG_RUNTIME_DIR/bao-cred/ssh/<identity>/
<session>/<role>. On permission denied it files a Grant Request for
<mount>/sign/<role>=update with the reason from --reason, else $BAO_REASON,
else "ssh user@host", and waits for a decision. Progress goes to stderr;
nothing goes to stdout.`,
		Example: `  bao-cred ssh cert core@jarvis
  bao-cred ssh cert --role jarvis-core --key ./id --reason "deploy the app on jarvis"`,
		Args: func(_ *cobra.Command, arguments []string) error {
			if len(arguments) > 1 {
				return usageError(errors.New("at most one destination is allowed"))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
			opts.credentials.identity = identityFlag(command)
			if len(arguments) == 1 {
				opts.destination = arguments[0]
				if opts.role == "" {
					var err error
					if opts.role, opts.destination, err = sshRole(command.Context(), arguments); err != nil {
						return err
					}
				}
			}

			resolved, err := resolveSSHCertOptions(opts)
			if err != nil {
				return usageError(err)
			}

			return runSSHCert(command.Context(), resolved, command.ErrOrStderr())
		},
	}

	flags := command.Flags()
	flags.StringVar(&opts.role, "role", "", "SSH role to sign with (default <host>-<user> of the destination)")
	flags.StringVar(&opts.mount, "mount", "ssh", "path of the OpenBao SSH secrets engine")
	flags.StringVar(&opts.key, "key", "", "private key path; the certificate goes to KEY-cert.pub")
	flags.StringVar(&opts.credentials.reason, "reason", "",
		"reason of a Grant Request on permission denied (default $BAO_REASON, else \"ssh user@host\")")
	flags.StringVar(&opts.credentials.scope, "scope", "", "suggested Grant scope: session, project, or global")
	flags.StringVar(&opts.credentials.authorizer, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	flags.DurationVar(&opts.credentials.timeout, "timeout", 15*time.Minute, "approval wait timeout")
	flags.BoolVar(&opts.credentials.quiet, "quiet", false, "suppress progress messages")
	return command
}

// resolveSSHCertOptions fills in the role, key path and reason defaults.
func resolveSSHCertOptions(opts sshCertOptions) (sshCertOptions, error) {
	if opts.credentials.timeout <= 0 {
		return opts, errors.New("timeout must be positive")
	}

	if _, err := parseScope(opts.credentials.scope); err != nil {
		return opts, err
	}

	if opts.mount = strings.Trim(opts.mount, "/"); opts.mount == "" {
		return opts, errors.New("--mount must not be empty")
	}

	if opts.role == "" {
		return opts, errors.New("a destination or --role is required")
	}

	if err := validateSSHRole(opts.role); err != nil {
		return opts, err
	}

	if opts.key == "" {
		directory, err := requesterKeyDirectory(opts.credentials.identity)
		if err != nil {
			return opts, err
		}

		opts.key = filepath.Join(directory, opts.role)
	}

	opts.credentials.reason = grantReason(opts.credentials.reason)

	if opts.credentials.reason == "" {
		target := opts.destination
		if target == "" {
			target = "with role " + opts.role
		}

		opts.credentials.reason = "ssh " + target
	}

	return opts, nil
}

// sshRole names the role <host>-<user> after what ssh would connect to,
// resolving the options and destination in arguments with ssh -G, which
// applies the ssh config. It also returns user@host for the reason.
func sshRole(ctx context.Context, arguments []string) (string, string, error) {
	// #nosec G204 -- the caller's own ssh arguments, only resolved.
	command := exec.CommandContext(ctx, "ssh", append([]string{"-G"}, arguments...)...)
	var errorOutput bytes.Buffer
	command.Stderr = &errorOutput
	output, err := command.Output()
	if err != nil {
		return "", "", fmt.Errorf("resolve the ssh destination with ssh -G: %w: %s", err, strings.TrimSpace(errorOutput.String()))
	}

	var host, user string
	for line := range strings.SplitSeq(string(output), "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), " ")
		switch key {
		case "host":
			host = value
		case "user":
			user = value
		}
	}

	role, err := sshRoleFor(host, user)
	if err != nil {
		return "", "", usageError(err)
	}

	return role, user + "@" + host, nil
}

// sshRoleFor is the role <host>-<user>, from the first DNS label of host.
func sshRoleFor(host, user string) (string, error) {
	if host == "" || user == "" {
		return "", errors.New("ssh -G reported no host or user; pass --role")
	}

	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "", fmt.Errorf("cannot derive an SSH role from the address %s; pass --role", host)
	}

	label, _, _ := strings.Cut(host, ".")
	role := label + "-" + user
	if err := validateSSHRole(role); err != nil {
		return "", fmt.Errorf("%w; pass --role", err)
	}

	return role, nil
}

func validateSSHRole(role string) error {
	if role == "" || strings.ContainsAny(role, "/*+@ \t\n") {
		return fmt.Errorf("invalid SSH role %q", role)
	}

	return nil
}

// sshKeyDirectory prefers the per-user tmpfs of $XDG_RUNTIME_DIR, so keys
// never reach a disk where it exists.
func sshKeyDirectory() (string, error) {
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(runtime) {
		return filepath.Join(runtime, "bao-cred", "ssh"), nil
	}

	directory, err := stateDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, "ssh"), nil
}

func runSSHCert(ctx context.Context, opts sshCertOptions, stderr io.Writer) error {
	certificateFile := opts.key + "-cert.pub"
	if err := os.MkdirAll(filepath.Dir(opts.key), 0o700); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}

	// Concurrent ssh processes, such as parallel git fetches, must not
	// interleave writing a key and another's certificate.
	unlock, err := lockFile(opts.key + ".lock")
	if err != nil {
		return err
	}
	defer unlock()

	if validSSHCertificate(opts.key, certificateFile, time.Now()) {
		return nil
	}

	privateKey, publicKey, err := newSSHKey()
	if err != nil {
		return err
	}

	signing := opts.credentials
	signing.write = true
	signing.path = opts.mount + "/sign/" + opts.role
	signing.data = map[string]any{"public_key": publicKey}
	signing.capabilities = []string{"update"}
	if opts.destination != "" {
		signing.beforeRequest = func(ctx context.Context, authorizer *authorizerClient) error {
			return checkSSHRole(ctx, authorizer, signing.path)
		}
	}

	data, err := credentials(ctx, signing, stderr)
	if err != nil {
		return err
	}

	certificate, ok := data["signed_key"].(string)
	if !ok || certificate == "" {
		return fmt.Errorf("sign with %s: response has no signed_key", signing.path)
	}

	// The key first: until the certificate replaces the old one, ssh offers a
	// mismatched pair at worst, which the server refuses.
	if err := writeFile(opts.key, privateKey); err != nil {
		return err
	}

	return writeFile(certificateFile, []byte(certificate))
}

// validSSHCertificate reports whether certificateFile is a user certificate
// for the private key in keyFile that is valid at now and stays valid for the
// renewal margin.
func validSSHCertificate(keyFile, certificateFile string, now time.Time) bool {
	privateKey, err := os.ReadFile(keyFile) // #nosec G304 -- the caller's own key path.
	if err != nil {
		return false
	}

	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return false
	}

	contents, err := os.ReadFile(certificateFile) // #nosec G304 -- next to the caller's own key path.
	if err != nil {
		return false
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return false
	}

	certificate, ok := parsed.(*ssh.Certificate)
	if !ok || certificate.CertType != ssh.UserCert ||
		string(certificate.Key.Marshal()) != string(signer.PublicKey().Marshal()) {
		return false
	}

	if certificate.ValidBefore == ssh.CertTimeInfinity || certificate.ValidBefore <= certificate.ValidAfter {
		return false
	}

	lifetime := time.Duration(certificate.ValidBefore-certificate.ValidAfter) * time.Second // #nosec G115 -- checked positive above.
	margin := min(sshRenewBefore, lifetime/5)
	return certificate.ValidAfter <= uint64(now.Unix()) && // #nosec G115 -- Unix times after 1970 are positive.
		certificate.ValidBefore > uint64(now.Add(margin).Unix()) // #nosec G115
}

// newSSHKey returns a new Ed25519 private key in OpenSSH PEM format and its
// public key in authorized_keys format.
func newSSHKey() ([]byte, string, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate SSH key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(privateKey, "bao-cred")
	if err != nil {
		return nil, "", fmt.Errorf("encode SSH key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, "", fmt.Errorf("encode SSH key: %w", err)
	}

	return pem.EncodeToMemory(block), string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

func lockFile(path string) (func(), error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- next to the caller's own key path.
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- file descriptors fit in int.
		_ = file.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return func() { _ = file.Close() }, nil
}

// checkSSHRole refuses to request a derived role that the catalog doesn't
// list, so a mistyped host never reaches an Approver. Without discovered
// paths under the sign endpoint there is nothing to check against.
func checkSSHRole(ctx context.Context, authorizer *authorizerClient, path string) error {
	grantables, err := authorizer.grantables(ctx)
	if err != nil {
		return err
	}

	prefix := path[:strings.LastIndex(path, "/")+1]
	known := sshRoles(grantables, prefix)
	if len(known) == 0 || slices.Contains(known, strings.TrimPrefix(path, prefix)) {
		return nil
	}

	return fmt.Errorf("no SSH role at %s; pass --role with one of: %s", path, strings.Join(known, ", "))
}

// sshRoles returns the sorted role names that the catalog discovered under
// prefix, the sign endpoint of an SSH mount.
func sshRoles(grantables []grantableOutput, prefix string) []string {
	var roles []string
	for _, grantable := range grantables {
		for _, path := range grantable.Paths {
			if role, ok := strings.CutPrefix(path, prefix); ok && role != "" && !slices.Contains(roles, role) {
				roles = append(roles, role)
			}
		}
	}

	slices.Sort(roles)
	return roles
}
