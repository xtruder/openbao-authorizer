package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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

func newSSHCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "ssh",
		Short: "Keep OpenBao-signed SSH certificates for ssh to use",
		Long: `bao-cred acts as an ssh credential helper: a Match exec block in the ssh
config runs bao-cred ssh cert, which keeps a key and an OpenBao-signed
certificate for the destination's SSH role, and ssh logs in with them. Plain
ssh, scp, rsync and git all use it. bao-cred ssh config prints the blocks.`,
		Args: noPositionalArgs,
		RunE: func(*cobra.Command, []string) error {
			return usageError(errors.New("a subcommand is required: cert or config"))
		},
	}

	command.AddCommand(newSSHCertCommand(), newSSHConfigCommand())
	return command
}

func newSSHCertCommand() *cobra.Command {
	var opts sshCertOptions

	command := &cobra.Command{
		Use:   "cert [flags] [user@host]",
		Short: "Ensure a valid SSH certificate for a role, signing a new one if needed",
		Long: `Ensures that KEY and KEY-cert.pub hold a private key and an OpenBao-signed
certificate for the SSH role that stays valid for at least 5 more minutes, or
a fifth of its lifetime when that is shorter. A valid cached pair is reused
without contacting OpenBao; otherwise a new
Ed25519 key is generated and signed at <mount>/sign/<role>.

The role defaults to <host>-<user> of the destination, using the first DNS
label of the host: core@jarvis.example.ts.net uses jarvis-core. KEY defaults to
<role> in $XDG_RUNTIME_DIR/bao-cred/ssh, or else in the bao-cred state
directory.

On permission denied it files a Grant Request for <mount>/sign/<role>=update
with the reason from --reason, else $BAO_SSH_REASON, else "ssh user@host", and
waits for a decision. Progress goes to stderr; nothing goes to stdout. Run it
from a Match exec block (see bao-cred ssh config): on failure ssh skips the
block and falls back to its other keys.`,
		Example: `  bao-cred ssh cert core@jarvis
  bao-cred ssh cert --role jarvis-core --reason "deploy the app on jarvis"`,
		Args: func(_ *cobra.Command, arguments []string) error {
			if len(arguments) > 1 {
				return usageError(errors.New("at most one user@host destination is allowed"))
			}

			return nil
		},
		RunE: func(command *cobra.Command, arguments []string) error {
			if len(arguments) == 1 {
				opts.destination = arguments[0]
			}

			opts.credentials.identity = identityFlag(command)
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
		"reason of a Grant Request on permission denied (default $BAO_SSH_REASON, else \"ssh user@host\")")
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
		if opts.destination == "" {
			return opts, errors.New("a user@host destination or --role is required")
		}

		role, err := deriveSSHRole(opts.destination)
		if err != nil {
			return opts, err
		}

		opts.role = role
	}

	if err := validateSSHRole(opts.role); err != nil {
		return opts, err
	}

	if opts.key == "" {
		directory, err := sshKeyDirectory()
		if err != nil {
			return opts, err
		}

		opts.key = filepath.Join(directory, opts.role)
	}

	opts.credentials.reason = strings.TrimSpace(opts.credentials.reason)
	if opts.credentials.reason == "" {
		opts.credentials.reason = strings.TrimSpace(os.Getenv("BAO_SSH_REASON"))
	}

	if opts.credentials.reason == "" {
		target := opts.destination
		if target == "" {
			target = "with role " + opts.role
		}

		opts.credentials.reason = "ssh " + target
	}

	return opts, nil
}

// deriveSSHRole names the role <host>-<user> after a user@host destination.
func deriveSSHRole(destination string) (string, error) {
	user, host, ok := strings.Cut(destination, "@")
	if !ok || user == "" || host == "" {
		return "", fmt.Errorf("destination %q must be user@host, or pass --role", destination)
	}

	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return "", fmt.Errorf("cannot derive an SSH role from the address %s; pass --role", host)
	}

	label, _, _ := strings.Cut(host, ".")
	return label + "-" + user, nil
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

func newSSHConfigCommand() *cobra.Command {
	var (
		mount, authorizerURL string
		aliases              []string
	)

	command := &cobra.Command{
		Use:   "config [flags]",
		Short: "Print ssh config blocks that use bao-cred ssh cert",
		Long: `Prints one Match block for each SSH role in the catalog that is named
<host>-<user>: it applies when ssh logs in as <user> to <host> or <host>.*, as
given on the command line. --alias NAME=ROLE adds a block for an ssh Host alias
not named after the host. Add the output to ~/.ssh/config; Match blocks apply
after the Host blocks above them, so put it after those.`,
		Example: `  bao-cred ssh config >> ~/.ssh/config
  bao-cred ssh config --alias core-jarvis=jarvis-core`,
		Args: noPositionalArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return runSSHConfig(command.Context(), strings.Trim(mount, "/"), authorizerURL, identityFlag(command), aliases, command.OutOrStdout())
		},
	}

	flags := command.Flags()
	flags.StringVar(&mount, "mount", "ssh", "path of the OpenBao SSH secrets engine")
	flags.StringVar(&authorizerURL, "authorizer", "", "authorizer base URL (default $BAO_AUTHORIZER_ADDR)")
	flags.StringArrayVar(&aliases, "alias", nil, "NAME=ROLE: an ssh Host alias that logs in with ROLE; repeatable")
	return command
}

func runSSHConfig(ctx context.Context, mount, authorizerURL, identity string, aliases []string, stdout io.Writer) error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate bao-cred: %w", err)
	}

	directory, err := sshKeyDirectory()
	if err != nil {
		return err
	}

	client, err := requesterAuthorizerClient(ctx, authorizerURL, identity)
	if err != nil {
		return err
	}

	grantables, err := client.grantables(ctx)
	if err != nil {
		return err
	}

	roles := sshRoles(grantables, mount+"/sign/")
	var blocks []string
	for _, alias := range aliases {
		name, role, ok := strings.Cut(alias, "=")
		if !ok || name == "" || strings.ContainsAny(name, " \t\",") || validateSSHRole(role) != nil {
			return usageError(fmt.Errorf("--alias must be NAME=ROLE: %q", alias))
		}

		blocks = append(blocks, sshConfigBlock(executable, mount, directory, role, "originalhost "+name))
	}

	for _, role := range roles {
		host, user, ok := cutLast(role, "-")
		if !ok {
			continue
		}

		blocks = append(blocks, sshConfigBlock(executable, mount, directory, role,
			fmt.Sprintf("originalhost %s,%s.* user %s", host, host, user)))
	}

	if len(blocks) == 0 {
		return errors.New("the catalog lists no SSH roles named <host>-<user>; pass --alias NAME=ROLE")
	}

	_, err = fmt.Fprintf(stdout, "# OpenBao SSH certificates, from bao-cred ssh config.\n%s", strings.Join(blocks, "\n"))
	return err
}

func sshConfigBlock(executable, mount, directory, role, criteria string) string {
	key := filepath.Join(directory, role)
	command := fmt.Sprintf("%s ssh cert --mount %s --role %s %%r@%%n", shellQuote(executable), mount, role)
	return fmt.Sprintf("Match %s exec %q\n  IdentityFile %s\n  CertificateFile %s-cert.pub\n",
		criteria, command, sshConfigPath(key), sshConfigPath(key))
}

// sshConfigPath quotes a path for ssh_config when it contains spaces.
func sshConfigPath(path string) string {
	if strings.ContainsAny(path, " \t") {
		return fmt.Sprintf("%q", path)
	}

	return path
}

func shellQuote(value string) string {
	if value != "" && strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-") == "" {
		return value
	}

	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func cutLast(value, separator string) (string, string, bool) {
	index := strings.LastIndex(value, separator)
	if index <= 0 || index == len(value)-len(separator) {
		return "", "", false
	}

	return value[:index], value[index+len(separator):], true
}
