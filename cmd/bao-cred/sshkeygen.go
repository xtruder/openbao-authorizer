package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

const (
	// sshKeygenName is the name bao-cred answers to as git's gpg.ssh.program,
	// which git runs with ssh-keygen's arguments, not a subcommand.
	sshKeygenName = "bao-cred-ssh-keygen"
	// openbaoKeyComment prefixes the comment of a public key whose private
	// key is an OpenBao transit key, as <mount>/<key>.
	openbaoKeyComment = "openbao:"
	// sshSignatureLineLength is the line length of armored SSH signatures.
	sshSignatureLineLength = 70
	// defaultApprovalTimeout is how long signing waits for an Approver;
	// git offers no flag to change it.
	defaultApprovalTimeout = 15 * time.Minute
)

func newSSHKeygenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ssh-keygen [ssh-keygen arguments]",
		Short: "Sign with an OpenBao transit key in place of ssh-keygen, for git",
		Long: `Acts as ssh-keygen for git's SSH signing. ssh-keygen -Y sign with a public key
whose comment is openbao:<mount>/<key> signs with that OpenBao transit key,
which never leaves OpenBao, through <mount>/sign/<key>; every other call runs
ssh-keygen itself, so verifying signatures and other keys work as before.

On permission denied it files a Grant Request for <mount>/sign/<key>=update
with the reason from BAO_REASON, else "sign with <key> in <directory>", and
waits for a decision. The key must be ed25519; the signature is checked
against the public key before it is written.

git runs gpg.ssh.program without a subcommand, so bao-cred answers to the name
` + sshKeygenName + ` as bao-cred ssh-keygen; release archives ship that link:

  git config --global gpg.format ssh
  git config --global gpg.ssh.program ` + sshKeygenName + `
  git config --global user.signingkey 'key::ssh-ed25519 AAAA... openbao:transit/git-me'
  git config --global commit.gpgsign true`,
		DisableFlagParsing: true,
		RunE: func(command *cobra.Command, arguments []string) error {
			if len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h") {
				return command.Help()
			}

			request, ok, err := parseSSHSignArguments(arguments)
			if err != nil {
				return usageError(err)
			}

			if !ok {
				return runSSHKeygen(command.Context(), arguments, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
			}

			request.identity = identityFlag(command)
			return runTransitSign(command.Context(), request, command.InOrStdin(), command.OutOrStdout(), command.ErrOrStderr())
		},
	}
}

// transitSignRequest is an ssh-keygen -Y sign call for an OpenBao key.
type transitSignRequest struct {
	identity  string
	namespace string
	publicKey ssh.PublicKey
	// path is the transit key as <mount>/<key>.
	path  string
	files []string
}

// parseSSHSignArguments recognizes ssh-keygen -Y sign -n NAMESPACE -f KEY
// [-U] [FILE...] for a public key file whose comment names an OpenBao
// transit key. ok is false for every other call, which goes to ssh-keygen.
func parseSSHSignArguments(arguments []string) (transitSignRequest, bool, error) {
	var request transitSignRequest
	var operation, keyFile string
	for index := 0; index < len(arguments); index++ {
		value := func() (string, error) {
			if index+1 == len(arguments) {
				return "", fmt.Errorf("%s needs a value", arguments[index])
			}

			index++
			return arguments[index], nil
		}

		var err error
		switch argument := arguments[index]; {
		case argument == "-Y":
			operation, err = value()
		case argument == "-n":
			request.namespace, err = value()
		case argument == "-f":
			keyFile, err = value()
		case argument == "-U":
			// The key is in an agent; for an OpenBao key, OpenBao is the agent.
		case argument == "-O":
			_, err = value()
		case strings.HasPrefix(argument, "-") && argument != "-":
			// An option this signer doesn't know: leave the call to ssh-keygen.
			return request, false, nil
		default:
			request.files = append(request.files, argument)
		}

		if err != nil {
			return request, false, err
		}
	}

	if operation != "sign" || keyFile == "" {
		return request, false, nil
	}

	contents, err := os.ReadFile(keyFile) // #nosec G304 -- the key file git or the caller names.
	if err != nil {
		// A private key file, or one ssh-keygen finds on its own.
		return request, false, nil //nolint:nilerr // ssh-keygen reports it.
	}

	publicKey, comment, _, _, err := ssh.ParseAuthorizedKey(contents)
	path, isOpenBao := strings.CutPrefix(comment, openbaoKeyComment)
	if err != nil || !isOpenBao {
		return request, false, nil //nolint:nilerr // Not an OpenBao key: ssh-keygen handles it.
	}

	mount, key, found := strings.Cut(strings.Trim(path, "/"), "/")
	if !found || mount == "" || key == "" || strings.Contains(key, "/") {
		return request, false, fmt.Errorf("key comment %q must be %s<mount>/<key>", comment, openbaoKeyComment)
	}

	if publicKey.Type() != ssh.KeyAlgoED25519 {
		return request, false, fmt.Errorf("OpenBao signing keys must be ed25519, not %s", publicKey.Type())
	}

	if request.namespace == "" {
		return request, false, errors.New("-Y sign needs -n NAMESPACE")
	}

	request.publicKey, request.path = publicKey, mount+"/"+key
	return request, true, nil
}

func runSSHKeygen(ctx context.Context, arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// #nosec G204 -- passing the caller's ssh-keygen arguments through is the purpose.
	command := exec.CommandContext(ctx, "ssh-keygen", arguments...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	if err := command.Run(); err != nil {
		if processExit, ok := errors.AsType[*exec.ExitError](err); ok {
			return &exitError{code: commandExitCode(processExit)}
		}

		return fmt.Errorf("run ssh-keygen: %w", err)
	}

	return nil
}

// runTransitSign signs each file, writing FILE.sig, or stdin to stdout when
// no file is given, as ssh-keygen -Y sign does.
func runTransitSign(ctx context.Context, request transitSignRequest, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(request.files) == 0 || len(request.files) == 1 && request.files[0] == "-" {
		message, err := io.ReadAll(stdin)
		if err != nil {
			return fmt.Errorf("read the message: %w", err)
		}

		signature, err := transitSSHSignature(ctx, request, message, stderr)
		if err != nil {
			return err
		}

		_, err = stdout.Write(signature)
		return err
	}

	for _, file := range request.files {
		message, err := os.ReadFile(file) // #nosec G304 -- the file the caller asks to sign.
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}

		signature, err := transitSSHSignature(ctx, request, message, stderr)
		if err != nil {
			return err
		}

		if err := writeFile(file+".sig", signature); err != nil {
			return err
		}
	}

	return nil
}

// transitSSHSignature returns an armored SSH signature (PROTOCOL.sshsig) of
// message, made by the OpenBao transit key of request.
func transitSSHSignature(ctx context.Context, request transitSignRequest, message []byte, stderr io.Writer) ([]byte, error) {
	digest := sha512.Sum512(message)
	signed := sshSignatureMagic()
	signed = appendSSHString(signed, []byte(request.namespace))
	signed = appendSSHString(signed, nil)
	signed = appendSSHString(signed, []byte("sha512"))
	signed = appendSSHString(signed, digest[:])

	mount, key, _ := strings.Cut(request.path, "/")
	directory, _ := os.Getwd()
	reason := grantReason("")
	if reason == "" {
		reason = fmt.Sprintf("sign with %s in %s", key, directory)
	}

	data, err := credentials(ctx, options{
		identity: request.identity, path: mount + "/sign/" + key, write: true, reason: reason,
		capabilities: []string{"update"}, timeout: defaultApprovalTimeout,
		data: map[string]any{"input": base64.StdEncoding.EncodeToString(signed)},
	}, stderr)
	if err != nil {
		return nil, err
	}

	raw, err := transitSignature(data)
	if err != nil {
		return nil, err
	}

	// A transit key other than the one git was told about would sign
	// commits nobody can verify; refuse rather than write them.
	cryptoKey, ok := request.publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("unsupported public key")
	}

	edKey, ok := cryptoKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok || !ed25519.Verify(edKey, signed, raw) {
		return nil, fmt.Errorf("the signature from %s doesn't match the public key; check the key comment", request.path)
	}

	blob := sshSignatureMagic()
	blob = binary.BigEndian.AppendUint32(blob, 1)
	blob = appendSSHString(blob, request.publicKey.Marshal())
	blob = appendSSHString(blob, []byte(request.namespace))
	blob = appendSSHString(blob, nil)
	blob = appendSSHString(blob, []byte("sha512"))
	blob = appendSSHString(blob, ssh.Marshal(ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: raw}))
	return armorSSHSignature(blob), nil
}

// transitSignature decodes the signature of a transit sign response,
// vault:v<version>:<base64>.
func transitSignature(data map[string]any) ([]byte, error) {
	value, _ := data["signature"].(string)
	index := strings.LastIndex(value, ":")
	if !strings.HasPrefix(value, "vault:v") || index < 0 {
		return nil, fmt.Errorf("unexpected transit signature %q", value)
	}

	raw, err := base64.StdEncoding.DecodeString(value[index+1:])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("transit returned a malformed ed25519 signature")
	}

	return raw, nil
}

func sshSignatureMagic() []byte { return []byte("SSHSIG") }

func appendSSHString(buffer, value []byte) []byte {
	buffer = binary.BigEndian.AppendUint32(buffer, uint32(len(value))) // #nosec G115 -- small fields.
	return append(buffer, value...)
}

func armorSSHSignature(blob []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(blob)
	var armored strings.Builder
	armored.WriteString("-----BEGIN SSH SIGNATURE-----\n")
	for len(encoded) > sshSignatureLineLength {
		armored.WriteString(encoded[:sshSignatureLineLength] + "\n")
		encoded = encoded[sshSignatureLineLength:]
	}

	armored.WriteString(encoded + "\n-----END SSH SIGNATURE-----\n")
	return []byte(armored.String())
}
