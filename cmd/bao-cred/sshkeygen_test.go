package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

// fakeTransit serves transit/sign/git-test, signing with key until allowed
// reports false, when it denies.
func fakeTransit(t *testing.T, key ed25519.PrivateKey, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Input string `json:"input"`
		}
		if request.Header.Get("X-Vault-Token") != testToken || request.Method != http.MethodPut ||
			request.URL.Path != "/v1/transit/sign/git-test" || json.NewDecoder(request.Body).Decode(&body) != nil {
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}

		response.Header().Set("Content-Type", "application/json")
		if !allowed() {
			response.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(response, `{"errors":["permission denied"]}`)
			return
		}

		count.add()
		input, err := base64.StdEncoding.DecodeString(body.Input)
		if err != nil {
			http.Error(response, "bad input", http.StatusBadRequest)
			return
		}

		signature := base64.StdEncoding.EncodeToString(ed25519.Sign(key, input))
		_, _ = fmt.Fprintf(response, `{"data":{"signature":"vault:v1:%s","key_version":1}}`, signature)
	}))
	t.Cleanup(server.Close)
	return fakeOpenBaoServer{Server: server, count: count}
}

// transitKeyFile writes the public key of key with an openbao: comment and
// returns its path and authorized_keys line.
func transitKeyFile(t *testing.T, key ed25519.PrivateKey, comment string) (string, string) {
	t.Helper()
	publicKey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + " " + comment
	path := filepath.Join(t.TempDir(), "signing.pub")
	writeTestFile(t, path, line+"\n")
	return path, line
}

func requireSSHKeygen(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is not installed")
	}
}

func TestSSHKeygenSignsWithTransitAndSSHKeygenVerifies(t *testing.T) {
	requireSSHKeygen(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	transit := fakeTransit(t, key, func() bool { return true })
	setupEnvironment(t, "", transit.URL)
	keyFile, line := transitKeyFile(t, key, "openbao:transit/git-test")
	message := filepath.Join(t.TempDir(), "commit")
	writeTestFile(t, message, "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor me\n\nsigned\n")

	// As git runs it: ssh-keygen -Y sign -n git -f KEY -U FILE, writing FILE.sig.
	if err := run([]string{"ssh-keygen", "-Y", "sign", "-n", "git", "-f", keyFile, "-U", message}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	allowed := filepath.Join(t.TempDir(), "allowed_signers")
	writeTestFile(t, allowed, "me@example.com "+line+"\n")
	verify := exec.CommandContext(t.Context(), "ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "me@example.com", "-n", "git", "-s", message+".sig")
	verify.Stdin = strings.NewReader("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor me\n\nsigned\n")
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, output)
	}

	// Another namespace doesn't verify.
	wrong := exec.CommandContext(t.Context(), "ssh-keygen", "-Y", "verify", "-f", allowed, "-I", "me@example.com", "-n", "file", "-s", message+".sig")
	wrong.Stdin = strings.NewReader("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor me\n\nsigned\n")
	if err := wrong.Run(); err == nil {
		t.Fatal("a git signature verified in the file namespace")
	}

	// Without a file it signs stdin to stdout.
	var stdout bytes.Buffer
	root := newRootCommand(runCredentials)
	root.SetArgs([]string{"ssh-keygen", "-Y", "sign", "-n", "file", "-f", keyFile})
	root.SetIn(strings.NewReader("hello"))
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	if err := root.ExecuteContext(t.Context()); err != nil || !strings.HasPrefix(stdout.String(), "-----BEGIN SSH SIGNATURE-----\n") {
		t.Fatalf("stdin signature = %q, %v", stdout.String(), err)
	}
}

func TestSSHKeygenRequestsAccessToSign(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "transit/sign/git-test", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "transit/sign/git-test", approved)),
	}}}
	transit := fakeTransit(t, key, func() bool { return authorizer.watchCount() > 0 })
	setupEnvironment(t, authorizer.url, transit.URL)
	t.Setenv("BAO_REASON", "sign the release commit")
	keyFile, _ := transitKeyFile(t, key, "openbao:transit/git-test")
	message := filepath.Join(t.TempDir(), "commit")
	writeTestFile(t, message, "commit\n")

	if err := run([]string{"ssh-keygen", "-Y", "sign", "-n", "git", "-f", keyFile, message}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	want := &authorizerv1.CreateGrantRequestRequest{
		Reason: "sign the release commit",
		Items:  []*authorizerv1.PermissionItemInput{{Path: "transit/sign/git-test", Capabilities: []string{"update"}}},
	}
	if got := authorizer.inputs(); len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("filed %v, want %v", got, want)
	}
}

func TestSSHKeygenRefusesAMismatchedTransitKey(t *testing.T) {
	_, declared, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	transit := fakeTransit(t, other, func() bool { return true })
	setupEnvironment(t, "", transit.URL)
	keyFile, _ := transitKeyFile(t, declared, "openbao:transit/git-test")
	message := filepath.Join(t.TempDir(), "commit")
	writeTestFile(t, message, "commit\n")

	err = run([]string{"ssh-keygen", "-Y", "sign", "-n", "git", "-f", keyFile, message}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "doesn't match the public key") {
		t.Fatalf("error = %v", err)
	}

	if _, statErr := os.Stat(message + ".sig"); !os.IsNotExist(statErr) {
		t.Fatalf("wrote a signature nobody can verify: %v", statErr)
	}
}

func TestSSHKeygenPassesOtherCallsToSSHKeygen(t *testing.T) {
	requireSSHKeygen(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A plain key and a non-signing operation both go to ssh-keygen, which
	// here prints the fingerprint.
	keyFile, _ := transitKeyFile(t, key, "me@example.com")
	var stdout bytes.Buffer
	if runErr := run([]string{"ssh-keygen", "-l", "-f", keyFile}, &stdout, &bytes.Buffer{}); runErr != nil || !strings.Contains(stdout.String(), "SHA256:") {
		t.Fatalf("ssh-keygen -l = %q, %v", stdout.String(), runErr)
	}

	request, ok, err := parseSSHSignArguments([]string{"-Y", "sign", "-n", "git", "-f", keyFile, "msg"})
	if err != nil || ok {
		t.Fatalf("plain key: %+v, %v, %v; want ssh-keygen", request, ok, err)
	}

	for comment, want := range map[string]string{
		"openbao:transit":       "<mount>/<key>",
		"openbao:transit/a/b":   "<mount>/<key>",
		"openbao:/transit/git/": "",
	} {
		keyFile, _ = transitKeyFile(t, key, comment)
		_, _, err = parseSSHSignArguments([]string{"-Y", "sign", "-n", "git", "-f", keyFile, "msg"})
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: error = %v", comment, err)
		}
	}
}

func TestSSHKeygenName(t *testing.T) {
	got := commandArguments([]string{"/usr/local/bin/" + sshKeygenName, "-Y", "sign"})
	if !slices.Equal(got, []string{"ssh-keygen", "-Y", "sign"}) {
		t.Fatalf("commandArguments = %v", got)
	}
}
