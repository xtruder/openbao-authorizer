package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

func TestSSHRoleFor(t *testing.T) {
	for _, test := range []struct{ host, user, want string }{
		{"jarvis", "core", "jarvis-core"},
		{"jarvis.example.ts.net", "core", "jarvis-core"},
		{"build-01.lan", "deploy", "build-01-deploy"},
		{"100.126.6.34", "core", ""},
		{"[fd7a:115c:a1e0::3a01]", "core", ""},
		{"fd7a:115c:a1e0::3a01:62b", "core", ""},
		{"", "core", ""},
		{"jarvis", "", ""},
	} {
		got, err := sshRoleFor(test.host, test.user)
		if test.want == "" {
			if err == nil {
				t.Errorf("%s/%s: role %q, want an error", test.host, test.user, got)
			}

			continue
		}

		if err != nil || got != test.want {
			t.Errorf("%s/%s: role %q, %v; want %q", test.host, test.user, got, err, test.want)
		}
	}
}

func TestResolveSSHCertOptionsDefaults(t *testing.T) {
	setupEnvironment(t, "", "http://127.0.0.1:1")
	t.Setenv("BAO_TOKEN", "")
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	opts := sshCertOptions{mount: "/ssh/", role: "jarvis-core", destination: "core@jarvis", credentials: options{timeout: time.Minute}}

	resolved, err := resolveSSHCertOptions(opts)
	if err != nil {
		t.Fatal(err)
	}

	if resolved.mount != "ssh" || resolved.credentials.reason != "ssh core@jarvis" ||
		resolved.key != filepath.Join(runtimeDir, "bao-cred", "ssh", "_login", "_named", "jarvis-core") {
		t.Fatalf("resolved %+v", resolved)
	}

	t.Setenv("BAO_REASON", " deploy the app ")
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "deploy the app" {
		t.Fatalf("BAO_REASON: reason %q, %v", resolved.credentials.reason, err)
	}

	opts.credentials.reason = "from the flag"
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "from the flag" {
		t.Fatalf("--reason: reason %q, %v", resolved.credentials.reason, err)
	}

	t.Setenv("BAO_REASON", "")
	opts = sshCertOptions{mount: "ssh", role: "jarvis-core", credentials: options{timeout: time.Minute}}
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "ssh with role jarvis-core" {
		t.Fatalf("role only: reason %q, %v", resolved.credentials.reason, err)
	}

	if _, err = resolveSSHCertOptions(sshCertOptions{mount: "ssh", credentials: options{timeout: time.Minute}}); err == nil {
		t.Fatal("resolved without a role")
	}
}

func TestSSHCertUsageErrors(t *testing.T) {
	fakeSSH(t, 0)
	for _, arguments := range [][]string{
		{"ssh"},
		{"ssh", "cert"},
		{"ssh", "cert", "core@100.126.6.34"},
		{"ssh", "cert", "--role", "a/b"},
		{"ssh", "cert", "--role", "jarvis-core", "--mount", "/"},
		{"ssh", "cert", "--role", "jarvis-core", "--scope", "planet"},
		{"ssh", "cert", "core@jarvis", "core@other"},
	} {
		err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if exitCode(err) != exitUsage {
			t.Errorf("%v: error = %v (exit %d)", arguments, err, exitCode(err))
		}
	}
}

func TestSSHCertSignsOnceAndReusesTheCertificate(t *testing.T) {
	fakeSSH(t, 0)
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	key := filepath.Join(t.TempDir(), "keys", "jarvis-core")

	for range 2 {
		if err := run([]string{"ssh", "cert", "--key", key, "core@jarvis"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}

	if signer.reads() != 1 {
		t.Fatalf("OpenBao signed %d times, want once", signer.reads())
	}

	certificate := readCertificate(t, key)
	if certificate.ValidPrincipals[0] != "core@jarvis" || !validSSHCertificate(key, key+"-cert.pub", time.Now()) {
		t.Fatalf("certificate %+v does not match the key", certificate)
	}

	for _, path := range []string{key, key + "-cert.pub", filepath.Dir(key)} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s: mode %v, %v; want private", path, info.Mode(), err)
		}
	}
}

func TestSSHCertRenewsBeforeExpiry(t *testing.T) {
	// Valid 30s back and 5s ahead: less than a fifth of its lifetime is
	// left, so the certificate is already due for renewal.
	signer := newFakeSSHSigner(t, 5*time.Second, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	key := filepath.Join(t.TempDir(), "jarvis-core")

	for range 2 {
		if err := run([]string{"ssh", "cert", "--key", key, "--role", "jarvis-core"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}

	if signer.reads() != 2 {
		t.Fatalf("OpenBao signed %d times, want a new certificate each time", signer.reads())
	}
}

func TestSSHCertReplacesAMismatchedPair(t *testing.T) {
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	key := filepath.Join(t.TempDir(), "jarvis-core")
	if err := run([]string{"ssh", "cert", "--key", key, "--role", "jarvis-core"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	other, _, err := newSSHKey()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(key, other, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := run([]string{"ssh", "cert", "--key", key, "--role", "jarvis-core"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if signer.reads() != 2 || !validSSHCertificate(key, key+"-cert.pub", time.Now()) {
		t.Fatalf("signed %d times; the pair must match again", signer.reads())
	}
}

func TestSSHCertRequestsAccessWithTheDefaultReason(t *testing.T) {
	fakeSSH(t, 0)
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{{Name: "ssh-cert", Path: "ssh/sign/*", Paths: []string{"ssh/sign/jarvis-core"}}}
	authorizer.created = testRequest(item("item-1", "ssh/sign/jarvis-core", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "ssh/sign/jarvis-core", approved)),
	}}}
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return authorizer.watchCount() > 0 })
	setupEnvironment(t, authorizer.url, signer.URL)
	t.Setenv("BAO_REASON", "")
	key := filepath.Join(t.TempDir(), "jarvis-core")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"ssh", "cert", "--key", key, "core@jarvis.example.ts.net"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	want := &authorizerv1.CreateGrantRequestRequest{
		Reason: "ssh core@jarvis.example.ts.net",
		Items:  []*authorizerv1.PermissionItemInput{{Path: "ssh/sign/jarvis-core", Capabilities: []string{"update"}}},
	}
	if got := authorizer.inputs(); len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("filed %v, want %v", got, want)
	}

	// stdout belongs to the commands bao-cred runs, so progress goes to stderr only.
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "approved") {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func TestSSHCertRefusesARoleMissingFromTheCatalog(t *testing.T) {
	fakeSSH(t, 0)
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{{
		Name: "ssh-cert", Path: "ssh/sign/*", Paths: []string{"ssh/sign/jarvis-core", "ssh/sign/build-deploy"},
	}}
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return false })
	setupEnvironment(t, authorizer.url, signer.URL)

	err := run([]string{"ssh", "cert", "--key", filepath.Join(t.TempDir(), "k"), "core@core-jarvis"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no SSH role at ssh/sign/core-jarvis-core") ||
		!strings.Contains(err.Error(), "build-deploy, jarvis-core") {
		t.Fatalf("error = %v", err)
	}

	if len(authorizer.inputs()) != 0 {
		t.Fatal("filed a Grant Request for a role the catalog doesn't list")
	}
}

func TestSSHCertificateRenewalMargin(t *testing.T) {
	// A 5m certificate renews in its last minute, a 1h one in its last 5m.
	for _, test := range []struct {
		lifetime, left time.Duration
		valid          bool
	}{
		{5 * time.Minute, 2 * time.Minute, true},
		{5 * time.Minute, 50 * time.Second, false},
		{time.Hour, 6 * time.Minute, true},
		{time.Hour, 4 * time.Minute, false},
	} {
		key, certificate := signedTestPair(t, test.lifetime, test.left)
		if got := validSSHCertificate(key, certificate, time.Now()); got != test.valid {
			t.Errorf("lifetime %s, %s left: valid = %v, want %v", test.lifetime, test.left, got, test.valid)
		}
	}
}

// signedTestPair writes a key and a certificate for it, valid for lifetime
// in total with left of it remaining.
func signedTestPair(t *testing.T, lifetime, left time.Duration) (string, string) {
	t.Helper()
	privateKey, publicKey, err := newSSHKey()
	if err != nil {
		t.Fatal(err)
	}

	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	end := time.Now().Add(left)
	certificate := &ssh.Certificate{
		Key: parsed, CertType: ssh.UserCert, ValidPrincipals: []string{"core@jarvis"},
		ValidAfter: uint64(end.Add(-lifetime).Unix()), ValidBefore: uint64(end.Unix()), // #nosec G115
	}
	if err := certificate.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(key+"-cert.pub", ssh.MarshalAuthorizedKey(certificate), 0o600); err != nil {
		t.Fatal(err)
	}

	return key, key + "-cert.pub"
}

// newFakeSSHSigner serves ssh/sign/<role> like OpenBao's SSH engine, signing
// the posted key for the principal core@jarvis with a test CA. It denies
// signing until allowed reports true.
func newFakeSSHSigner(t *testing.T, ttl time.Duration, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}

	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			PublicKey string `json:"public_key"`
		}
		if request.Header.Get("X-Vault-Token") != testToken || request.Method != http.MethodPut ||
			!strings.HasPrefix(request.URL.Path, "/v1/ssh/sign/") || json.NewDecoder(request.Body).Decode(&body) != nil {
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
		publicKey, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(body.PublicKey))
		if parseErr != nil {
			http.Error(response, "bad public key", http.StatusBadRequest)
			return
		}

		now := time.Now()
		certificate := &ssh.Certificate{
			Key: publicKey, CertType: ssh.UserCert, KeyId: "test", ValidPrincipals: []string{"core@jarvis"},
			ValidAfter: uint64(now.Add(-30 * time.Second).Unix()), ValidBefore: uint64(now.Add(ttl).Unix()), // #nosec G115
		}
		if signErr := certificate.SignCert(rand.Reader, ca); signErr != nil {
			http.Error(response, signErr.Error(), http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]string{
			"serial_number": "01", "signed_key": string(ssh.MarshalAuthorizedKey(certificate)),
		}})
	}))
	t.Cleanup(server.Close)
	return fakeOpenBaoServer{Server: server, count: count}
}

func readCertificate(t *testing.T, key string) *ssh.Certificate {
	t.Helper()
	contents, err := os.ReadFile(key + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	certificate, ok := parsed.(*ssh.Certificate)
	if err != nil || !ok {
		t.Fatalf("certificate: %v", err)
	}

	return certificate
}

// fakeSSH puts an ssh on PATH that prints a usage summary without arguments,
// answers -G for a user@host destination,
// or a bare host with user offlinehq, and otherwise records its arguments in
// a file and exits with status. It returns a reader of the recorded runs.
func fakeSSH(t *testing.T, status int) func() []string {
	t.Helper()
	bin := t.TempDir()
	record := filepath.Join(bin, "runs")
	script := fmt.Sprintf(`#!/bin/sh
if [ $# -eq 0 ]; then
  echo "usage: ssh [-46] destination" >&2
  exit 255
fi
if [ "$1" = "-G" ]; then
  for argument; do last=$argument; done
  case "$last" in
    *@*) user=${last%%%%@*}; host=${last#*@} ;;
    *) user=offlinehq; host=$last ;;
  esac
  printf 'host %%s\nuser %%s\nhostname 192.0.2.1\n' "$host" "$user"
  exit 0
fi
printf '%%s\n' "$*" >> %q
exit %d
`, record, status)
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0o700); err != nil { // #nosec G306 -- an executable test script.
		t.Fatal(err)
	}

	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		contents, err := os.ReadFile(record)
		if err != nil {
			return nil
		}

		return strings.Split(strings.TrimSpace(string(contents)), "\n")
	}
}

func TestSSHRunsSSHWithTheRequestersCertificate(t *testing.T) {
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	runs := fakeSSH(t, 0)

	for range 2 {
		if err := run([]string{"ssh", "-p", "2222", "core@jarvis", "uptime", "-p"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}

	// BAO_TOKEN names the Requester here, so the pair is kept per token.
	key := filepath.Join(runtimeDir, "bao-cred", "ssh", "tokens", fmt.Sprintf("%x", sha256.Sum256([]byte(testToken)))[:16], "jarvis-core")
	want := "-i " + key + " -o CertificateFile=" + key + "-cert.pub -o IdentitiesOnly=yes -p 2222 core@jarvis uptime -p"
	if got := runs(); len(got) != 2 || got[0] != want {
		t.Fatalf("ssh ran with %q, want %q", got, want)
	}

	if signer.reads() != 1 || !validSSHCertificate(key, key+"-cert.pub", time.Now()) {
		t.Fatalf("signed %d times, want once and a valid pair at %s", signer.reads(), key)
	}
}

func TestSSHKeepsEachRequestersCertificateApart(t *testing.T) {
	bao := newFakeTokenStore(t)
	setupIdentityEnvironment(t, bao.URL)
	ring := useKeyring(t, nil)
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	ring.entries[keyringService+"/app-k7q2xm"] = "named-app"
	bao.valid["named-app"] = true
	root := newProject(t, "app", "")
	writeTestFile(t, filepath.Join(root, ".git", repositoryFileName), "app-k7q2xm\n")

	for session, want := range map[string]string{
		"":      filepath.Join(runtimeDir, "bao-cred", "ssh", "app-k7q2xm", "_named"),
		"ses-1": filepath.Join(runtimeDir, "bao-cred", "ssh", "app-k7q2xm", "ses-1"),
	} {
		t.Setenv("BAO_SESSION_ID", session)
		if got, err := requesterKeyDirectory(""); err != nil || got != want {
			t.Errorf("session %q: directory %q, %v; want %q", session, got, err, want)
		}
	}

	t.Setenv("BAO_SESSION_ID", "")
	t.Chdir(t.TempDir())
	if got, err := requesterKeyDirectory(""); err != nil || got != filepath.Join(runtimeDir, "bao-cred", "ssh", "_login", "_named") {
		t.Errorf("outside projects: directory %q, %v", got, err)
	}
}

func TestSSHPassesSSHArgumentsThrough(t *testing.T) {
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	runs := fakeSSH(t, 0)

	// Leading --name arguments are bao-cred's, before or after a global
	// --identity; the rest, including a bare --, is ssh's.
	for _, test := range []struct {
		arguments []string
		suffix    string
	}{
		{[]string{"ssh", "--reason=check the logs", "--quiet", "-L", "8080:localhost:80", "core@jarvis"}, " -L 8080:localhost:80 core@jarvis"},
		{[]string{"ssh", "--role", "jarvis-core", "--", "core@jarvis", "ls", "--all"}, " -- core@jarvis ls --all"},
		{[]string{"--identity", "app", "ssh", "--timeout", "1m", "core@jarvis"}, " core@jarvis"},
	} {
		if err := run(test.arguments, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
			t.Fatalf("%v: %v", test.arguments, err)
		}

		got := runs()
		if !strings.HasSuffix(got[len(got)-1], test.suffix) || !strings.Contains(got[len(got)-1], "/jarvis-core -o CertificateFile=") {
			t.Errorf("%v: ssh ran with %q, want it to end in %q", test.arguments, got[len(got)-1], test.suffix)
		}
	}
}

func TestSSHResolvesAliasesWithTheSSHConfig(t *testing.T) {
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	runs := fakeSSH(t, 0)

	// ssh -G reports user offlinehq for the alias, so the role is jarvis-offlinehq.
	if err := run([]string{"ssh", "jarvis", "true"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if got := runs(); len(got) != 1 || !strings.Contains(got[0], "/jarvis-offlinehq -o CertificateFile=") || !strings.HasSuffix(got[0], " jarvis true") {
		t.Fatalf("ssh ran with %q", got)
	}
}

func TestSSHReturnsTheExitStatusOfSSH(t *testing.T) {
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return true })
	setupEnvironment(t, "", signer.URL)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	fakeSSH(t, 7)

	if err := run([]string{"ssh", "core@jarvis", "false"}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != 7 {
		t.Fatalf("error = %v (exit %d), want 7", err, exitCode(err))
	}
}

func TestSSHUsageErrors(t *testing.T) {
	setupEnvironment(t, "", "http://127.0.0.1:1")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	runs := fakeSSH(t, 0)
	for _, arguments := range [][]string{
		{"ssh"},
		{"ssh", "core@100.126.6.34"},
		{"ssh", "-p"},
		{"ssh", "--role", "a/b", "core@jarvis"},
		{"ssh", "--bogus", "core@jarvis"},
		{"ssh", "--reason"},
		{"ssh", "--timeout", "soon", "core@jarvis"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
			t.Errorf("%v: error = %v (exit %d)", arguments, err, exitCode(err))
		}
	}

	if len(runs()) != 0 {
		t.Fatal("usage errors ran ssh")
	}
}

func TestSSHHelpIsSSHsUsage(t *testing.T) {
	fakeSSH(t, 0)
	var stdout bytes.Buffer
	if err := run([]string{"ssh", "--help"}, &stdout, &bytes.Buffer{}); err != nil || stdout.String() != "usage: ssh [-46] destination\n" {
		t.Fatalf("ssh --help = %q, %v", stdout.String(), err)
	}

	stdout.Reset()
	if err := run([]string{"help", "ssh"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), "--reason") {
		t.Fatalf("help ssh = %q, %v", stdout.String(), err)
	}
}
