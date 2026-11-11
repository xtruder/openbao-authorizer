package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

func TestDeriveSSHRole(t *testing.T) {
	for destination, want := range map[string]string{
		"core@jarvis":                   "jarvis-core",
		"core@jarvis.example.ts.net":    "jarvis-core",
		"deploy@build-01.lan":           "build-01-deploy",
		"core@100.126.6.34":             "",
		"core@[fd7a:115c:a1e0::3a01]":   "",
		"jarvis":                        "",
		"@jarvis":                       "",
		"core@":                         "",
		"core@fd7a:115c:a1e0::3a01:62b": "",
	} {
		got, err := deriveSSHRole(destination)
		if want == "" {
			if err == nil {
				t.Errorf("%s: role %q, want an error", destination, got)
			}

			continue
		}

		if err != nil || got != want {
			t.Errorf("%s: role %q, %v; want %q", destination, got, err, want)
		}
	}
}

func TestResolveSSHCertOptionsDefaults(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("BAO_SSH_REASON", "")
	opts := sshCertOptions{mount: "/ssh/", destination: "core@jarvis", credentials: options{timeout: time.Minute}}

	resolved, err := resolveSSHCertOptions(opts)
	if err != nil {
		t.Fatal(err)
	}

	if resolved.role != "jarvis-core" || resolved.mount != "ssh" || resolved.credentials.reason != "ssh core@jarvis" ||
		resolved.key != filepath.Join(runtimeDir, "bao-cred", "ssh", "jarvis-core") {
		t.Fatalf("resolved %+v", resolved)
	}

	t.Setenv("BAO_SSH_REASON", " deploy the app ")
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "deploy the app" {
		t.Fatalf("BAO_SSH_REASON: reason %q, %v", resolved.credentials.reason, err)
	}

	opts.credentials.reason = "from the flag"
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "from the flag" {
		t.Fatalf("--reason: reason %q, %v", resolved.credentials.reason, err)
	}

	t.Setenv("BAO_SSH_REASON", "")
	opts = sshCertOptions{mount: "ssh", role: "jarvis-core", credentials: options{timeout: time.Minute}}
	if resolved, err = resolveSSHCertOptions(opts); err != nil || resolved.credentials.reason != "ssh with role jarvis-core" {
		t.Fatalf("role only: reason %q, %v", resolved.credentials.reason, err)
	}
}

func TestSSHCertUsageErrors(t *testing.T) {
	for _, arguments := range [][]string{
		{"ssh"},
		{"ssh", "cert"},
		{"ssh", "cert", "core@100.126.6.34"},
		{"ssh", "cert", "jarvis"},
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
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{{Name: "ssh-cert", Path: "ssh/sign/*", Paths: []string{"ssh/sign/jarvis-core"}}}
	authorizer.created = testRequest(item("item-1", "ssh/sign/jarvis-core", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "ssh/sign/jarvis-core", approved)),
	}}}
	signer := newFakeSSHSigner(t, time.Hour, func() bool { return authorizer.watchCount() > 0 })
	setupEnvironment(t, authorizer.url, signer.URL)
	t.Setenv("BAO_SSH_REASON", "")
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

	// ssh shows a Match exec command's stdout, so progress goes to stderr only.
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "approved") {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func TestSSHCertRefusesARoleMissingFromTheCatalog(t *testing.T) {
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

func TestSSHConfigBlocks(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{
		{Name: "github-token", Path: "github/token/project-*", Paths: []string{"github/token/project-a"}},
		{Name: "ssh-cert", Path: "ssh/sign/*", Paths: []string{"ssh/sign/jarvis-core", "ssh/sign/build-01-deploy", "ssh/sign/nouser"}},
	}
	setupEnvironment(t, authorizer.url, "http://127.0.0.1:1")
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	var stdout bytes.Buffer
	if err := run([]string{"ssh", "config", "--alias", "core-jarvis=jarvis-core"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	keys := filepath.Join(runtimeDir, "bao-cred", "ssh")
	output := stdout.String()
	for _, want := range []string{
		fmt.Sprintf("Match originalhost core-jarvis exec \"%s ssh cert --mount ssh --role jarvis-core %%r@%%n\"\n  IdentityFile %s/jarvis-core\n  CertificateFile %s/jarvis-core-cert.pub\n",
			shellQuote(executable), keys, keys),
		"Match originalhost jarvis,jarvis.* user core exec",
		"Match originalhost build-01,build-01.* user deploy exec",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output lacks %q:\n%s", want, output)
		}
	}

	if strings.Contains(output, "project-a") || strings.Contains(output, "nouser") {
		t.Errorf("output has blocks for other paths:\n%s", output)
	}

	for _, alias := range []string{"core-jarvis", "=jarvis-core", "core-jarvis=", "a b=jarvis-core", "core-jarvis=a/b"} {
		if err := run([]string{"ssh", "config", "--alias", alias}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitUsage {
			t.Errorf("--alias %q: error = %v", alias, err)
		}
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

func TestShellQuote(t *testing.T) {
	for value, want := range map[string]string{
		"/usr/local/bin/bao-cred": "/usr/local/bin/bao-cred",
		"/Users/me/My Tools/bao":  "'/Users/me/My Tools/bao'",
		"/tmp/it's":               `'/tmp/it'\''s'`,
	} {
		if got := shellQuote(value); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", value, got, want)
		}
	}
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
