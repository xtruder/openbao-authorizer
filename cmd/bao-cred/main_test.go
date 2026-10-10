package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

const testToken = "session-token-value"

// parseRead runs the read command with arguments and returns the options it
// would read with.
func parseRead(t *testing.T, arguments ...string) (options, error) {
	t.Helper()
	var parsed options
	root := newRootCommand(func(_ context.Context, opts options, _, _ io.Writer) error {
		parsed = opts
		return nil
	})
	root.SetArgs(append([]string{"read"}, arguments...))
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	err := root.Execute()
	return parsed, err
}

func TestParseOutputAndExecModes(t *testing.T) {
	output, err := parseRead(t, "--field", "database.username", "--reason", " deploy ", "secret/path")
	if err != nil {
		t.Fatal(err)
	}

	if output.path != "secret/path" || output.field != "database.username" || output.reason != "deploy" {
		t.Fatalf("unexpected options: %#v", output)
	}

	execOptions, err := parseRead(t, "--map", "TOKEN=token", "secret/path", "--", "tool", "--field", "arg")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(execOptions.command, []string{"tool", "--field", "arg"}) ||
		execOptions.mappings[0].Name != "TOKEN" || execOptions.field != "" {
		t.Fatalf("unexpected options: %#v", execOptions)
	}
}

func TestParseAcceptsFlagsAfterPath(t *testing.T) {
	parsed, err := parseRead(t, "secret/path", "--field", "token")
	if err != nil {
		t.Fatal(err)
	}

	if parsed.path != "secret/path" || parsed.field != "token" || parsed.command != nil {
		t.Fatalf("unexpected options: %#v", parsed)
	}
}

func TestParseRejectsMixedDeliveryModes(t *testing.T) {
	_, err := parseRead(t, "--field", "token", "--map", "TOKEN=token", "secret/path", "--", "tool")
	if exitCode(err) != exitUsage {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestParseRejectsDuplicateMappings(t *testing.T) {
	_, err := parseRead(t, "--format", "dotenv", "--map", "TOKEN=one", "--map", "TOKEN=two", "secret/path")
	if exitCode(err) != exitUsage {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestReadUsageErrors(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)
	for _, arguments := range [][]string{
		{},
		{"secret/app"},
		{"unknown", "secret/app"},
		{"read"},
		{"read", "secret/app", "secret/other"},
		{"read", "--map", "TOKEN=token", "secret/app", "--"},
		{"read", "--map", "TOKEN=token", "--", "tool"},
		{"read", "--timeout", "0s", "secret/app"},
		{"read", "--timeout", "soon", "secret/app"},
		{"read", "--format", "xml", "secret/app"},
		{"read", "--map", "TOKEN", "secret/app"},
		{"read", "-reason", "deploy", "secret/app"},
		{"read", "--unknown", "secret/app"},
	} {
		var stdout, stderr bytes.Buffer
		err := run(arguments, &stdout, &stderr)
		if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "--help' for usage") {
			t.Fatalf("%v: error = %v (exit %d)", arguments, err, exitCode(err))
		}

		// main prints the error once; cobra itself prints nothing.
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("%v: stdout %q, stderr %q", arguments, stdout.String(), stderr.String())
		}
	}

	if openBao.reads() != 0 {
		t.Fatalf("usage errors reached OpenBao %d times", openBao.reads())
	}
}

func TestSingleDashLongFlagHintsDoubleDash(t *testing.T) {
	for _, arguments := range [][]string{
		{"read", "-reason", "deploy", "secret/app"},
		{"read", "-field=token", "secret/app"},
		{"request", "-item", "kv/data/a=read"},
	} {
		err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		flag, _, _ := strings.Cut(strings.TrimPrefix(arguments[1], "-"), "=")
		if exitCode(err) != exitUsage || !strings.Contains(err.Error(), "long flags take two dashes: --"+flag) {
			t.Fatalf("%v: error = %v (exit %d)", arguments, err, exitCode(err))
		}
	}
}

func TestRuntimeErrorPrintsNoUsage(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return false })
	setupEnvironment(t, "", openBao.URL)

	var stdout, stderr bytes.Buffer
	err := run([]string{"read", "secret/app"}, &stdout, &stderr)
	if exitCode(err) != exitFailure || strings.Contains(err.Error(), "for usage") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func TestHelpExitsCleanly(t *testing.T) {
	for _, arguments := range [][]string{{"--help"}, {"read", "-h"}, {"request", "--help"}, {"help", "grants"}} {
		var stdout bytes.Buffer
		if err := run(arguments, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatalf("%v: error = %v", arguments, err)
		}

		if !strings.Contains(stdout.String(), "Usage:") {
			t.Fatalf("%v: stdout = %q", arguments, stdout.String())
		}
	}
}

func TestReadPassesArgumentsAfterDashToCommand(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)

	var stdout bytes.Buffer
	err := run([]string{
		"read", "--map", "SECRET=token", "secret/app", "--",
		"sh", "-c", `printf '%s|%s|%s' "$SECRET" "$1" "${BAO_TOKEN-unset}"`, "sh", "--quiet",
	}, &stdout, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "secret-value|--quiet|unset" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestReadReturnsCommandExitStatus(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)

	err := run([]string{"read", "--map", "SECRET=token", "secret/app", "--", "sh", "-c", "exit 7"}, &bytes.Buffer{}, &bytes.Buffer{})
	if exitCode(err) != 7 {
		t.Fatalf("error = %v (exit %d), want 7", err, exitCode(err))
	}
}

func TestRequesterTokenPriority(t *testing.T) {
	t.Setenv("BAO_TOKEN", "bao-token")
	t.Setenv("VAULT_TOKEN", "vault-token")
	if got, err := requesterToken(); err != nil || got != "bao-token" {
		t.Fatalf("BAO_TOKEN: got %q, %v", got, err)
	}

	t.Setenv("BAO_TOKEN", "")
	if got, err := requesterToken(); err != nil || got != "vault-token" {
		t.Fatalf("VAULT_TOKEN: got %q, %v", got, err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_CRED_NO_TOKEN_FILE", "")
	if _, err := requesterToken(); err == nil || !strings.Contains(err.Error(), "bao login") {
		t.Fatalf("missing token error = %v", err)
	}

	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := requesterToken(); err != nil || got != "file-token" {
		t.Fatalf("token file: got %q, %v", got, err)
	}

	// Inside opencode the plugin disables the file, so a command without its
	// Session Token never falls back to the human's token.
	t.Setenv("BAO_CRED_NO_TOKEN_FILE", "1")
	if got, err := requesterToken(); err == nil || got != "" {
		t.Fatalf("disabled token file: got %q, %v", got, err)
	}
}

func TestMergeEnvironmentReplacesMappedValues(t *testing.T) {
	got := mergeEnvironment(
		[]string{"PATH=/bin", "TOKEN=old", "BAO_TOKEN=requester", "VAULT_TOKEN=requester"},
		[]string{"TOKEN=new", "USER=alice"},
	)
	want := []string{"PATH=/bin", "TOKEN=new", "USER=alice"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadDeniedWithoutReasonHints(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return false })
	authorizer := newFakeAuthorizer(t)
	setupEnvironment(t, authorizer.url, openBao.URL)

	var stdout bytes.Buffer
	err := run([]string{"read", "secret/app"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "--reason") || !strings.Contains(err.Error(), "bao-cred request") {
		t.Fatalf("error = %v, want hint", err)
	}

	if exitCode(err) != exitFailure || stdout.Len() != 0 || authorizer.calls() != 0 {
		t.Fatalf("exit %d, stdout %q, authorizer calls %d", exitCode(err), stdout.String(), authorizer.calls())
	}
}

func TestReadWithReasonRequestsAccessAndRetries(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "secret/app", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "secret/app", approved)),
	}}}
	openBao := fakeOpenBao(t, func() bool { return authorizer.watchCount() > 0 })
	setupEnvironment(t, authorizer.url, openBao.URL)

	var stdout, stderr bytes.Buffer
	err := run([]string{"read", "--reason", "deploy the app", "--field", "token", "secret/app"}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "secret-value" {
		t.Fatalf("stdout = %q", stdout.String())
	}

	want := &authorizerv1.CreateGrantRequestRequest{
		Reason: "deploy the app", Items: []*authorizerv1.PermissionItemInput{{Path: "secret/app", Capabilities: []string{"read"}}},
	}
	if got := authorizer.inputs(); len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("filed %v, want %v", got, want)
	}

	if !strings.Contains(stderr.String(), "secret/app=read: approved") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestReadWithReasonReportsRejection(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "secret/app", pending))
	denied := item("item-1", "secret/app", rejected)
	denied.Reason = "use the staging path"
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(denied)}}}
	openBao := fakeOpenBao(t, func() bool { return false })
	setupEnvironment(t, authorizer.url, openBao.URL)

	var stdout bytes.Buffer
	err := run([]string{"read", "--reason", "deploy", "--quiet", "secret/app"}, &stdout, &bytes.Buffer{})
	if exitCode(err) != exitNotGranted || !strings.Contains(err.Error(), "use the staging path") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if strings.Contains(err.Error(), testToken) || stdout.Len() != 0 {
		t.Fatalf("error %q or stdout %q leaks data", err, stdout.String())
	}

	if openBao.reads() != 1 {
		t.Fatalf("OpenBao reads = %d, want no retry after rejection", openBao.reads())
	}
}

func TestReadWithReasonWithoutAuthorizerURLFails(t *testing.T) {
	openBao := fakeOpenBao(t, func() bool { return false })
	setupEnvironment(t, "", openBao.URL)

	err := run([]string{"read", "--reason", "deploy", "secret/app"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "OPENBAO_AUTHORIZER_URL") {
		t.Fatalf("error = %v", err)
	}
}

type fakeOpenBaoServer struct {
	*httptest.Server

	count *counter
}

func (s fakeOpenBaoServer) reads() int { return s.count.get() }

// fakeOpenBao serves secret/app, denying it until allowed reports true.
func fakeOpenBao(t *testing.T, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != testToken || request.URL.Path != "/v1/secret/app" {
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}

		count.add()
		response.Header().Set("Content-Type", "application/json")
		if !allowed() {
			response.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(response, `{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`)
			return
		}

		_, _ = fmt.Fprint(response, `{"data":{"token":"secret-value"}}`)
	}))
	t.Cleanup(server.Close)
	return fakeOpenBaoServer{Server: server, count: count}
}

func setupEnvironment(t *testing.T, authorizerURL, openBaoURL string) {
	t.Helper()
	t.Setenv("BAO_TOKEN", testToken)
	t.Setenv("VAULT_TOKEN", "")
	t.Setenv("BAO_ADDR", openBaoURL)
	t.Setenv("BAO_MAX_RETRIES", "0")
	t.Setenv("BAO_CACERT", "")
	t.Setenv("BAO_CACERT_BYTES", "")
	t.Setenv("BAO_CAPATH", "")
	t.Setenv("OPENBAO_AUTHORIZER_URL", authorizerURL)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}

	if coded, ok := errors.AsType[*exitError](err); ok {
		return coded.code
	}

	return exitFailure
}
