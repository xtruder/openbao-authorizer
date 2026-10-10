package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

const testToken = "session-token-value"

func TestParseOutputAndExecModes(t *testing.T) {
	output, err := parseOptions([]string{"-field", "database.username", "-reason", " deploy ", "secret/path"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if output.path != "secret/path" || output.field != "database.username" || output.reason != "deploy" {
		t.Fatalf("unexpected options: %#v", output)
	}

	execOptions, err := parseOptions([]string{"-map", "TOKEN=token", "secret/path", "--", "tool", "arg"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(execOptions.command, []string{"tool", "arg"}) || execOptions.mappings[0].Name != "TOKEN" {
		t.Fatalf("unexpected options: %#v", execOptions)
	}
}

func TestParseRejectsMixedDeliveryModes(t *testing.T) {
	_, err := parseOptions([]string{"-field", "token", "-map", "TOKEN=token", "secret/path", "--", "tool"}, &bytes.Buffer{})
	if exitCode(err) != exitUsage {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestParseRejectsDuplicateMappings(t *testing.T) {
	_, err := parseOptions([]string{"-format", "dotenv", "-map", "TOKEN=one", "-map", "TOKEN=two", "secret/path"}, &bytes.Buffer{})
	if exitCode(err) != exitUsage {
		t.Fatalf("error = %v, want usage error", err)
	}
}

func TestSessionTokenPriority(t *testing.T) {
	t.Setenv("BAO_TOKEN", "bao-token")
	t.Setenv("VAULT_TOKEN", "vault-token")
	if got, err := sessionToken(); err != nil || got != "bao-token" {
		t.Fatalf("BAO_TOKEN: got %q, %v", got, err)
	}

	t.Setenv("BAO_TOKEN", "")
	if got, err := sessionToken(); err != nil || got != "vault-token" {
		t.Fatalf("VAULT_TOKEN: got %q, %v", got, err)
	}

	t.Setenv("VAULT_TOKEN", "")
	if _, err := sessionToken(); err == nil || !strings.Contains(err.Error(), "BAO_TOKEN") {
		t.Fatalf("missing token error = %v", err)
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
	err := run([]string{"secret/app"}, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "-reason") || !strings.Contains(err.Error(), "bao-cred request") {
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
	err := run([]string{"-reason", "deploy the app", "-field", "token", "secret/app"}, &stdout, &stderr)
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
	err := run([]string{"-reason", "deploy", "-quiet", "secret/app"}, &stdout, &bytes.Buffer{})
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

	err := run([]string{"-reason", "deploy", "secret/app"}, &bytes.Buffer{}, &bytes.Buffer{})
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
