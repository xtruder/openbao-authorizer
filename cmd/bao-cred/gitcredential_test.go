package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

// fakeGitHubToken serves github/token/project-a like the GitHub plugin,
// denying it until allowed reports true.
func fakeGitHubToken(t *testing.T, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != testToken || request.URL.Path != "/v1/github/token/project-a" {
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}

		count.add()
		response.Header().Set("Content-Type", "application/json")
		if !allowed() {
			response.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(response, `{"errors":["permission denied"]}`)
			return
		}

		_, _ = fmt.Fprint(response, `{"data":{"token":"ghs_installation","expires_at":"2026-11-13T10:00:00Z","org_name":"example"}}`)
	}))
	t.Cleanup(server.Close)
	return fakeOpenBaoServer{Server: server, count: count}
}

// runGitCredential runs the helper as git does, with request on stdin.
func runGitCredential(t *testing.T, request string, arguments ...string) (string, error) {
	t.Helper()
	root := newRootCommand(runCredentials)
	root.SetArgs(append([]string{"git-credential"}, arguments...))
	root.SetIn(strings.NewReader(request))
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	err := root.ExecuteContext(t.Context())
	return stdout.String(), err
}

func TestGitCredentialAnswersWithTheToken(t *testing.T) {
	openBao := fakeGitHubToken(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)

	got, err := runGitCredential(t, "protocol=https\nhost=github.com\npath=example/app.git\n\n", "github/token/project-a", "get")
	want := "username=x-access-token\npassword=ghs_installation\npassword_expiry_utc=1794564000\n"
	if err != nil || got != want {
		t.Fatalf("get = %q, %v; want %q", got, err, want)
	}

	// Nothing is stored, so store and erase only consume the request.
	for _, operation := range []string{"store", "erase"} {
		if got, err := runGitCredential(t, "protocol=https\nhost=github.com\npassword=x\n\n", "github/token/project-a", operation); err != nil || got != "" {
			t.Fatalf("%s = %q, %v", operation, got, err)
		}
	}

	if openBao.reads() != 1 {
		t.Fatalf("OpenBao reads = %d, want 1", openBao.reads())
	}
}

func TestGitCredentialRequestsAccessWithTheURL(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "github/token/project-a", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "github/token/project-a", approved)),
	}}}
	openBao := fakeGitHubToken(t, func() bool { return authorizer.watchCount() > 0 })
	setupEnvironment(t, authorizer.url, openBao.URL)

	got, err := runGitCredential(t, "protocol=https\nhost=github.com\npath=example/app.git\n\n", "github/token/project-a", "get")
	if err != nil || !strings.Contains(got, "password=ghs_installation\n") {
		t.Fatalf("get = %q, %v", got, err)
	}

	want := &authorizerv1.CreateGrantRequestRequest{
		Reason: "git access to https://github.com/example/app.git",
		Items:  []*authorizerv1.PermissionItemInput{{Path: "github/token/project-a", Capabilities: []string{"read"}}},
	}
	if filed := authorizer.inputs(); len(filed) != 1 || !proto.Equal(filed[0], want) {
		t.Fatalf("filed %v, want %v", filed, want)
	}
}

func TestGitCredentialErrors(t *testing.T) {
	openBao := fakeGitHubToken(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)
	for _, arguments := range [][]string{{}, {"github/token/project-a"}, {"github/token/project-a", "list"}} {
		if _, err := runGitCredential(t, "", arguments...); exitCode(err) != exitUsage {
			t.Errorf("%v: error = %v", arguments, err)
		}
	}

	if _, err := runGitCredential(t, "\n", "--field", "missing", "github/token/project-a", "get"); err == nil {
		t.Fatal("answered without the field")
	}
}
