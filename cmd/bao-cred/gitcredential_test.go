package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
)

// fakeGitHubToken serves github/token/project-a like the GitHub plugin,
// denying it until allowed reports true.
func fakeGitHubToken(t *testing.T, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	return fakeGitHubTokenAt(t, "github/token/project-a", allowed)
}

// fakeGitHubTokenAt serves path like the GitHub plugin.
func fakeGitHubTokenAt(t *testing.T, path string, allowed func() bool) fakeOpenBaoServer {
	t.Helper()
	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("X-Vault-Token") != testToken || request.URL.Path != "/v1/"+path {
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

func TestExpandGitCredentialPath(t *testing.T) {
	for urlPath, want := range map[string]string{
		"xtruder/openbao-authorizer.git": "github/token/project-xtruder-openbao-authorizer",
		"/Xtruder/HomeLab":               "github/token/project-xtruder-homelab",
		"org/repo.git/info/refs":         "github/token/project-org-repo",
		"":                               "",
		"org":                            "",
		"org/..":                         "",
		"org/a%2Fb":                      "",
	} {
		got, err := expandGitCredentialPath("github/token/project-{owner}-{repo}", urlPath)
		if want == "" {
			if err == nil {
				t.Errorf("%q: path %q, want an error", urlPath, got)
			}

			continue
		}

		if err != nil || got != want {
			t.Errorf("%q: path %q, %v; want %q", urlPath, got, err, want)
		}
	}

	if _, err := expandGitCredentialPath("github/token/project-{owner}-{repo}", ""); err == nil || !strings.Contains(err.Error(), "useHttpPath") {
		t.Fatalf("missing path: %v", err)
	}
}

func TestGitCredentialTemplateServesEachRepository(t *testing.T) {
	openBao := fakeGitHubTokenAt(t, "github/token/project-xtruder-homelab", func() bool { return true })
	setupEnvironment(t, "", openBao.URL)

	got, err := runGitCredential(t, "protocol=https\nhost=github.com\npath=xtruder/homelab.git\n\n", "github/token/project-{owner}-{repo}", "get")
	if err != nil || !strings.Contains(got, "password=ghs_installation\n") {
		t.Fatalf("get = %q, %v", got, err)
	}
}

func TestGitCredentialTemplateRefusesRepositoriesWithoutACredential(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{{
		Name: "github-token", Path: "github/token/project-*",
		Paths: []string{"github/token/project-a", "github/token/project-xtruder-homelab"},
	}}
	openBao := fakeGitHubTokenAt(t, "github/token/project-other-repo", func() bool { return false })
	setupEnvironment(t, authorizer.url, openBao.URL)

	_, err := runGitCredential(t, "protocol=https\nhost=github.com\npath=other/repo.git\n\n", "github/token/project-{owner}-{repo}", "get")
	if err == nil || !strings.Contains(err.Error(), "isn't in the catalog") || !strings.Contains(err.Error(), "project-xtruder-homelab") {
		t.Fatalf("error = %v", err)
	}

	if len(authorizer.inputs()) != 0 {
		t.Fatal("filed a request for a repository without a credential")
	}
}

func TestGitCredentialCachesUntilShortlyBeforeExpiry(t *testing.T) {
	openBao := fakeGitHubToken(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)
	request := "protocol=https\nhost=github.com\npath=example/app.git\n\n"

	for range 3 {
		if got, err := runGitCredential(t, request, "github/token/project-a", "get"); err != nil || !strings.Contains(got, "password=ghs_installation\n") {
			t.Fatalf("get = %q, %v", got, err)
		}
	}

	if openBao.reads() != 1 {
		t.Fatalf("OpenBao reads = %d, want 1 and then the cache", openBao.reads())
	}

	// erase, after the server rejected it, drops the cached copy.
	if _, err := runGitCredential(t, request, "github/token/project-a", "erase"); err != nil {
		t.Fatal(err)
	}

	if _, err := runGitCredential(t, request, "github/token/project-a", "get"); err != nil || openBao.reads() != 2 {
		t.Fatalf("get after erase: reads %d, %v", openBao.reads(), err)
	}

	// A copy that expires within the renewal margin is replaced.
	cacheFile, err := gitCredentialCacheFile("", "github/token/project-a", "token")
	if err != nil {
		t.Fatal(err)
	}

	if err := writeCachedGitCredential(cacheFile, cachedGitCredential{Password: "old", ExpiresAt: time.Now().Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}

	if got, err := runGitCredential(t, request, "github/token/project-a", "get"); err != nil || strings.Contains(got, "password=old") || openBao.reads() != 3 {
		t.Fatalf("get with a stale cache = %q, reads %d, %v", got, openBao.reads(), err)
	}

	// --no-cache reads OpenBao every time.
	for range 2 {
		if _, err := runGitCredential(t, request, "--no-cache", "github/token/project-a", "get"); err != nil {
			t.Fatal(err)
		}
	}

	if openBao.reads() != 5 {
		t.Fatalf("OpenBao reads with --no-cache = %d, want 5", openBao.reads())
	}
}

func TestGitCredentialCacheIsPerRequester(t *testing.T) {
	openBao := fakeGitHubToken(t, func() bool { return true })
	setupEnvironment(t, "", openBao.URL)
	request := "protocol=https\nhost=github.com\npath=example/app.git\n\n"

	// BAO_TOKEN names the Requester here: another token gets its own copy.
	if _, err := runGitCredential(t, request, "github/token/project-a", "get"); err != nil {
		t.Fatal(err)
	}

	first, _ := gitCredentialCacheFile("", "github/token/project-a", "token")
	t.Setenv("BAO_TOKEN", "another-requester")
	second, _ := gitCredentialCacheFile("", "github/token/project-a", "token")
	if first == second || filepath.Dir(first) == filepath.Dir(second) {
		t.Fatalf("both Requesters cache at %s", first)
	}

	if info, err := os.Stat(first); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode %v, %v", info.Mode(), err)
	}
}

func TestGitCredentialDoesNotCacheWithoutAnExpiry(t *testing.T) {
	count := &counter{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		count.add()
		response.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(response, `{"data":{"token":"no-expiry"}}`)
	}))
	t.Cleanup(server.Close)
	setupEnvironment(t, "", server.URL)

	for range 2 {
		got, err := runGitCredential(t, "protocol=https\nhost=git.example.com\n\n", "kv/app", "get")
		if err != nil || got != "username=x-access-token\npassword=no-expiry\n" {
			t.Fatalf("get = %q, %v", got, err)
		}
	}

	if count.get() != 2 {
		t.Fatalf("reads = %d, want 2: nothing to cache without an expiry", count.get())
	}
}
