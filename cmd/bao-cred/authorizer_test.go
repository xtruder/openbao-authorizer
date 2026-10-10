package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
)

const (
	pending        = authorizerv1.ItemState_ITEM_STATE_PENDING
	approved       = authorizerv1.ItemState_ITEM_STATE_APPROVED
	alreadyGranted = authorizerv1.ItemState_ITEM_STATE_ALREADY_GRANTED
	rejected       = authorizerv1.ItemState_ITEM_STATE_REJECTED
	refused        = authorizerv1.ItemState_ITEM_STATE_REFUSED
)

var testExpiry = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func TestRequestWatchesUntilDecided(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending), item("item-2", "kv/data/b", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "kv/data/a", pending), item("item-2", "kv/data/b", pending)),
		snapshot(item("item-1", "kv/data/a", approved), item("item-2", "kv/data/b", pending)),
		snapshot(item("item-1", "kv/data/a", approved), item("item-2", "kv/data/b", approved)),
	}}}
	setupEnvironment(t, authorizer.url, "")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"request", "--reason", "migrate schema", "--item", "kv/data/a=read", "--item", "kv/data/b=read, update", "--ttl", "1h",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}

	want := &authorizerv1.CreateGrantRequestRequest{Reason: "migrate schema", Items: []*authorizerv1.PermissionItemInput{
		{Path: "kv/data/a", Capabilities: []string{"read"}, Ttl: durationpb.New(time.Hour)},
		{Path: "kv/data/b", Capabilities: []string{"read", "update"}, Ttl: durationpb.New(time.Hour)},
	}}
	if got := authorizer.inputs(); len(got) != 1 || !proto.Equal(got[0], want) {
		t.Fatalf("filed %v, want %v", got, want)
	}

	if authorizer.watchCount() != 1 {
		t.Fatalf("watches = %d, want 1", authorizer.watchCount())
	}

	wantJSON := `{"id":"req-1","items":[` +
		`{"id":"item-1","path":"kv/data/a","capabilities":["read"],"ttl":"1h0m0s","state":"approved","expires_at":"2026-10-09T12:00:00Z"},` +
		`{"id":"item-2","path":"kv/data/b","capabilities":["read"],"ttl":"1h0m0s","state":"approved","expires_at":"2026-10-09T12:00:00Z"}]}`
	if got := compactJSON(t, stdout.Bytes()); got != wantJSON {
		t.Fatalf("stdout = %s\nwant     %s", got, wantJSON)
	}

	for _, line := range []string{"filed Grant Request req-1", "kv/data/a=read: approved", "kv/data/b=read: approved"} {
		if !strings.Contains(stderr.String(), line) {
			t.Fatalf("stderr %q lacks %q", stderr.String(), line)
		}
	}
}

func TestRequestReportsPartialOutcome(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", alreadyGranted), item("item-2", "kv/data/b", pending))
	denied := item("item-2", "kv/data/b", rejected)
	denied.Reason = "use the staging path"
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "kv/data/a", alreadyGranted), denied),
	}}}
	setupEnvironment(t, authorizer.url, "")

	var stdout, stderr bytes.Buffer
	err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read", "--item", "kv/data/b=read"}, &stdout, &stderr)
	if exitCode(err) != exitNotGranted || !strings.Contains(err.Error(), "kv/data/b=read: rejected (use the staging path)") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	for _, state := range []string{`"state": "already_granted"`, `"state": "rejected"`, `"reason": "use the staging path"`} {
		if !strings.Contains(stdout.String(), state) {
			t.Fatalf("stdout %q lacks %q", stdout.String(), state)
		}
	}
}

func TestRequestSkipsWatchWhenNothingPending(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", alreadyGranted))
	setupEnvironment(t, authorizer.url, "")

	var stderr bytes.Buffer
	err := run([]string{"request", "--quiet", "--reason", "r", "--item", "kv/data/a=read"}, &bytes.Buffer{}, &stderr)
	if err != nil {
		t.Fatal(err)
	}

	if authorizer.watchCount() != 0 || stderr.Len() != 0 {
		t.Fatalf("watches %d, -quiet wrote %q", authorizer.watchCount(), stderr.String())
	}
}

func TestRequestReconnectsAfterStreamDrop(t *testing.T) {
	fastRetries(t)
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	authorizer.watches = []watchScript{
		{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(item("item-1", "kv/data/a", pending))}, drop: true},
		{err: unavailableError()},
		{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(item("item-1", "kv/data/a", pending))}},
		{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(item("item-1", "kv/data/a", approved))}},
	}
	setupEnvironment(t, authorizer.url, "")

	var stderr bytes.Buffer
	err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read"}, &bytes.Buffer{}, &stderr)
	if err != nil {
		t.Fatalf("%v; stderr %q", err, stderr.String())
	}

	if authorizer.watchCount() != 4 {
		t.Fatalf("watches = %d, want 4", authorizer.watchCount())
	}

	if strings.Count(stderr.String(), "reconnecting") != 3 || !strings.Contains(stderr.String(), "cannot reach OpenBao") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRequestReconnectsIdleStream(t *testing.T) {
	fastRetries(t)
	streamIdleTimeout = 50 * time.Millisecond
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	authorizer.watches = []watchScript{
		{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(item("item-1", "kv/data/a", pending))}, hold: true},
		{messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(item("item-1", "kv/data/a", approved))}},
	}
	setupEnvironment(t, authorizer.url, "")

	var stderr bytes.Buffer
	if err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read"}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatal(err)
	}

	if authorizer.watchCount() != 2 || !strings.Contains(stderr.String(), "idle") {
		t.Fatalf("watches %d, stderr %q", authorizer.watchCount(), stderr.String())
	}
}

func TestRequestIgnoresHeartbeats(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		heartbeat(),
		snapshot(item("item-1", "kv/data/a", pending)),
		heartbeat(),
		heartbeat(),
		snapshot(item("item-1", "kv/data/a", approved)),
	}}}
	setupEnvironment(t, authorizer.url, "")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	if authorizer.watchCount() != 1 || !strings.Contains(stdout.String(), `"state": "approved"`) {
		t.Fatalf("watches %d, stdout %q", authorizer.watchCount(), stdout.String())
	}

	if want := "filed Grant Request req-1\nkv/data/a=read: approved\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

func TestRequestReportsPendingAtTimeout(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending), item("item-2", "sys/mounts", refused))
	authorizer.watches = []watchScript{{
		messages: []*authorizerv1.WatchGrantRequestResponse{snapshot(authorizer.created.GetItems()...), heartbeat()},
		hold:     true,
	}}
	setupEnvironment(t, authorizer.url, "")

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"request", "--timeout", "200ms", "--reason", "r", "--item", "kv/data/a=read", "--item", "sys/mounts=read",
	}, &stdout, &stderr)
	if exitCode(err) != exitPending || !strings.Contains(err.Error(), "still pending after 200ms; resume with: bao-cred request --wait req-1") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if !strings.Contains(stdout.String(), `"state": "pending"`) || !strings.Contains(stdout.String(), `"state": "refused"`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRequestNoWaitReturnsImmediately(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	setupEnvironment(t, authorizer.url, "")

	var stdout bytes.Buffer
	err := run([]string{"request", "--no-wait", "--reason", "r", "--item", "kv/data/a=read"}, &stdout, &bytes.Buffer{})
	if exitCode(err) != exitPending || !strings.Contains(err.Error(), "wait with: bao-cred request --wait req-1") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if authorizer.watchCount() != 0 || !strings.Contains(stdout.String(), `"id": "req-1"`) {
		t.Fatalf("watches %d, stdout %q", authorizer.watchCount(), stdout.String())
	}
}

func TestRequestResumesWaiting(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.current = testRequest(item("item-1", "kv/data/a", pending))
	authorizer.watches = []watchScript{{messages: []*authorizerv1.WatchGrantRequestResponse{
		snapshot(item("item-1", "kv/data/a", pending)),
		snapshot(item("item-1", "kv/data/a", approved)),
	}}}
	setupEnvironment(t, authorizer.url, "")

	var stderr bytes.Buffer
	if err := run([]string{"request", "--wait", "req-1"}, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatal(err)
	}

	if len(authorizer.inputs()) != 0 || authorizer.watchCount() != 1 {
		t.Fatalf("filed %d, watches %d", len(authorizer.inputs()), authorizer.watchCount())
	}

	if !strings.Contains(stderr.String(), "waiting on Grant Request req-1") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRequestWaitUnknownRequest(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	setupEnvironment(t, authorizer.url, "")

	err := run([]string{"request", "--wait", "req-2"}, &bytes.Buffer{}, &bytes.Buffer{})
	if exitCode(err) != exitFailure || err.Error() != "read Grant Request req-2: not found for this Requester" {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}
}

func TestRequestStopsOnPermanentWatchError(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	authorizer.watches = []watchScript{{err: detailedError(connect.CodeUnauthenticated, "INVALID_TOKEN", "token revoked")}}
	setupEnvironment(t, authorizer.url, "")

	err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read"}, &bytes.Buffer{}, &bytes.Buffer{})
	if exitCode(err) != exitFailure || !strings.Contains(err.Error(), "rejected the token") ||
		!strings.Contains(err.Error(), "resume with: bao-cred request --wait req-1") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if authorizer.watchCount() != 1 {
		t.Fatalf("watches = %d, want no retry", authorizer.watchCount())
	}
}

func TestRequestAuthorizerErrorsOmitToken(t *testing.T) {
	for token, want := range map[string]string{
		"not-a-requester-token": "file Grant Request: this token is not allowed to request grants (no matching requester rule)",
		"expired-token":         "file Grant Request: the authorizer rejected the token; it may be expired or revoked",
	} {
		authorizer := newFakeAuthorizer(t)
		setupEnvironment(t, authorizer.url, "")
		t.Setenv("BAO_TOKEN", token)

		var stdout, stderr bytes.Buffer
		err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read"}, &stdout, &stderr)
		if exitCode(err) != exitFailure || err.Error() != want {
			t.Fatalf("%s: error = %v (exit %d)", token, err, exitCode(err))
		}

		if strings.Contains(err.Error()+stdout.String()+stderr.String(), token) {
			t.Fatalf("output leaks token: %v %q %q", err, stdout.String(), stderr.String())
		}
	}
}

func TestRequestReportsInvalidRequest(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.createErr = detailedError(connect.CodeInvalidArgument, "INVALID_REQUEST", "ttl exceeds the rule's max_ttl")
	setupEnvironment(t, authorizer.url, "")

	err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read", "--ttl", "100h"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || err.Error() != "file Grant Request: authorizer returned invalid_argument: ttl exceeds the rule's max_ttl" {
		t.Fatalf("error = %v", err)
	}
}

func TestRequestUsageErrors(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	setupEnvironment(t, authorizer.url, "")
	for _, arguments := range [][]string{
		{"request", "--item", "kv/data/a=read"},
		{"request", "--reason", "r"},
		{"request", "--reason", "r", "--item", "kv/data/a"},
		{"request", "--reason", "r", "--item", "kv/data/a=read,"},
		{"request", "--reason", "r", "--item", "=read"},
		{"request", "--wait", "req-1", "--item", "kv/data/a=read"},
		{"request", "--reason", "r", "--item", "kv/data/a=read", "extra"},
		{"request", "--unknown"},
		{"grants", "extra"},
		{"grantable", "extra"},
	} {
		err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{})
		if exitCode(err) != exitUsage {
			t.Fatalf("%v: error = %v (exit %d)", arguments, err, exitCode(err))
		}
	}

	if authorizer.calls() != 0 {
		t.Fatalf("usage errors reached the authorizer %d times", authorizer.calls())
	}
}

func TestParseItemKeepsEqualsInPath(t *testing.T) {
	got, err := parseItem("kv/data/a=b=read,list", 0)
	if err != nil {
		t.Fatal(err)
	}

	want := &authorizerv1.PermissionItemInput{Path: "kv/data/a=b", Capabilities: []string{"read", "list"}}
	if !proto.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestGrantsPrintsJSON(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.grants = []*authorizerv1.Grant{{
		Id: "grant-1", ItemId: "item-1", Path: "kv/data/a", Capabilities: []string{"read"},
		CreatedAt: timestamppb.New(testExpiry.Add(-time.Hour)), ExpiresAt: timestamppb.New(testExpiry),
		ApprovedBy: "approver",
	}}
	setupEnvironment(t, authorizer.url, "")

	var stdout bytes.Buffer
	if err := run([]string{"grants"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	want := `[{"id":"grant-1","item_id":"item-1","path":"kv/data/a","capabilities":["read"],` +
		`"created_at":"2026-10-09T11:00:00Z","expires_at":"2026-10-09T12:00:00Z"}]`
	if got := compactJSON(t, stdout.Bytes()); got != want {
		t.Fatalf("stdout = %s\nwant     %s", got, want)
	}
}

func TestGrantsPrintsEmptyArray(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	setupEnvironment(t, authorizer.url, "")

	var stdout bytes.Buffer
	if err := run([]string{"grants"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	if stdout.String() != "[]\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestGrantablePrintsJSON(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	authorizer.grantables = []*authorizerv1.Grantable{
		{
			Name: "github-token", Path: "github/token/project-*", Capabilities: []string{"read"}, MaxTtl: durationpb.New(8 * time.Hour),
			Description: "One project's GitHub token", Paths: []string{"github/token/project-web"},
		},
		{Name: "kv", Path: "kv/data/app/*", Capabilities: []string{"read", "list"}, MaxTtl: durationpb.New(time.Hour), DiscoverError: "permission denied listing kv/metadata/app"},
	}
	setupEnvironment(t, authorizer.url, "")

	var stdout bytes.Buffer
	if err := run([]string{"grantable"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	want := `[{"name":"github-token","path":"github/token/project-*","capabilities":["read"],"max_ttl":"8h0m0s",` +
		`"description":"One project's GitHub token","paths":["github/token/project-web"]},` +
		`{"name":"kv","path":"kv/data/app/*","capabilities":["read","list"],"max_ttl":"1h0m0s",` +
		`"discover_error":"permission denied listing kv/metadata/app"}]`
	if got := compactJSON(t, stdout.Bytes()); got != want {
		t.Fatalf("stdout = %s\nwant     %s", got, want)
	}
}

func TestGrantablePrintsEmptyArrayAndReportsErrors(t *testing.T) {
	authorizer := newFakeAuthorizer(t)
	setupEnvironment(t, authorizer.url, "")

	var stdout bytes.Buffer
	if err := run([]string{"grantable"}, &stdout, &bytes.Buffer{}); err != nil || stdout.String() != "[]\n" {
		t.Fatalf("stdout = %q, error = %v", stdout.String(), err)
	}

	t.Setenv("BAO_TOKEN", "not-a-requester-token")
	err := run([]string{"grantable"}, &bytes.Buffer{}, &bytes.Buffer{})
	if exitCode(err) != exitFailure || err.Error() != "list Grantable Rules: this token is not allowed to request grants (no matching requester rule)" {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	t.Setenv("BAO_AUTHORIZER_ADDR", "")
	t.Setenv("BAO_TOKEN", testToken)
	if err := run([]string{"grantable"}, &bytes.Buffer{}, &bytes.Buffer{}); exitCode(err) != exitFailure || !strings.Contains(err.Error(), "BAO_AUTHORIZER_ADDR") {
		t.Fatalf("missing authorizer error = %v", err)
	}
}

func TestAuthorizerTrustsBaoCACert(t *testing.T) {
	authorizer := newFakeAuthorizerServer(t, httptest.NewTLSServer)
	setupEnvironment(t, authorizer.url, "")
	if err := run([]string{"grants"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("untrusted authorizer certificate was accepted")
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authorizer.server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_CACERT", caFile)
	if err := run([]string{"grants"}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizerURLRequiresHTTPSOffLoopback(t *testing.T) {
	for _, raw := range []string{"https://authorizer.example.com", "http://127.0.0.1:8080", "http://127.8.0.1", "http://[::1]:8080", "http://localhost:8080", "http://LOCALHOST"} {
		if _, err := newAuthorizerClient(raw, "token"); err != nil {
			t.Errorf("%s: unexpected error %v", raw, err)
		}
	}

	for _, raw := range []string{"http://authorizer.example.com", "http://10.0.0.1", "http://localhost.example.com", "http://[::2]", "ftp://127.0.0.1"} {
		if _, err := newAuthorizerClient(raw, "token"); err == nil {
			t.Errorf("%s: expected an error", raw)
		}
	}
}

func TestAuthorizerClientRefusesRedirectToPlainHTTP(t *testing.T) {
	client, err := newAuthorizerClient("https://authorizer.example.com", "token")
	if err != nil {
		t.Fatal(err)
	}

	insecure, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://authorizer.example.com/api", nil)
	if err := client.http.CheckRedirect(insecure, []*http.Request{{}}); err == nil {
		t.Fatal("expected redirect to plain HTTP to be refused")
	}

	secure, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://authorizer.example.com/api", nil)
	if err := client.http.CheckRedirect(secure, []*http.Request{{}}); err != nil {
		t.Fatalf("secure redirect: %v", err)
	}
}

func TestRequestStopsOnInsecureRedirectDuringWatch(t *testing.T) {
	fastRetries(t)
	var redirects counter
	authorizer := newFakeAuthorizerServer(t, func(handler http.Handler) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if strings.HasSuffix(request.URL.Path, "/WatchGrantRequest") {
				redirects.add()
				http.Redirect(response, request, "http://authorizer.example.com"+request.URL.Path, http.StatusTemporaryRedirect)
				return
			}

			handler.ServeHTTP(response, request)
		}))
	})
	authorizer.created = testRequest(item("item-1", "kv/data/a", pending))
	setupEnvironment(t, authorizer.url, "")
	trustServer(t, authorizer.server)

	err := run([]string{"request", "--reason", "r", "--item", "kv/data/a=read", "--timeout", "5s"}, &bytes.Buffer{}, &bytes.Buffer{})
	if exitCode(err) != exitFailure || !strings.Contains(err.Error(), "insecure authorizer URL") {
		t.Fatalf("error = %v (exit %d)", err, exitCode(err))
	}

	if redirects.get() != 1 {
		t.Fatalf("watch attempts = %d, want no retry", redirects.get())
	}
}

func TestUntrustedCertificateIsPermanent(t *testing.T) {
	authorizer := newFakeAuthorizerServer(t, httptest.NewTLSServer)
	authorizer.watches = []watchScript{{hold: true}}
	setupEnvironment(t, authorizer.url, "")
	client, err := newAuthorizerClient(authorizer.url, testToken)
	if err != nil {
		t.Fatal(err)
	}

	err = client.watchGrantRequest(t.Context(), "req-1", func(grantRequest) {}, func() {})
	if err == nil || transientAuthorizerError(err) {
		t.Fatalf("certificate failure = %v, want a permanent error", err)
	}

	if !transientAuthorizerError(newAuthorizerError(connect.NewError(connect.CodeUnavailable, errors.New("connection refused")))) {
		t.Fatal("plain connection failures must stay transient")
	}
}

func trustServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BAO_CACERT", caFile)
}

type counter struct {
	mu    sync.Mutex
	value int
}

func (c *counter) add() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.value++
}

func (c *counter) get() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.value
}

// watchScript is what one WatchGrantRequest call sends. After its messages
// the stream ends normally, unless drop aborts the connection, hold keeps it
// open until the client leaves, or err ends it with that error.
type watchScript struct {
	messages []*authorizerv1.WatchGrantRequestResponse
	drop     bool
	hold     bool
	err      error
}

// fakeAuthorizer implements GrantService for req-1. Watch calls follow
// watches in order, repeating the last script.
type fakeAuthorizer struct {
	authorizerv1connect.UnimplementedGrantServiceHandler

	url        string
	server     *httptest.Server
	created    *authorizerv1.GrantRequest
	createErr  error
	current    *authorizerv1.GrantRequest
	watches    []watchScript
	grants     []*authorizerv1.Grant
	grantables []*authorizerv1.Grantable

	mu      sync.Mutex
	filed   []*authorizerv1.CreateGrantRequestRequest
	watched int
	total   int
}

func newFakeAuthorizer(t *testing.T) *fakeAuthorizer {
	t.Helper()
	return newFakeAuthorizerServer(t, httptest.NewServer)
}

func newFakeAuthorizerServer(t *testing.T, start func(http.Handler) *httptest.Server) *fakeAuthorizer {
	t.Helper()
	fake := &fakeAuthorizer{}
	path, handler := authorizerv1connect.NewGrantServiceHandler(fake, connect.WithInterceptors(fakeAuthentication{}))
	mux := http.NewServeMux()
	mux.Handle("/api"+path, http.StripPrefix("/api", handler))
	fake.server = start(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		fake.mu.Lock()
		fake.total++
		fake.mu.Unlock()
		mux.ServeHTTP(response, request)
	}))
	t.Cleanup(fake.server.Close)
	fake.url = fake.server.URL
	return fake
}

func (f *fakeAuthorizer) CreateGrantRequest(
	_ context.Context, request *connect.Request[authorizerv1.CreateGrantRequestRequest],
) (*connect.Response[authorizerv1.CreateGrantRequestResponse], error) {
	f.mu.Lock()
	f.filed = append(f.filed, request.Msg)
	f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}

	return connect.NewResponse(&authorizerv1.CreateGrantRequestResponse{GrantRequest: f.created}), nil
}

func (f *fakeAuthorizer) GetGrantRequest(
	_ context.Context, request *connect.Request[authorizerv1.GetGrantRequestRequest],
) (*connect.Response[authorizerv1.GetGrantRequestResponse], error) {
	if request.Msg.GetId() != "req-1" || f.current == nil {
		return nil, detailedError(connect.CodeNotFound, "NOT_FOUND", "grant request not found")
	}

	return connect.NewResponse(&authorizerv1.GetGrantRequestResponse{GrantRequest: f.current}), nil
}

func (f *fakeAuthorizer) WatchGrantRequest(
	ctx context.Context, request *connect.Request[authorizerv1.WatchGrantRequestRequest],
	stream *connect.ServerStream[authorizerv1.WatchGrantRequestResponse],
) error {
	if request.Msg.GetId() != "req-1" {
		return detailedError(connect.CodeNotFound, "NOT_FOUND", "grant request not found")
	}

	f.mu.Lock()
	script := f.watches[min(f.watched, len(f.watches)-1)]
	f.watched++
	f.mu.Unlock()
	for _, message := range script.messages {
		if err := stream.Send(message); err != nil {
			return err
		}
	}

	switch {
	case script.drop:
		panic(http.ErrAbortHandler)
	case script.hold:
		<-ctx.Done()
		return ctx.Err()
	default:
		return script.err
	}
}

func (f *fakeAuthorizer) ListMyGrants(
	context.Context, *connect.Request[authorizerv1.ListMyGrantsRequest],
) (*connect.Response[authorizerv1.ListMyGrantsResponse], error) {
	return connect.NewResponse(&authorizerv1.ListMyGrantsResponse{Grants: f.grants}), nil
}

func (f *fakeAuthorizer) ListGrantables(
	context.Context, *connect.Request[authorizerv1.ListGrantablesRequest],
) (*connect.Response[authorizerv1.ListGrantablesResponse], error) {
	return connect.NewResponse(&authorizerv1.ListGrantablesResponse{Grantables: f.grantables}), nil
}

func (f *fakeAuthorizer) inputs() []*authorizerv1.CreateGrantRequestRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*authorizerv1.CreateGrantRequestRequest(nil), f.filed...)
}

func (f *fakeAuthorizer) watchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watched
}

func (f *fakeAuthorizer) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.total
}

// fakeAuthentication accepts only testToken, answering like the authorizer
// does for revoked tokens and for tokens matching no Requester Rule.
type fakeAuthentication struct{}

func (fakeAuthentication) check(header http.Header) error {
	switch header.Get("Authorization") {
	case "Bearer " + testToken:
		return nil
	case "Bearer expired-token":
		return detailedError(connect.CodeUnauthenticated, "INVALID_TOKEN", "invalid token")
	default:
		return detailedError(connect.CodePermissionDenied, "NOT_REQUESTER", "no matching requester rule")
	}
}

func (a fakeAuthentication) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		if err := a.check(request.Header()); err != nil {
			return nil, err
		}

		return next(ctx, request)
	}
}

func (fakeAuthentication) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (a fakeAuthentication) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if err := a.check(conn.RequestHeader()); err != nil {
			return err
		}

		return next(ctx, conn)
	}
}

func detailedError(code connect.Code, reason, message string) error {
	err := connect.NewError(code, errors.New(message))
	if detail, detailErr := connect.NewErrorDetail(&authorizerv1.ErrorDetail{Reason: reason}); detailErr == nil {
		err.AddDetail(detail)
	}

	return err
}

func unavailableError() error {
	return detailedError(connect.CodeUnavailable, "OPENBAO_UNAVAILABLE", "OpenBao is unavailable")
}

func fastRetries(t *testing.T) {
	t.Helper()
	retryDelay, maxRetryDelay = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() {
		retryDelay, maxRetryDelay, streamIdleTimeout = time.Second, 30*time.Second, time.Minute
	})
}

func compactJSON(t *testing.T, value []byte) string {
	t.Helper()
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, value); err != nil {
		t.Fatalf("%q: %v", value, err)
	}

	return compacted.String()
}

func testRequest(items ...*authorizerv1.PermissionItem) *authorizerv1.GrantRequest {
	return &authorizerv1.GrantRequest{Id: "req-1", Reason: "r", CreatedAt: timestamppb.New(testExpiry), Items: items}
}

func snapshot(items ...*authorizerv1.PermissionItem) *authorizerv1.WatchGrantRequestResponse {
	return &authorizerv1.WatchGrantRequestResponse{
		Event: &authorizerv1.WatchGrantRequestResponse_GrantRequest{GrantRequest: testRequest(items...)},
	}
}

func heartbeat() *authorizerv1.WatchGrantRequestResponse {
	return &authorizerv1.WatchGrantRequestResponse{
		Event: &authorizerv1.WatchGrantRequestResponse_Heartbeat{Heartbeat: &authorizerv1.Heartbeat{}},
	}
}

func item(id, path string, state authorizerv1.ItemState) *authorizerv1.PermissionItem {
	return &authorizerv1.PermissionItem{
		Id: id, Path: path, Capabilities: []string{"read"}, Ttl: durationpb.New(time.Hour), State: state,
		ExpiresAt: timestamppb.New(testExpiry),
	}
}
