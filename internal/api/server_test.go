package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
	"github.com/xtruder/openbao-authorizer/internal/config"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/openbao/openbaotest"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

var approverIdentity = openbao.Identity{EntityID: "bob-id", DisplayName: "Bob", IdentityPolicies: []string{"approver"}, TTL: 300}

const testHeartbeat = 20 * time.Millisecond

type testServer struct {
	t        *testing.T
	url      string
	http     *http.Client
	bao      *openbaotest.Fake
	database *store.DB
	events   *EventBus
	approver authorizerv1connect.ApproverServiceClient
	grant    authorizerv1connect.GrantServiceClient
}

type testConfig struct {
	options func(*Options)
	server  func(*http.Server)
}

func newTestServer(t *testing.T, configs ...testConfig) *testServer {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if closeErr := database.Close(); closeErr != nil {
			t.Error(closeErr)
		}
	})
	bao := openbaotest.New()
	bao.SetIdentity("human-token", approverIdentity)
	bao.AddSession("session-a", "entity-a", map[string]string{"session_id": "aaa", "title": "Fix CI", "directory": "/src/app"})
	bao.AddSession("session-b", "entity-b", map[string]string{"session_id": "bbb"})
	events := NewEventBus()
	service := grants.New(bao, database, &Notifier{Events: events}, grants.Config{
		Policy: grants.Policy{DefaultTTL: 72 * time.Hour, Rules: []grants.Rule{
			{Name: "kv", Path: "kv/data/*", Capabilities: []string{"read"}, MaxTTL: 8 * time.Hour, Description: "App secrets", Discover: "kv/metadata"},
		}},
		PendingTTL: time.Hour,
		Requesters: []grants.RequesterRule{{Name: "opencode", TokenRole: "opencode-session"}},
	})
	options := Options{
		OpenBao: bao, Store: database, Grants: service, Events: events,
		ApproverPolicy: "approver", InsecureCookies: true, HeartbeatInterval: testHeartbeat,
	}
	for _, setup := range configs {
		if setup.options != nil {
			setup.options(&options)
		}
	}

	// Mounted like the application mux does, so URLs carry the /api prefix.
	mux := http.NewServeMux()
	mux.Handle("/api/", New(options))
	server := httptest.NewUnstartedServer(mux)
	for _, setup := range configs {
		if setup.server != nil {
			setup.server(server.Config)
		}
	}

	server.Start()
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Jar = jar
	baseURL := server.URL + "/api"
	return &testServer{
		t: t, url: server.URL, http: client, bao: bao, database: database, events: events,
		// The PWA speaks Connect JSON; bao-cred the binary default.
		approver: authorizerv1connect.NewApproverServiceClient(client, baseURL, connect.WithProtoJSON()),
		grant:    authorizerv1connect.NewGrantServiceClient(client, baseURL),
	}
}

func (s *testServer) login() {
	s.t.Helper()
	_, err := s.approver.CreateSession(s.t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"}))
	if err != nil {
		s.t.Fatalf("login: %v", err)
	}
}

func bearer[T any](token string, message *T) *connect.Request[T] {
	request := connect.NewRequest(message)
	request.Header().Set("Authorization", "Bearer "+token)
	return request
}

// requireError asserts the Connect code and ErrorDetail reason of err.
func requireError(t *testing.T, err error, code connect.Code, reason string) *authorizerv1.ErrorDetail {
	t.Helper()
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("error = %v, want %s/%s", err, code, reason)
	}

	if connectErr.Code() != code {
		t.Fatalf("code = %s (%v), want %s", connectErr.Code(), err, code)
	}

	for _, detail := range connectErr.Details() {
		value, valueErr := detail.Value()
		if errorDetail, ok := value.(*authorizerv1.ErrorDetail); valueErr == nil && ok {
			if errorDetail.GetReason() != reason {
				t.Fatalf("reason = %s (%v), want %s", errorDetail.GetReason(), err, reason)
			}

			return errorDetail
		}
	}

	t.Fatalf("error %v has no ErrorDetail", err)
	return nil
}

func (s *testServer) create(token, reason string, items ...*authorizerv1.PermissionItemInput) *authorizerv1.GrantRequest {
	s.t.Helper()
	response, err := s.grant.CreateGrantRequest(s.t.Context(), bearer(token, &authorizerv1.CreateGrantRequestRequest{Reason: reason, Items: items}))
	if err != nil {
		s.t.Fatalf("create grant request: %v", err)
	}

	return response.Msg.GetGrantRequest()
}

func readItem(path string) *authorizerv1.PermissionItemInput {
	return &authorizerv1.PermissionItemInput{Path: path, Capabilities: []string{"read"}}
}

func itemStatesOf(request *authorizerv1.GrantRequest) []authorizerv1.ItemState {
	states := make([]authorizerv1.ItemState, 0, len(request.GetItems()))
	for _, item := range request.GetItems() {
		states = append(states, item.GetState())
	}

	return states
}

func (s *testServer) subscribers() int {
	s.events.mu.Lock()
	defer s.events.mu.Unlock()
	return len(s.events.subscribers)
}

// waitForNoSubscribers fails unless every stream handler has returned.
func (s *testServer) waitForNoSubscribers() {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.subscribers() != 0 {
		if time.Now().After(deadline) {
			s.t.Fatalf("%d stream handlers still running", s.subscribers())
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// nextRequest returns the next GrantRequest from the stream, skipping
// heartbeats; heartbeats reports how many were skipped.
func nextRequest(t *testing.T, stream *connect.ServerStreamForClient[authorizerv1.WatchGrantRequestResponse]) (*authorizerv1.GrantRequest, int) {
	t.Helper()
	heartbeats := 0
	for stream.Receive() {
		if request := stream.Msg().GetGrantRequest(); request != nil {
			return request, heartbeats
		}

		heartbeats++
	}

	t.Fatalf("stream ended: %v", stream.Err())
	return nil, 0
}

func nextSnapshot(t *testing.T, stream *connect.ServerStreamForClient[authorizerv1.WatchEventsResponse]) (*authorizerv1.DashboardSnapshot, int) {
	t.Helper()
	heartbeats := 0
	for stream.Receive() {
		if snapshot := stream.Msg().GetSnapshot(); snapshot != nil {
			return snapshot, heartbeats
		}

		heartbeats++
	}

	t.Fatalf("stream ended: %v", stream.Err())
	return nil, 0
}

// streamEnd reads until the stream ends and returns its error.
func streamEnd[T any](stream *connect.ServerStreamForClient[T]) error {
	for stream.Receive() {
	}

	return stream.Err()
}

func TestApproverSessionLifecycle(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	_, err := server.approver.ListGrantRequests(t.Context(), connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonSessionExpired)

	login, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: " human-token "}))
	if err != nil {
		t.Fatal(err)
	}

	cookie := login.Header().Get("Set-Cookie")
	for _, attribute := range []string{"openbao-authorizer-session=", "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age="} {
		if !strings.Contains(cookie, attribute) {
			t.Fatalf("Set-Cookie = %q, missing %q", cookie, attribute)
		}
	}

	if login.Msg.GetIdentity().GetEntityId() != "bob-id" || login.Msg.GetIdentity().GetDisplayName() != "Bob" {
		t.Fatalf("login identity = %v", login.Msg.GetIdentity())
	}

	// The OpenBao token only proves who signed in.
	if revoked := server.bao.RevokedTokens(); !slices.Equal(revoked, []string{"human-token"}) {
		t.Fatalf("revoked tokens = %#v", revoked)
	}

	id := sessionID(t, login.Header())
	stored, err := server.database.Session(t.Context(), id, time.Now())
	if err != nil || stored.EntityID != "bob-id" || stored.DisplayName != "Bob" {
		t.Fatalf("stored session = %#v, %v", stored, err)
	}

	// Later RPCs need no CSRF token and never call OpenBao.
	server.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusInternalServerError})
	restored, err := server.approver.GetSession(t.Context(), connect.NewRequest(&authorizerv1.GetSessionRequest{}))
	if err != nil || restored.Msg.GetIdentity().GetEntityId() != "bob-id" {
		t.Fatalf("get session = %v, %v", restored, err)
	}

	listed, err := server.approver.ListGrantRequests(t.Context(), connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{Filter: authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_PENDING}))
	if err != nil || len(listed.Msg.GetGrantRequests()) != 0 {
		t.Fatalf("list = %v, %v", listed, err)
	}

	_, err = server.approver.ListGrantRequests(t.Context(), connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{Filter: 99}))
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)

	logout, err := server.approver.Logout(t.Context(), connect.NewRequest(&authorizerv1.LogoutRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	if cleared := logout.Header().Get("Set-Cookie"); !strings.Contains(cleared, "Max-Age=0") || !strings.Contains(cleared, "HttpOnly") {
		t.Fatalf("logout Set-Cookie = %q", cleared)
	}

	if _, lookupErr := server.database.Session(t.Context(), id, time.Now()); !errors.Is(lookupErr, store.ErrNotFound) {
		t.Fatalf("stored session after logout: %v", lookupErr)
	}

	_, err = server.approver.GetSession(t.Context(), connect.NewRequest(&authorizerv1.GetSessionRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonSessionExpired)
}

func sessionID(t *testing.T, header http.Header) string {
	t.Helper()
	cookie, err := http.ParseSetCookie(header.Get("Set-Cookie"))
	if err != nil {
		t.Fatal(err)
	}

	return cookie.Value
}

func TestCreateSessionKeepsPastedToken(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	_, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token", KeepToken: true}))
	if err != nil {
		t.Fatal(err)
	}

	if revoked := server.bao.RevokedTokens(); len(revoked) != 0 {
		t.Fatalf("pasted token was revoked: %#v", revoked)
	}
}

func TestCreateSessionReplacesPreviousSession(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.bao.SetIdentity("carol-token", openbao.Identity{EntityID: "carol-id", IdentityPolicies: []string{"approver"}})
	first, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"}))
	if err != nil {
		t.Fatal(err)
	}

	second, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "carol-token"}))
	if err != nil {
		t.Fatal(err)
	}

	if _, lookupErr := server.database.Session(t.Context(), sessionID(t, first.Header()), time.Now()); !errors.Is(lookupErr, store.ErrNotFound) {
		t.Fatalf("previous session survived re-login: %v", lookupErr)
	}

	current, err := server.approver.GetSession(t.Context(), connect.NewRequest(&authorizerv1.GetSessionRequest{}))
	if err != nil || current.Msg.GetIdentity().GetEntityId() != "carol-id" || sessionID(t, second.Header()) == sessionID(t, first.Header()) {
		t.Fatalf("session after re-login = %v, %v", current, err)
	}
}

func TestSessionTTL(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{options: func(options *Options) { options.SessionTTL = 2 * time.Hour }})
	login, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"}))
	if err != nil {
		t.Fatal(err)
	}

	stored, err := server.database.Session(t.Context(), sessionID(t, login.Header()), time.Now())
	if remaining := time.Until(stored.ExpiresAt); err != nil || remaining > 2*time.Hour || remaining < time.Hour {
		t.Fatalf("stored session = %#v, %v", stored, err)
	}
}

func TestSecureCookieAttributes(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{options: func(options *Options) { options.InsecureCookies = false }})
	login, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"}))
	if err != nil {
		t.Fatal(err)
	}

	cookie := login.Header().Get("Set-Cookie")
	if !strings.HasPrefix(cookie, "__Host-openbao-authorizer-session=") || !strings.Contains(cookie, "Secure") {
		t.Fatalf("Set-Cookie = %q", cookie)
	}
}

func TestCreateSessionFailures(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.bao.SetIdentity("requester-token", openbao.Identity{EntityID: "alice-id", IdentityPolicies: []string{"requester"}})
	server.bao.SetIdentity("orphan-token", openbao.Identity{Policies: []string{"approver"}})

	_, err := server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{}))
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)

	_, err = server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "unknown-token"}))
	requireError(t, err, connect.CodeUnauthenticated, reasonInvalidToken)

	_, err = server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "requester-token"}))
	requireError(t, err, connect.CodePermissionDenied, reasonNotApprover)

	_, err = server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "orphan-token"}))
	requireError(t, err, connect.CodePermissionDenied, reasonNotApprover)
	if revoked := server.bao.RevokedTokens(); !slices.Equal(revoked, []string{"requester-token", "orphan-token"}) {
		t.Fatalf("refused tokens were not revoked: %#v", revoked)
	}

	server.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusInternalServerError})
	_, err = server.approver.CreateSession(t.Context(), connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"}))
	requireError(t, err, connect.CodeUnavailable, reasonOpenBaoUnavailable)
	server.bao.Fail("LookupSelf", nil)

	crossSite := connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"})
	crossSite.Header().Set("Origin", "https://evil.example")
	_, err = server.approver.CreateSession(t.Context(), crossSite)
	requireError(t, err, connect.CodePermissionDenied, reasonCrossOrigin)

	sameOrigin := connect.NewRequest(&authorizerv1.CreateSessionRequest{OpenbaoToken: "human-token"})
	sameOrigin.Header().Set("Origin", server.url)
	if _, err := server.approver.CreateSession(t.Context(), sameOrigin); err != nil {
		t.Fatalf("same-origin session: %v", err)
	}
}

func TestGetLoginOptionsNeedsNoSession(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{options: func(options *Options) {
		options.ApproverLogin = config.ApproverLogin{OpenBaoAddress: "https://bao.example", Namespace: "team", Methods: []config.LoginMethod{
			{Type: "token", Label: "Token"},
			{Type: "oidc", Mount: "sso", Label: "SSO", OIDCRole: "approver"},
		}}
	}})
	options, err := server.approver.GetLoginOptions(t.Context(), connect.NewRequest(&authorizerv1.GetLoginOptionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	want := &authorizerv1.GetLoginOptionsResponse{OpenbaoAddress: "https://bao.example", Namespace: "team", Methods: []*authorizerv1.LoginMethod{
		{Type: authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_TOKEN, Label: "Token"},
		{Type: authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_OIDC, Mount: "sso", Label: "SSO", OidcRole: "approver"},
	}}
	if !proto.Equal(options.Msg, want) {
		t.Fatalf("login options = %v", options.Msg)
	}

	crossSite := connect.NewRequest(&authorizerv1.GetLoginOptionsRequest{})
	crossSite.Header().Set("Sec-Fetch-Site", "cross-site")
	_, err = server.approver.GetLoginOptions(t.Context(), crossSite)
	requireError(t, err, connect.CodePermissionDenied, reasonCrossOrigin)
}

func TestApproverRPCsRequireSameOrigin(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{options: func(options *Options) { options.PublicOrigin = "https://authorizer.example/" }})
	server.login()

	tamper := map[string]func(http.Header){
		"wrong origin": func(header http.Header) { header.Set("Origin", server.url) },
		"cross-site":   func(header http.Header) { header.Set("Sec-Fetch-Site", "cross-site") },
	}
	for name, change := range tamper {
		getSession := connect.NewRequest(&authorizerv1.GetSessionRequest{})
		change(getSession.Header())
		_, err := server.approver.GetSession(t.Context(), getSession)
		requireError(t, err, connect.CodePermissionDenied, reasonCrossOrigin)

		revoke := connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: "missing"})
		change(revoke.Header())
		_, err = server.approver.RevokeGrant(t.Context(), revoke)
		requireError(t, err, connect.CodePermissionDenied, reasonCrossOrigin)

		watch := connect.NewRequest(&authorizerv1.WatchEventsRequest{})
		change(watch.Header())
		stream, err := server.approver.WatchEvents(t.Context(), watch)
		if err != nil {
			t.Fatalf("%s: open stream: %v", name, err)
		}

		requireError(t, streamEnd(stream), connect.CodePermissionDenied, reasonCrossOrigin)
		_ = stream.Close()
	}

	matching := connect.NewRequest(&authorizerv1.GetSessionRequest{})
	matching.Header().Set("Origin", "https://authorizer.example")
	matching.Header().Set("Sec-Fetch-Site", "same-origin")
	if _, err := server.approver.GetSession(t.Context(), matching); err != nil {
		t.Fatalf("configured origin: %v", err)
	}
}

func TestGrantAPIRequiresRequesterToken(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	message := &authorizerv1.CreateGrantRequestRequest{Reason: "x", Items: []*authorizerv1.PermissionItemInput{readItem("kv/data/a")}}
	_, err := server.grant.CreateGrantRequest(t.Context(), connect.NewRequest(message))
	var connectErr *connect.Error
	if requireError(t, err, connect.CodeUnauthenticated, reasonInvalidToken); !errors.As(err, &connectErr) || connectErr.Meta().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("missing bearer challenge: %v", err)
	}

	_, err = server.grant.CreateGrantRequest(t.Context(), bearer("unknown-token", message))
	requireError(t, err, connect.CodeUnauthenticated, reasonInvalidToken)

	// A human approver token has an entity but matches no Requester Rule.
	_, err = server.grant.CreateGrantRequest(t.Context(), bearer("human-token", message))
	requireError(t, err, connect.CodePermissionDenied, reasonNotRequester)

	// Approver cookies never authenticate the Grant API.
	server.login()
	_, err = server.grant.ListMyGrants(t.Context(), connect.NewRequest(&authorizerv1.ListMyGrantsRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonInvalidToken)

	stream, err := server.grant.WatchGrantRequest(t.Context(), bearer("unknown-token", &authorizerv1.WatchGrantRequestRequest{Id: "x"}))
	if err != nil {
		t.Fatal(err)
	}

	requireError(t, streamEnd(stream), connect.CodeUnauthenticated, reasonInvalidToken)
	_ = stream.Close()

	_, err = server.grant.CreateGrantRequest(t.Context(), bearer("session-a", &authorizerv1.CreateGrantRequestRequest{Items: message.Items}))
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)

	_, err = server.grant.CreateGrantRequest(t.Context(), bearer("session-a", &authorizerv1.CreateGrantRequestRequest{Reason: strings.Repeat("x", maxBodyBytes+1), Items: message.Items}))
	if connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("oversized body error = %v", err)
	}
}

func TestGrantableCatalogForRequestersAndApprovers(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{options: func(options *Options) { options.PublicOrigin = "https://authorizer.example" }})
	server.bao.SetList("kv/metadata", "b", "a", "folder/")
	want := []*authorizerv1.Grantable{{
		Name: "kv", Path: "kv/data/*", Capabilities: []string{"read"}, MaxTtl: durationpb.New(8 * time.Hour),
		Description: "App secrets", Paths: []string{"kv/data/a", "kv/data/b"},
	}}

	_, err := server.grant.ListGrantables(t.Context(), connect.NewRequest(&authorizerv1.ListGrantablesRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonInvalidToken)
	_, err = server.grant.ListGrantables(t.Context(), bearer("human-token", &authorizerv1.ListGrantablesRequest{}))
	requireError(t, err, connect.CodePermissionDenied, reasonNotRequester)

	requesterView, err := server.grant.ListGrantables(t.Context(), bearer("session-a", &authorizerv1.ListGrantablesRequest{}))
	if err != nil || !slices.EqualFunc(requesterView.Msg.GetGrantables(), want, func(a, b *authorizerv1.Grantable) bool { return proto.Equal(a, b) }) {
		t.Fatalf("requester catalog = %v, %v", requesterView, err)
	}

	_, err = server.approver.ListGrantableRules(t.Context(), connect.NewRequest(&authorizerv1.ListGrantableRulesRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonSessionExpired)

	server.login()
	crossOrigin := connect.NewRequest(&authorizerv1.ListGrantableRulesRequest{})
	crossOrigin.Header().Set("Origin", server.url)
	_, err = server.approver.ListGrantableRules(t.Context(), crossOrigin)
	requireError(t, err, connect.CodePermissionDenied, reasonCrossOrigin)

	approverView, err := server.approver.ListGrantableRules(t.Context(), connect.NewRequest(&authorizerv1.ListGrantableRulesRequest{}))
	if err != nil || !slices.EqualFunc(approverView.Msg.GetGrantables(), want, func(a, b *authorizerv1.Grantable) bool { return proto.Equal(a, b) }) {
		t.Fatalf("approver catalog = %v, %v", approverView, err)
	}
}

func TestGrantRequestApprovalWorkflow(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.login()
	changes, unsubscribe := server.events.Subscribe()
	defer unsubscribe()

	created := server.create("session-a", "deploy the app",
		&authorizerv1.PermissionItemInput{Path: "kv/data/a", Capabilities: []string{"read"}, Ttl: durationpb.New(2 * time.Hour)},
		readItem("kv/data/b"),
		readItem("secret/data/x"),
		readItem("sys/policies/acl/root"),
		&authorizerv1.PermissionItemInput{Path: "kv/data/c", Capabilities: []string{"read"}, Ttl: durationpb.New(9 * time.Hour)},
	)
	pending, refused := authorizerv1.ItemState_ITEM_STATE_PENDING, authorizerv1.ItemState_ITEM_STATE_REFUSED
	if !slices.Equal(itemStatesOf(created), []authorizerv1.ItemState{pending, pending, refused, refused, refused}) ||
		created.GetItems()[0].GetTtl().AsDuration() != 2*time.Hour || created.GetItems()[1].GetTtl().AsDuration() != 8*time.Hour {
		t.Fatalf("created = %v", created)
	}

	if created.GetRequester() != nil || created.GetItems()[2].GetReason() == "" || created.GetItems()[0].GetExpiresAt() == nil {
		t.Fatalf("agent view = %v", created)
	}

	select {
	case <-changes:
	default:
		t.Fatal("creation did not wake streams")
	}

	listed, err := server.approver.ListGrantRequests(t.Context(), connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{Filter: authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_PENDING}))
	if err != nil || len(listed.Msg.GetGrantRequests()) != 1 {
		t.Fatalf("pending = %v, %v", listed, err)
	}

	view := listed.Msg.GetGrantRequests()[0]
	if session := view.GetRequester(); view.GetReason() != "deploy the app" || session.GetId() != "aaa" || session.GetTitle() != "Fix CI" || session.GetDirectory() != "/src/app" || session.GetEntityId() != "entity-a" {
		t.Fatalf("approver view = %v", view)
	}

	_, err = server.grant.GetGrantRequest(t.Context(), bearer("session-b", &authorizerv1.GetGrantRequestRequest{Id: created.GetId()}))
	requireError(t, err, connect.CodeNotFound, reasonNotFound)

	itemA, itemB := created.GetItems()[0].GetId(), created.GetItems()[1].GetId()
	decide := func(decisions ...*authorizerv1.ItemDecision) (*authorizerv1.GrantRequest, error) {
		response, decideErr := server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{GrantRequestId: created.GetId(), Decisions: decisions}))
		if decideErr != nil {
			return nil, decideErr
		}

		return response.Msg.GetGrantRequest(), nil
	}
	approve, reject := authorizerv1.Decision_DECISION_APPROVE, authorizerv1.Decision_DECISION_REJECT

	_, err = decide(&authorizerv1.ItemDecision{ItemId: itemA, Decision: approve, Ttl: durationpb.New(3 * time.Hour)})
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)
	_, err = decide(&authorizerv1.ItemDecision{ItemId: itemA})
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)
	_, err = server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{GrantRequestId: "missing", Decisions: []*authorizerv1.ItemDecision{{ItemId: itemA, Decision: approve}}}))
	requireError(t, err, connect.CodeNotFound, reasonNotFound)

	decided, err := decide(
		&authorizerv1.ItemDecision{ItemId: itemA, Decision: approve, Ttl: durationpb.New(time.Hour)},
		&authorizerv1.ItemDecision{ItemId: itemB, Decision: reject},
	)
	if err != nil || decided.GetItems()[0].GetState() != authorizerv1.ItemState_ITEM_STATE_APPROVED || decided.GetItems()[1].GetState() != authorizerv1.ItemState_ITEM_STATE_REJECTED || decided.GetItems()[0].GetDecidedBy() != "Bob" {
		t.Fatalf("decide = %v, %v", decided, err)
	}

	policyName := grants.PolicyPrefix + "entity-a"
	if policy, ok := server.bao.Policy(policyName); !ok || policy.Expiration.IsZero() {
		t.Fatalf("grant policy = %#v, %v", policy, ok)
	}

	if policies := server.bao.EntityPolicies("entity-a"); !slices.Equal(policies, []string{policyName}) {
		t.Fatalf("entity policies = %#v", policies)
	}

	_, err = decide(&authorizerv1.ItemDecision{ItemId: itemB, Decision: approve})
	if detail := requireError(t, err, connect.CodeFailedPrecondition, reasonItemNotPending); !slices.Equal(detail.GetIds(), []string{itemB}) {
		t.Fatalf("conflict ids = %v", detail.GetIds())
	}

	again := server.create("session-a", "read it again", readItem("kv/data/a"))
	if again.GetItems()[0].GetState() != authorizerv1.ItemState_ITEM_STATE_ALREADY_GRANTED {
		t.Fatalf("already granted = %v", again)
	}

	agentGrants, err := server.grant.ListMyGrants(t.Context(), bearer("session-a", &authorizerv1.ListMyGrantsRequest{}))
	if err != nil || len(agentGrants.Msg.GetGrants()) != 1 || agentGrants.Msg.GetGrants()[0].GetPath() != "kv/data/a" || agentGrants.Msg.GetGrants()[0].GetRequester() != nil {
		t.Fatalf("agent grants = %v, %v", agentGrants, err)
	}

	otherGrants, err := server.grant.ListMyGrants(t.Context(), bearer("session-b", &authorizerv1.ListMyGrantsRequest{}))
	if err != nil || len(otherGrants.Msg.GetGrants()) != 0 {
		t.Fatalf("other session grants = %v, %v", otherGrants, err)
	}

	allGrants, err := server.approver.ListGrants(t.Context(), connect.NewRequest(&authorizerv1.ListGrantsRequest{}))
	if err != nil || len(allGrants.Msg.GetGrants()) != 1 || allGrants.Msg.GetGrants()[0].GetRequester() == nil || allGrants.Msg.GetGrants()[0].GetApprovedBy() != "Bob" {
		t.Fatalf("approver grants = %v, %v", allGrants, err)
	}

	grantID := allGrants.Msg.GetGrants()[0].GetId()
	if _, revokeErr := server.approver.RevokeGrant(t.Context(), connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: grantID})); revokeErr != nil {
		t.Fatalf("revoke: %v", revokeErr)
	}

	if _, ok := server.bao.Policy(policyName); ok {
		t.Fatal("revoked grant's policy remains")
	}

	_, err = server.approver.RevokeGrant(t.Context(), connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: grantID}))
	if detail := requireError(t, err, connect.CodeFailedPrecondition, reasonGrantNotActive); !slices.Equal(detail.GetIds(), []string{grantID}) {
		t.Fatalf("revoke conflict ids = %v", detail.GetIds())
	}

	_, err = server.approver.RevokeGrant(t.Context(), connect.NewRequest(&authorizerv1.RevokeGrantRequest{GrantId: "missing"}))
	requireError(t, err, connect.CodeNotFound, reasonNotFound)

	history, err := server.approver.ListGrantRequests(t.Context(), connect.NewRequest(&authorizerv1.ListGrantRequestsRequest{Filter: authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_DECIDED}))
	if err != nil || len(history.Msg.GetGrantRequests()) != 2 {
		t.Fatalf("history = %v, %v", history, err)
	}

	revokedView, err := server.grant.GetGrantRequest(t.Context(), bearer("session-a", &authorizerv1.GetGrantRequestRequest{Id: created.GetId()}))
	if err != nil || revokedView.Msg.GetGrantRequest().GetItems()[0].GetState() != authorizerv1.ItemState_ITEM_STATE_REVOKED {
		t.Fatalf("revoked item = %v, %v", revokedView, err)
	}
}

func TestApproversCannotDecideTheirOwnRequests(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	// An approver who also holds a Requester token shares one entity across both.
	server.bao.SetIdentity("bob-session", openbao.Identity{EntityID: "bob-id", Role: "opencode-session", Path: "auth/token/create/opencode-session"})
	server.bao.AddEntity(openbao.Entity{ID: "bob-id"})
	created := server.create("bob-session", "self", readItem("kv/data/a"))
	server.login()
	_, err := server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{
		GrantRequestId: created.GetId(),
		Decisions:      []*authorizerv1.ItemDecision{{ItemId: created.GetItems()[0].GetId(), Decision: authorizerv1.Decision_DECISION_APPROVE}},
	}))
	requireError(t, err, connect.CodePermissionDenied, reasonSelfApproval)
}

func TestOpenBaoFailuresAreReported(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.login()
	created := server.create("session-a", "x", readItem("kv/data/a"))

	server.bao.Fail("WritePolicy", &openbao.HTTPError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}})
	_, err := server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{
		GrantRequestId: created.GetId(),
		Decisions:      []*authorizerv1.ItemDecision{{ItemId: created.GetItems()[0].GetId(), Decision: authorizerv1.Decision_DECISION_APPROVE}},
	}))
	requireError(t, err, connect.CodeUnavailable, reasonOpenBaoUnavailable)
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("approver error lacks OpenBao detail: %v", err)
	}

	// Requesters get no OpenBao error text.
	server.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusInternalServerError, Errors: []string{"internal detail"}})
	_, err = server.grant.ListMyGrants(t.Context(), bearer("session-a", &authorizerv1.ListMyGrantsRequest{}))
	requireError(t, err, connect.CodeUnavailable, reasonOpenBaoUnavailable)
	if connectErr := new(connect.Error); errors.As(err, &connectErr) && connectErr.Message() != "OpenBao request failed" {
		t.Fatalf("agent error message = %q", connectErr.Message())
	}
}

func TestWatchGrantRequestFollowsDecisionsUntilNothingIsPending(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.login()
	created := server.create("session-a", "x", readItem("kv/data/a"), readItem("kv/data/b"))

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := server.grant.WatchGrantRequest(ctx, bearer("session-a", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = stream.Close() }()
	snapshot, _ := nextRequest(t, stream)
	if snapshot.GetId() != created.GetId() || snapshot.GetRequester() != nil || !slices.Equal(itemStatesOf(snapshot), itemStatesOf(created)) {
		t.Fatalf("snapshot = %v", snapshot)
	}

	// An unrelated change wakes the stream but sends nothing new; heartbeats
	// keep arriving until this request changes.
	server.create("session-b", "y", readItem("kv/data/z"))
	decide := func(itemID string, decision authorizerv1.Decision) {
		t.Helper()
		if _, decideErr := server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{
			GrantRequestId: created.GetId(), Decisions: []*authorizerv1.ItemDecision{{ItemId: itemID, Decision: decision}},
		})); decideErr != nil {
			t.Fatal(decideErr)
		}
	}
	time.Sleep(3 * testHeartbeat)
	decide(created.GetItems()[0].GetId(), authorizerv1.Decision_DECISION_APPROVE)
	changed, heartbeats := nextRequest(t, stream)
	if heartbeats == 0 {
		t.Fatal("no heartbeat while waiting")
	}

	if changed.GetItems()[0].GetState() != authorizerv1.ItemState_ITEM_STATE_APPROVED || changed.GetItems()[1].GetState() != authorizerv1.ItemState_ITEM_STATE_PENDING {
		t.Fatalf("after approval = %v", changed)
	}

	decide(created.GetItems()[1].GetId(), authorizerv1.Decision_DECISION_REJECT)
	final, _ := nextRequest(t, stream)
	if final.GetItems()[1].GetState() != authorizerv1.ItemState_ITEM_STATE_REJECTED {
		t.Fatalf("final = %v", final)
	}

	if endErr := streamEnd(stream); endErr != nil {
		t.Fatalf("stream did not end normally: %v", endErr)
	}

	// A request with nothing pending sends its state once and ends.
	done, err := server.grant.WatchGrantRequest(ctx, bearer("session-a", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatal(err)
	}

	if once, _ := nextRequest(t, done); once.GetId() != created.GetId() {
		t.Fatalf("decided snapshot = %v", once)
	}

	if endErr := streamEnd(done); endErr != nil {
		t.Fatalf("decided stream error = %v", endErr)
	}

	_ = done.Close()
	other, err := server.grant.WatchGrantRequest(ctx, bearer("session-b", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatal(err)
	}

	requireError(t, streamEnd(other), connect.CodeNotFound, reasonNotFound)
	_ = other.Close()
	server.waitForNoSubscribers()
}

func TestWatchGrantRequestEndsWhenTokenStopsAuthenticating(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	created := server.create("session-a", "x", readItem("kv/data/a"))
	watch := func() *connect.ServerStreamForClient[authorizerv1.WatchGrantRequestResponse] {
		t.Helper()
		stream, err := server.grant.WatchGrantRequest(t.Context(), bearer("session-a", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
		if err != nil {
			t.Fatal(err)
		}

		nextRequest(t, stream)
		return stream
	}

	stream := watch()
	server.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusInternalServerError})
	for range 3 {
		if !stream.Receive() || stream.Msg().GetHeartbeat() == nil {
			t.Fatalf("transient OpenBao failure ended the stream: %v", stream.Err())
		}
	}

	server.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusForbidden})
	requireError(t, streamEnd(stream), connect.CodeUnauthenticated, reasonInvalidToken)
	_ = stream.Close()

	server.bao.Fail("LookupSelf", nil)
	stream = watch()
	server.bao.SetIdentity("session-a", openbao.Identity{})
	requireError(t, streamEnd(stream), connect.CodePermissionDenied, reasonNotRequester)
	_ = stream.Close()
	server.waitForNoSubscribers()
}

func TestStreamsDisableProxyBuffering(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.login()
	created := server.create("session-a", "x", readItem("kv/data/a"))
	agentStream, err := server.grant.WatchGrantRequest(t.Context(), bearer("session-a", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = agentStream.Close() }()
	approverStream, err := server.approver.WatchEvents(t.Context(), connect.NewRequest(&authorizerv1.WatchEventsRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = approverStream.Close() }()
	nextRequest(t, agentStream)
	nextSnapshot(t, approverStream)
	for name, header := range map[string]http.Header{"WatchGrantRequest": agentStream.ResponseHeader(), "WatchEvents": approverStream.ResponseHeader()} {
		if header.Get("X-Accel-Buffering") != "no" || header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s headers = %v", name, header)
		}
	}
}

func TestWatchEventsSendsSnapshotsUntilLogout(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	server.login()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	stream, err := server.approver.WatchEvents(ctx, connect.NewRequest(&authorizerv1.WatchEventsRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = stream.Close() }()
	initial, _ := nextSnapshot(t, stream)
	if len(initial.GetPendingRequests())+len(initial.GetDecidedRequests())+len(initial.GetActiveGrants()) != 0 {
		t.Fatalf("initial snapshot = %v", initial)
	}

	time.Sleep(3 * testHeartbeat)
	created := server.create("session-a", "x", readItem("kv/data/a"))
	withPending, heartbeats := nextSnapshot(t, stream)
	if heartbeats == 0 {
		t.Fatal("no heartbeat while waiting")
	}

	if len(withPending.GetPendingRequests()) != 1 || withPending.GetPendingRequests()[0].GetRequester().GetId() != "aaa" {
		t.Fatalf("pending snapshot = %v", withPending)
	}

	if _, err := server.approver.DecideItems(t.Context(), connect.NewRequest(&authorizerv1.DecideItemsRequest{
		GrantRequestId: created.GetId(),
		Decisions:      []*authorizerv1.ItemDecision{{ItemId: created.GetItems()[0].GetId(), Decision: authorizerv1.Decision_DECISION_APPROVE}},
	})); err != nil {
		t.Fatal(err)
	}

	decided, _ := nextSnapshot(t, stream)
	if len(decided.GetPendingRequests()) != 0 || len(decided.GetDecidedRequests()) != 1 || len(decided.GetActiveGrants()) != 1 || decided.GetActiveGrants()[0].GetApprovedBy() != "Bob" {
		t.Fatalf("decided snapshot = %v", decided)
	}

	if _, err := server.approver.Logout(t.Context(), connect.NewRequest(&authorizerv1.LogoutRequest{})); err != nil {
		t.Fatal(err)
	}

	requireError(t, streamEnd(stream), connect.CodeUnauthenticated, reasonSessionExpired)
	server.waitForNoSubscribers()
}

func TestWatchEventsEndsWhenSessionExpires(t *testing.T) {
	t.Parallel()

	server := newTestServer(t)
	// Long enough that opening the stream on a loaded CI machine can't outlive
	// the session, which would fail the open instead of ending the stream.
	if err := server.database.PutSession(t.Context(), store.Session{ID: "short", EntityID: "bob-id", ExpiresAt: time.Now().Add(2 * time.Second)}); err != nil {
		t.Fatal(err)
	}

	request := connect.NewRequest(&authorizerv1.WatchEventsRequest{})
	request.Header().Set("Cookie", "openbao-authorizer-session=short")
	stream, err := server.approver.WatchEvents(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	nextSnapshot(t, stream)
	requireError(t, streamEnd(stream), connect.CodeUnauthenticated, reasonSessionExpired)
	_ = stream.Close()
	server.waitForNoSubscribers()
}

func TestStreamsOutliveServerTimeoutsAndStopOnDisconnect(t *testing.T) {
	t.Parallel()

	server := newTestServer(t, testConfig{server: func(config *http.Server) {
		config.ReadTimeout = 200 * time.Millisecond
		config.WriteTimeout = 200 * time.Millisecond
		config.IdleTimeout = time.Minute
	}})
	server.login()
	created := server.create("session-a", "x", readItem("kv/data/a"))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	agentStream, err := server.grant.WatchGrantRequest(ctx, bearer("session-a", &authorizerv1.WatchGrantRequestRequest{Id: created.GetId()}))
	if err != nil {
		t.Fatal(err)
	}

	approverStream, err := server.approver.WatchEvents(ctx, connect.NewRequest(&authorizerv1.WatchEventsRequest{}))
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !agentStream.Receive() {
			t.Fatalf("agent stream ended early: %v", agentStream.Err())
		}

		if !approverStream.Receive() {
			t.Fatalf("approver stream ended early: %v", approverStream.Err())
		}
	}

	if server.subscribers() != 2 {
		t.Fatalf("subscribers = %d", server.subscribers())
	}

	cancel()
	_ = agentStream.Close()
	_ = approverStream.Close()
	server.waitForNoSubscribers()
}

func TestPushEnrollment(t *testing.T) {
	t.Parallel()

	var validated []string
	server := newTestServer(t, testConfig{options: func(options *Options) {
		options.VAPIDPublicKey = "vapid-public-key"
		options.ValidatePushEndpoint = func(_ context.Context, endpoint string) error {
			validated = append(validated, endpoint)
			if strings.Contains(endpoint, "blocked") {
				return errors.New("blocked host")
			}

			return nil
		}
	}})
	_, err := server.approver.GetPushPublicKey(t.Context(), connect.NewRequest(&authorizerv1.GetPushPublicKeyRequest{}))
	requireError(t, err, connect.CodeUnauthenticated, reasonSessionExpired)

	server.login()
	key, err := server.approver.GetPushPublicKey(t.Context(), connect.NewRequest(&authorizerv1.GetPushPublicKeyRequest{}))
	if err != nil || key.Msg.GetPublicKey() != "vapid-public-key" {
		t.Fatalf("public key = %v, %v", key, err)
	}

	valid := &authorizerv1.RegisterPushSubscriptionRequest{
		Endpoint: "https://push.example/endpoint",
		P256Dh:   base64URL(65),
		Auth:     base64URL(16),
	}
	invalid := []*authorizerv1.RegisterPushSubscriptionRequest{
		{Endpoint: "http://push.example/endpoint", P256Dh: valid.P256Dh, Auth: valid.Auth},
		{Endpoint: valid.Endpoint, P256Dh: base64URL(64), Auth: valid.Auth},
		{Endpoint: "https://blocked.example/endpoint", P256Dh: valid.P256Dh, Auth: valid.Auth},
	}
	for _, message := range invalid {
		_, registerErr := server.approver.RegisterPushSubscription(t.Context(), connect.NewRequest(message))
		requireError(t, registerErr, connect.CodeInvalidArgument, reasonInvalidRequest)
	}

	if _, registerErr := server.approver.RegisterPushSubscription(t.Context(), connect.NewRequest(valid)); registerErr != nil {
		t.Fatal(registerErr)
	}

	subscriptions, err := server.database.Subscriptions(t.Context())
	if err != nil || len(subscriptions) != 1 || subscriptions[0].EntityID != "bob-id" || subscriptions[0].Endpoint != valid.Endpoint {
		t.Fatalf("subscriptions = %#v, %v", subscriptions, err)
	}

	_, err = server.approver.DeletePushSubscription(t.Context(), connect.NewRequest(&authorizerv1.DeletePushSubscriptionRequest{}))
	requireError(t, err, connect.CodeInvalidArgument, reasonInvalidRequest)
	if _, deleteErr := server.approver.DeletePushSubscription(t.Context(), connect.NewRequest(&authorizerv1.DeletePushSubscriptionRequest{Endpoint: valid.Endpoint})); deleteErr != nil {
		t.Fatal(deleteErr)
	}

	subscriptions, err = server.database.Subscriptions(t.Context())
	if err != nil || len(subscriptions) != 0 {
		t.Fatalf("subscriptions after delete = %#v, %v", subscriptions, err)
	}

	if !slices.Contains(validated, valid.Endpoint) {
		t.Fatalf("validated endpoints = %#v", validated)
	}

	// Subscriptions expire with the session, and logout deletes them.
	if _, registerErr := server.approver.RegisterPushSubscription(t.Context(), connect.NewRequest(valid)); registerErr != nil {
		t.Fatal(registerErr)
	}

	subscriptions, err = server.database.Subscriptions(t.Context())
	if remaining := time.Until(subscriptions[0].ExpiresAt); err != nil || remaining > defaultSessionTTL || remaining < defaultSessionTTL-time.Minute {
		t.Fatalf("subscriptions = %#v, %v", subscriptions, err)
	}

	if _, logoutErr := server.approver.Logout(t.Context(), connect.NewRequest(&authorizerv1.LogoutRequest{})); logoutErr != nil {
		t.Fatal(logoutErr)
	}

	subscriptions, err = server.database.Subscriptions(t.Context())
	if err != nil || len(subscriptions) != 0 {
		t.Fatalf("subscriptions after logout = %#v, %v", subscriptions, err)
	}
}

func base64URL(length int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, length))
}

type blockingPush struct {
	release chan struct{}
	sent    chan time.Time
}

func (p *blockingPush) NewRequest(ctx context.Context, _ string) error {
	<-p.release
	deadline, _ := ctx.Deadline()
	p.sent <- deadline
	return nil
}

func TestNotifierPushesWithoutBlockingTheCaller(t *testing.T) {
	t.Parallel()

	push := &blockingPush{release: make(chan struct{}), sent: make(chan time.Time, 1)}
	notifier := &Notifier{Events: NewEventBus(), Push: push}
	changes, unsubscribe := notifier.Events.Subscribe()
	defer unsubscribe()
	ctx, cancel := context.WithCancel(t.Context())
	if err := notifier.RequestChanged(ctx, "request-1", true); err != nil {
		t.Fatal(err)
	}

	// Streams wake synchronously; the push only runs once released, after
	// the caller's context is gone.
	select {
	case <-changes:
	default:
		t.Fatal("streams were not woken")
	}

	cancel()
	close(push.release)
	select {
	case deadline := <-push.sent:
		if deadline.IsZero() || time.Until(deadline) > pushTimeout {
			t.Fatalf("push deadline = %s", deadline)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push was not sent")
	}
}
