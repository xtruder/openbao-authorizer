package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/approvalcontext"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type fakeBao struct {
	approvedToken     string
	loginUsername     string
	loginPassword     string
	renewedToken      string
	revokedToken      string
	identity          openbao.Identity
	identities        map[string]openbao.Identity
	lookupErrors      map[string]error
	requests          map[string]openbao.ControlGroupRequest
	requestErrors     map[string]error
	requestCalls      []string
	authorizeUpdates  map[string]openbao.ControlGroupRequest
	authorizeErrors   map[string]error
	authorizeCalls    []string
	revokeErrors      map[string]error
	revokeCalls       []string
	readData          map[string]json.RawMessage
	readErrors        map[string]error
	readCalls         []string
	onRevokeAccessor  func(string)
	revokeAccessorErr error
}

func (f *fakeBao) LoginUserpass(_ context.Context, username, password string) (openbao.AuthToken, error) {
	f.loginUsername = username
	f.loginPassword = password
	if username != "bob" || password != "correct horse" {
		return openbao.AuthToken{}, &openbao.HTTPError{StatusCode: http.StatusBadRequest}
	}

	return openbao.AuthToken{Token: "human-token", Renewable: true, TTL: 24 * time.Hour}, nil
}

func (f *fakeBao) RenewSelf(_ context.Context, token string) error {
	f.renewedToken = token
	return nil
}

func (f *fakeBao) RevokeSelf(_ context.Context, token string) error {
	f.revokedToken = token
	return nil
}

func (f *fakeBao) RevokeAccessor(_ context.Context, accessor string) error {
	f.revokeCalls = append(f.revokeCalls, accessor)
	if f.onRevokeAccessor != nil {
		f.onRevokeAccessor(accessor)
	}

	if err := f.revokeErrors[accessor]; err != nil {
		return err
	}

	return f.revokeAccessorErr
}

func (f *fakeBao) LookupSelf(_ context.Context, token string) (openbao.Identity, error) {
	if err := f.lookupErrors[token]; err != nil {
		return openbao.Identity{}, err
	}

	if identity, ok := f.identities[token]; ok {
		return identity, nil
	}

	if token != "human-token" {
		return openbao.Identity{}, &openbao.HTTPError{StatusCode: http.StatusForbidden}
	}

	if f.identity.EntityID != "" {
		return f.identity, nil
	}

	return openbao.Identity{EntityID: "bob-id", DisplayName: "Bob", IdentityPolicies: []string{"approver"}, TTL: 300}, nil
}

func (f *fakeBao) Authorize(_ context.Context, token, accessor string) (bool, error) {
	f.approvedToken = token
	f.authorizeCalls = append(f.authorizeCalls, accessor)
	if err := f.authorizeErrors[accessor]; err != nil {
		return false, err
	}

	if update, ok := f.authorizeUpdates[accessor]; ok {
		f.requests[accessor] = update
	} else {
		request := f.requests[accessor]
		request.Approved = true
		request.Authorizations = append(request.Authorizations, openbao.Authorization{EntityID: "bob-id", EntityName: "Bob"})
		f.requests[accessor] = request
	}

	return f.requests[accessor].Approved, nil
}

func (f *fakeBao) ControlGroupRequest(_ context.Context, accessor string) (openbao.ControlGroupRequest, error) {
	f.requestCalls = append(f.requestCalls, accessor)
	if err := f.requestErrors[accessor]; err != nil {
		return openbao.ControlGroupRequest{}, err
	}

	request, ok := f.requests[accessor]
	if !ok {
		return openbao.ControlGroupRequest{}, openbao.ErrNotControlGroup
	}

	return request, nil
}

func (f *fakeBao) Read(_ context.Context, path string) (json.RawMessage, error) {
	f.readCalls = append(f.readCalls, path)
	if err := f.readErrors[path]; err != nil {
		return nil, err
	}

	return f.readData[path], nil
}

type recordingStore struct {
	*store.DB
	beforeCreate func()
}

func (s *recordingStore) CreateGroup(ctx context.Context, input store.CreateGroupInput) (store.Group, bool, error) {
	if s.beforeCreate != nil {
		s.beforeCreate()
	}

	return s.DB.CreateGroup(ctx, input)
}

func openTestStore(t *testing.T) *store.DB {
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
	return database
}

func testOptions(bao *fakeBao, persistence Store, sessions *Sessions) Options {
	if sessions == nil {
		sessions = NewSessions()
	}

	return Options{
		OpenBao: bao, Store: persistence, Events: NewEventBus(), Sessions: sessions,
		ApproverPolicy: "approver", InsecureCookies: true,
	}
}

func performRequest(t *testing.T, handler http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	for name, value := range headers {
		request.Header.Set(name, value)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func performApproverMutation(t *testing.T, handler http.Handler, path, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		request.Header.Set("X-CSRF-Token", csrf)
	}

	request.AddCookie(&http.Cookie{Name: "openbao-authorizer-session", Value: "approver-session"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func approverSessions() *Sessions {
	sessions := NewSessions()
	sessions.sessions["approver-session"] = session{
		Token: "human-token", CSRFToken: "csrf",
		Identity: openbao.Identity{EntityID: "bob-id", DisplayName: "Bob"}, ExpiresAt: time.Now().Add(time.Hour),
	}
	return sessions
}

func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}

	return string(encoded)
}

func submitGroup(t *testing.T, handler http.Handler, token, key, reason string, accessors []string) *httptest.ResponseRecorder {
	t.Helper()
	body := encodeJSON(t, map[string]any{"idempotencyKey": key, "reason": reason, "accessors": accessors})
	headers := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		headers["X-Vault-Token"] = token
	}

	return performRequest(t, handler, http.MethodPost, "/api/v1/request-groups", body, headers)
}

func createGroup(t *testing.T, database *store.DB, key, reason string, accessors []string, requests []openbao.ControlGroupRequest) store.Group {
	t.Helper()
	submitted := make([]store.SubmittedRequest, len(accessors))
	for index := range accessors {
		submitted[index] = store.SubmittedRequest{Accessor: accessors[index], Request: requests[index]}
	}

	group, created, err := database.CreateGroup(t.Context(), store.CreateGroupInput{
		IdempotencyKey: key, Reason: reason, Entity: openbao.Entity{ID: "alice-id", Name: "Alice"}, Requests: submitted,
	})
	if err != nil || !created {
		t.Fatalf("create group: new=%v error=%v", created, err)
	}

	return group
}

func pendingRequest(path string) openbao.ControlGroupRequest {
	return openbao.ControlGroupRequest{
		Operation: "read", Path: path, Data: json.RawMessage(`{"secret":"value"}`),
		Entity: openbao.Entity{ID: "alice-id", Name: "Alice"},
	}
}

func TestSessionsRestoreDurableRecords(t *testing.T) {
	t.Parallel()

	expires := time.Now().Add(time.Hour)
	sessions := NewSessions()
	sessions.Restore([]store.Session{{
		ID: "restored", Token: "human-token", CSRFToken: "csrf",
		Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: expires,
	}})
	if tokens := sessions.ActiveTokens("bob"); len(tokens) != 1 || tokens[0] != "human-token" {
		t.Fatalf("restored tokens = %#v", tokens)
	}
}

func TestSessionsExposeActiveTokensAndDeleteOneToken(t *testing.T) {
	t.Parallel()

	now := time.Now()
	sessions := NewSessions()
	sessions.sessions["active"] = session{Token: "renew-me", Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: now.Add(time.Hour)}
	sessions.sessions["expired"] = session{Token: "expired", Identity: openbao.Identity{EntityID: "bob"}, ExpiresAt: now.Add(-time.Hour)}

	if tokens := sessions.AllActiveTokens(now); len(tokens) != 1 || tokens[0] != "renew-me" {
		t.Fatalf("active tokens = %#v", tokens)
	}

	sessions.DeleteToken("renew-me")
	if tokens := sessions.AllActiveTokens(now); len(tokens) != 0 {
		t.Fatalf("tokens after delete = %#v", tokens)
	}
}

func TestSubmitRequestGroupUsesEntityTokenAndReviewsEveryAccessor(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	bao := &fakeBao{
		identities: map[string]openbao.Identity{
			"entity-token": {EntityID: "alice-id", DisplayName: "Alice", IdentityPolicies: []string{"requester"}},
		},
		requests: map[string]openbao.ControlGroupRequest{
			"accessor-b": pendingRequest("secret/b"),
			"accessor-a": pendingRequest("secret/a"),
		},
	}
	createAfterReviews := -1
	persistence := &recordingStore{DB: database, beforeCreate: func() { createAfterReviews = len(bao.requestCalls) }}
	handler := New(testOptions(bao, persistence, nil))

	response := submitGroup(t, handler, "entity-token", "deploy-42", "Deploy payroll changes", []string{"accessor-b", "accessor-a"})
	if response.Code != http.StatusCreated {
		t.Fatalf("submit status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.requestCalls, []string{"accessor-b", "accessor-a"}) || createAfterReviews != 2 {
		t.Fatalf("request reviews = %#v, reviews before create = %d", bao.requestCalls, createAfterReviews)
	}

	var group store.Group
	if err := json.NewDecoder(response.Body).Decode(&group); err != nil {
		t.Fatal(err)
	}

	if group.Reason != "Deploy payroll changes" || group.Entity.ID != "alice-id" || len(group.Requests) != 2 {
		t.Fatalf("submitted group = %#v", group)
	}

	if group.Requests[0].Path != "secret/b" || group.Requests[1].Path != "secret/a" {
		t.Fatalf("request order = %#v", group.Requests)
	}

	accessors, err := database.GroupAccessors(t.Context(), group.ID)
	if err != nil || accessors[0].Accessor != "accessor-b" || accessors[1].Accessor != "accessor-a" {
		t.Fatalf("stored accessors = %#v, error = %v", accessors, err)
	}
}

func TestSubmitRequestGroupRejectsMissingAndInvalidEntityTokens(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		token string
	}{
		{name: "missing"},
		{name: "invalid", token: "invalid-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			database := openTestStore(t)
			bao := &fakeBao{requests: map[string]openbao.ControlGroupRequest{"accessor": pendingRequest("secret/a")}}
			handler := New(testOptions(bao, database, nil))

			response := submitGroup(t, handler, test.token, "key", "reason", []string{"accessor"})
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}

			groups, err := database.Groups(t.Context())
			if err != nil || len(groups) != 0 {
				t.Fatalf("groups = %#v, error = %v", groups, err)
			}
		})
	}
}

func TestSubmitRequestGroupOwnershipMismatchLeavesDatabaseUnchanged(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	mismatched := pendingRequest("secret/b")
	mismatched.Entity = openbao.Entity{ID: "mallory-id", Name: "Mallory"}
	bao := &fakeBao{
		identities: map[string]openbao.Identity{"entity-token": {EntityID: "alice-id", DisplayName: "Alice"}},
		requests: map[string]openbao.ControlGroupRequest{
			"owned": pendingRequest("secret/a"), "other": mismatched,
		},
	}
	handler := New(testOptions(bao, database, nil))

	response := submitGroup(t, handler, "entity-token", "key", "reason", []string{"owned", "other"})
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.requestCalls, []string{"owned", "other"}) {
		t.Fatalf("reviewed accessors = %#v", bao.requestCalls)
	}

	groups, err := database.Groups(t.Context())
	if err != nil || len(groups) != 0 {
		t.Fatalf("groups = %#v, error = %v", groups, err)
	}
}

func TestSubmitRequestGroupValidatesAccessorsAndReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		reason        string
		accessors     []string
		requireReason bool
	}{
		{name: "duplicate accessor", reason: "reason", accessors: []string{"accessor", " accessor "}},
		{name: "empty accessor", reason: "reason", accessors: []string{"accessor", "  "}},
		{name: "required reason", accessors: []string{"accessor"}, requireReason: true},
		{name: "reason too long", reason: strings.Repeat("å", maxReasonLength+1), accessors: []string{"accessor"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			database := openTestStore(t)
			bao := &fakeBao{
				identities: map[string]openbao.Identity{"entity-token": {EntityID: "alice-id"}},
				requests:   map[string]openbao.ControlGroupRequest{"accessor": pendingRequest("secret/a")},
			}
			options := testOptions(bao, database, nil)
			options.RequireReason = test.requireReason
			handler := New(options)

			response := submitGroup(t, handler, "entity-token", "key", test.reason, test.accessors)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}

			groups, err := database.Groups(t.Context())
			if err != nil || len(groups) != 0 {
				t.Fatalf("groups = %#v, error = %v", groups, err)
			}
		})
	}
}

func TestSubmitRequestGroupIsIdempotentAndRejectsConflictingRetry(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	bao := &fakeBao{
		identities: map[string]openbao.Identity{"entity-token": {EntityID: "alice-id", DisplayName: "Alice"}},
		requests:   map[string]openbao.ControlGroupRequest{"accessor": pendingRequest("secret/a")},
	}
	handler := New(testOptions(bao, database, nil))

	first := submitGroup(t, handler, "entity-token", "stable-key", "same reason", []string{"accessor"})
	retry := submitGroup(t, handler, "entity-token", "stable-key", "same reason", []string{"accessor"})
	conflict := submitGroup(t, handler, "entity-token", "stable-key", "different reason", []string{"accessor"})
	if first.Code != http.StatusCreated || retry.Code != http.StatusOK || conflict.Code != http.StatusConflict {
		t.Fatalf("statuses = %d, %d, %d", first.Code, retry.Code, conflict.Code)
	}

	var created, retried store.Group
	if err := json.NewDecoder(first.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	if err := json.NewDecoder(retry.Body).Decode(&retried); err != nil {
		t.Fatal(err)
	}

	if created.ID == "" || retried.ID != created.ID {
		t.Fatalf("created ID = %q, retried ID = %q", created.ID, retried.ID)
	}

	groups, err := database.Groups(t.Context())
	if err != nil || len(groups) != 1 {
		t.Fatalf("groups = %#v, error = %v", groups, err)
	}
}

func TestListRequestGroupsRequiresApproverAndRedactsMemberData(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	createGroup(t, database, "key", "Production deploy", []string{"accessor"}, []openbao.ControlGroupRequest{pendingRequest("secret/a")})
	bao := &fakeBao{}
	handler := New(testOptions(bao, database, approverSessions()))

	unauthenticated := performRequest(t, handler, http.MethodGet, "/api/v1/request-groups", "", nil)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", unauthenticated.Code)
	}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/request-groups", nil)
	request.AddCookie(&http.Cookie{Name: "openbao-authorizer-session", Value: "approver-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", response.Code, response.Body.String())
	}

	var groups []store.Group
	if err := json.NewDecoder(response.Body).Decode(&groups); err != nil {
		t.Fatal(err)
	}

	if len(groups) != 1 || groups[0].Reason != "Production deploy" || len(groups[0].Requests) != 1 {
		t.Fatalf("groups = %#v", groups)
	}

	if len(groups[0].Requests[0].Data) != 0 {
		t.Fatalf("raw member data was exposed: %s", groups[0].Requests[0].Data)
	}
}

func TestGetRequestGroupReturnsRedactedGroupAndUnknownIDNotFound(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	group := createGroup(t, database, "key", "Production deploy", []string{"accessor"}, []openbao.ControlGroupRequest{pendingRequest("secret/a")})
	handler := New(testOptions(&fakeBao{}, database, approverSessions()))

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/request-groups/"+group.ID, nil)
	request.AddCookie(&http.Cookie{Name: "openbao-authorizer-session", Value: "approver-session"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", response.Code, response.Body.String())
	}

	var got store.Group
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}

	if got.ID != group.ID || got.Reason != "Production deploy" || len(got.Requests) != 1 {
		t.Fatalf("group = %#v", got)
	}

	if len(got.Requests[0].Data) != 0 {
		t.Fatalf("raw member data was exposed: %s", got.Requests[0].Data)
	}

	missingRequest := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/request-groups/unknown", nil)
	missingRequest.AddCookie(&http.Cookie{Name: "openbao-authorizer-session", Value: "approver-session"})
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingRequest)
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("unknown group status = %d, body = %s", missingResponse.Code, missingResponse.Body.String())
	}
}

func TestApproveRequestGroupProcessesMembersInOrderAndTracksQuorum(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		approved   []bool
		wantStatus store.GroupStatus
	}{
		{name: "quorum remains pending", approved: []bool{false, true}, wantStatus: store.GroupPending},
		{name: "all approved", approved: []bool{true, true}, wantStatus: store.GroupApproved},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			database := openTestStore(t)
			first := pendingRequest("secret/first")
			second := pendingRequest("secret/second")
			group := createGroup(t, database, "key", "reason", []string{"accessor-2", "accessor-1"}, []openbao.ControlGroupRequest{first, second})
			firstAfter := first
			firstAfter.Approved = test.approved[0]
			firstAfter.Authorizations = []openbao.Authorization{{EntityID: "bob-id", EntityName: "Bob"}}
			secondAfter := second
			secondAfter.Approved = test.approved[1]
			secondAfter.Authorizations = []openbao.Authorization{{EntityID: "bob-id", EntityName: "Bob"}}
			bao := &fakeBao{
				requests: map[string]openbao.ControlGroupRequest{"accessor-2": first, "accessor-1": second},
				authorizeUpdates: map[string]openbao.ControlGroupRequest{
					"accessor-2": firstAfter, "accessor-1": secondAfter,
				},
			}
			handler := New(testOptions(bao, database, approverSessions()))

			if test.wantStatus == store.GroupApproved {
				missingCSRF := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/approve", "")
				if missingCSRF.Code != http.StatusForbidden || len(bao.authorizeCalls) != 0 {
					t.Fatalf("missing CSRF status/calls = %d/%#v", missingCSRF.Code, bao.authorizeCalls)
				}
			}

			response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/approve", "csrf")
			if response.Code != http.StatusOK {
				t.Fatalf("approve status = %d, body = %s", response.Code, response.Body.String())
			}

			if !slices.Equal(bao.requestCalls, []string{"accessor-2", "accessor-1", "accessor-2", "accessor-1"}) {
				t.Fatalf("request calls = %#v", bao.requestCalls)
			}

			if !slices.Equal(bao.authorizeCalls, []string{"accessor-2", "accessor-1"}) || bao.approvedToken != "human-token" {
				t.Fatalf("authorize calls/token = %#v/%q", bao.authorizeCalls, bao.approvedToken)
			}

			stored, err := database.Group(t.Context(), group.ID)
			if err != nil || stored.Status != test.wantStatus {
				t.Fatalf("stored group = %#v, error = %v", stored, err)
			}

			if stored.Requests[0].Approved != test.approved[0] || stored.Requests[1].Approved != test.approved[1] {
				t.Fatalf("stored members = %#v", stored.Requests)
			}
		})
	}
}

func TestApproveRequestGroupSkipsApproversExistingAuthorization(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	first := pendingRequest("secret/first")
	first.Authorizations = []openbao.Authorization{{EntityID: "bob-id", EntityName: "Bob"}}
	second := pendingRequest("secret/second")
	group := createGroup(t, database, "key", "reason", []string{"already-authorized", "needs-authorization"}, []openbao.ControlGroupRequest{first, second})
	secondAfter := second
	secondAfter.Approved = true
	bao := &fakeBao{
		requests:         map[string]openbao.ControlGroupRequest{"already-authorized": first, "needs-authorization": second},
		authorizeUpdates: map[string]openbao.ControlGroupRequest{"needs-authorization": secondAfter},
	}
	handler := New(testOptions(bao, database, approverSessions()))

	response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/approve", "csrf")
	if response.Code != http.StatusOK {
		t.Fatalf("approve status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.authorizeCalls, []string{"needs-authorization"}) {
		t.Fatalf("authorize calls = %#v", bao.authorizeCalls)
	}

	stored, err := database.Group(t.Context(), group.ID)
	if err != nil || stored.Status != store.GroupPending || stored.Requests[0].Approved {
		t.Fatalf("stored group = %#v, error = %v", stored, err)
	}
}

func TestApproveRequestGroupPreflightsContextDriftBeforeAuthorization(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	first := pendingRequest("secret/first")
	second := pendingRequest("github/token/project")
	second.ApprovalContext = &openbao.ApprovalContext{Available: true, Data: json.RawMessage(`{"repositories":["old"]}`)}
	group := createGroup(t, database, "key", "reason", []string{"first", "drifted"}, []openbao.ControlGroupRequest{first, second})
	contexts, err := approvalcontext.New([]approvalcontext.Rule{{
		Name: "github-token", MatchPath: "github/token/{name}", ReadPath: "github/permissionset/{name}",
	}})
	if err != nil {
		t.Fatal(err)
	}

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{"first": first, "drifted": second},
		readData: map[string]json.RawMessage{"github/permissionset/project": json.RawMessage(`{"repositories":["new"]}`)},
	}
	options := testOptions(bao, database, approverSessions())
	options.ApprovalContext = contexts
	handler := New(options)

	response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/approve", "csrf")
	if response.Code != http.StatusConflict {
		t.Fatalf("approve status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.requestCalls, []string{"first", "drifted"}) || len(bao.authorizeCalls) != 0 {
		t.Fatalf("request/authorize calls = %#v/%#v", bao.requestCalls, bao.authorizeCalls)
	}

	stored, err := database.Group(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}

	if stored.Status != store.GroupPending || stored.Requests[0].Approved {
		t.Fatalf("stored group = %#v", stored)
	}

	if got := string(stored.Requests[1].ApprovalContext.Data); got != `{"repositories":["new"]}` {
		t.Fatalf("refreshed context = %s", got)
	}
}

func TestApproveRequestGroupRecordsFailureStatus(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	first := pendingRequest("secret/first")
	second := pendingRequest("secret/second")
	group := createGroup(t, database, "key", "reason", []string{"first", "second"}, []openbao.ControlGroupRequest{first, second})
	firstAfter := first
	firstAfter.Approved = true
	bao := &fakeBao{
		requests:         map[string]openbao.ControlGroupRequest{"first": first, "second": second},
		authorizeUpdates: map[string]openbao.ControlGroupRequest{"first": firstAfter},
		authorizeErrors: map[string]error{
			"second": &openbao.HTTPError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}},
		},
	}
	handler := New(testOptions(bao, database, approverSessions()))

	response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/approve", "csrf")
	if response.Code != http.StatusBadGateway {
		t.Fatalf("approve status = %d, body = %s", response.Code, response.Body.String())
	}

	stored, err := database.Group(t.Context(), group.ID)
	if err != nil || stored.Status != store.GroupApprovalFailed {
		t.Fatalf("stored group = %#v, error = %v", stored, err)
	}

	if !stored.Requests[0].Approved || stored.Requests[1].Approved {
		t.Fatalf("stored members = %#v", stored.Requests)
	}
}

func TestRejectRequestGroupRejectsEveryMember(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	group := createGroup(t, database, "key", "reason", []string{"second", "first"}, []openbao.ControlGroupRequest{
		pendingRequest("secret/second"), pendingRequest("secret/first"),
	})
	bao := &fakeBao{}
	handler := New(testOptions(bao, database, approverSessions()))

	response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/reject", "csrf")
	if response.Code != http.StatusOK {
		t.Fatalf("reject status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.revokeCalls, []string{"second", "first"}) {
		t.Fatalf("revoke calls = %#v", bao.revokeCalls)
	}

	stored, err := database.Group(t.Context(), group.ID)
	if err != nil || stored.Status != store.GroupRejected {
		t.Fatalf("stored group = %#v, error = %v", stored, err)
	}

	for _, request := range stored.Requests {
		if request.Status != store.RequestRejected {
			t.Fatalf("stored members = %#v", stored.Requests)
		}
	}
}

func TestRejectRequestGroupRecordsFailureStatus(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	group := createGroup(t, database, "key", "reason", []string{"fails", "succeeds"}, []openbao.ControlGroupRequest{
		pendingRequest("secret/first"), pendingRequest("secret/second"),
	})
	bao := &fakeBao{revokeErrors: map[string]error{"fails": errors.New("OpenBao unavailable")}}
	handler := New(testOptions(bao, database, approverSessions()))

	response := performApproverMutation(t, handler, "/api/v1/request-groups/"+group.ID+"/reject", "csrf")
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("reject status = %d, body = %s", response.Code, response.Body.String())
	}

	if !slices.Equal(bao.revokeCalls, []string{"fails", "succeeds"}) {
		t.Fatalf("revoke calls = %#v", bao.revokeCalls)
	}

	stored, err := database.Group(t.Context(), group.ID)
	if err != nil || stored.Status != store.GroupRejectionFailed {
		t.Fatalf("stored group = %#v, error = %v", stored, err)
	}

	if stored.Requests[0].Status != store.RequestPending || stored.Requests[1].Status != store.RequestRejected {
		t.Fatalf("stored members = %#v", stored.Requests)
	}
}

func TestSessionLoginAndLogoutWorkflow(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	bao := &fakeBao{}
	server := httptest.NewServer(New(testOptions(bao, database, nil)))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Jar = jar

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}

	loginCookies := response.Cookies()
	var login struct {
		CSRFToken string `json:"csrfToken"`
	}
	if decodeErr := json.NewDecoder(response.Body).Decode(&login); decodeErr != nil {
		t.Fatal(decodeErr)
	}

	if login.CSRFToken == "" || bao.loginUsername != "bob" || bao.loginPassword != "correct horse" {
		t.Fatalf("login = %#v, credentials = %q/%q", login, bao.loginUsername, bao.loginPassword)
	}

	if len(loginCookies) != 1 || loginCookies[0].MaxAge < int((29*24*time.Hour).Seconds()) {
		t.Fatalf("persistent cookies = %#v", loginCookies)
	}

	storedSessions, err := database.Sessions(t.Context(), time.Now())
	if err != nil || len(storedSessions) != 1 || storedSessions[0].Token != "human-token" {
		t.Fatalf("stored sessions = %#v, %v", storedSessions, err)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodDelete, server.URL+"/api/v1/session", bytes.NewBufferString(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", login.CSRFToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent || bao.revokedToken != "human-token" {
		t.Fatalf("logout status/token = %d/%q", response.StatusCode, bao.revokedToken)
	}

	storedSessions, err = database.Sessions(t.Context(), time.Now())
	if err != nil || len(storedSessions) != 0 {
		t.Fatalf("stored sessions after logout = %#v, %v", storedSessions, err)
	}
}

func TestLoginRequiresJSONAndApproverPolicy(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	bao := &fakeBao{identity: openbao.Identity{EntityID: "alice-id", IdentityPolicies: []string{"requester"}, TTL: 300}}
	server := httptest.NewServer(New(testOptions(bao, database, nil)))
	defer server.Close()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("missing JSON content type status = %d", response.StatusCode)
	}

	request, err = http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	request.Header.Set("Content-Type", "application/json")
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("non-approver status = %d", response.StatusCode)
	}

	if bao.revokedToken != "human-token" {
		t.Fatalf("rejected login token was not revoked: %q", bao.revokedToken)
	}
}

func TestSessionRevalidatesPolicy(t *testing.T) {
	t.Parallel()

	database := openTestStore(t)
	bao := &fakeBao{identity: openbao.Identity{EntityID: "bob-id", IdentityPolicies: []string{"approver"}, TTL: 300}}
	server := httptest.NewServer(New(testOptions(bao, database, nil)))
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	client := server.Client()
	client.Jar = jar

	login, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/api/v1/session", bytes.NewBufferString(`{"username":"bob","password":"correct horse"}`))
	if err != nil {
		t.Fatal(err)
	}

	login.Header.Set("Content-Type", "application/json")
	response, err := client.Do(login)
	if err != nil {
		t.Fatal(err)
	}

	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", response.StatusCode)
	}

	bao.identity.IdentityPolicies = []string{"requester"}
	listRequest, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/v1/request-groups", nil)
	if err != nil {
		t.Fatal(err)
	}

	response, err = client.Do(listRequest)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked approver policy status = %d", response.StatusCode)
	}
}
