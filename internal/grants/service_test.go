package grants

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/openbao/openbaotest"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type recordingNotifier struct {
	mu         sync.Mutex
	newPending []string
	grants     []string
}

func (n *recordingNotifier) RequestChanged(_ context.Context, id string, newPending bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if newPending {
		n.newPending = append(n.newPending, id)
	}

	return nil
}

func (n *recordingNotifier) GrantChanged(_ context.Context, id string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.grants = append(n.grants, id)
	return nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

// faultyStore fails selected writes, as a full disk or a lost database would.
type faultyStore struct {
	*store.DB
	mu        sync.Mutex
	decideErr error
	revokeErr error
}

func (f *faultyStore) fail(decideErr, revokeErr error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decideErr, f.revokeErr = decideErr, revokeErr
}

func (f *faultyStore) DecideItems(ctx context.Context, request store.GrantRequest, grants []store.Grant) error {
	f.mu.Lock()
	err := f.decideErr
	f.mu.Unlock()
	if err != nil {
		return err
	}

	return f.DB.DecideItems(ctx, request, grants)
}

func (f *faultyStore) RevokeGrant(ctx context.Context, grantID string, approver store.Approver, now time.Time) error {
	f.mu.Lock()
	err := f.revokeErr
	f.mu.Unlock()
	if err != nil {
		return err
	}

	return f.DB.RevokeGrant(ctx, grantID, approver, now)
}

type fixture struct {
	service  *Service
	store    *faultyStore
	bao      *openbaotest.Fake
	notifier *recordingNotifier
	clock    *clock
	session  Requester
}

var approver = store.Approver{EntityID: "approver-1", Name: "Bob"}

func newFixture(t *testing.T) fixture {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	bao := openbaotest.New()
	bao.AddSession("token-a", "entity-a", map[string]string{"session_id": "aaa", "title": "Fix CI", "directory": "/src/app"})
	bao.AddSession("token-b", "entity-b", nil)
	notifier := &recordingNotifier{}
	now := &clock{now: time.Now().UTC()}
	faulty := &faultyStore{DB: database}
	service := New(bao, faulty, notifier, Config{
		Policy: Policy{DefaultTTL: 72 * time.Hour, Rules: []Rule{
			{Name: "kv", Path: "kv/data/*", Capabilities: []string{"read", "update"}, MaxTTL: 8 * time.Hour},
		}},
		PendingTTL: time.Hour,
		Requesters: []RequesterRule{{Name: "opencode", TokenRole: "opencode-session"}, {Name: "ci", AuthMount: "approle"}},
		Now:        now.Now,
	})
	session, err := service.Authenticate(t.Context(), "token-a")
	if err != nil {
		t.Fatal(err)
	}

	return fixture{service: service, store: faulty, bao: bao, notifier: notifier, clock: now, session: session}
}

func read(path string) ItemInput { return ItemInput{Path: path, Capabilities: []string{"read"}} }

const sessionPolicyName = PolicyPrefix + "entity-a"

// policyBlocks returns the session policy's blocks as "path=capabilities@expiry".
func (f fixture) policyBlocks(t *testing.T) []string {
	t.Helper()
	policy, ok := f.bao.Policy(sessionPolicyName)
	if !ok {
		return nil
	}

	blocks, err := openbaotest.ParsePolicy(policy.Document)
	if err != nil {
		t.Fatalf("parse session policy: %v\n%s", err, policy.Document)
	}

	rendered := make([]string, 0, len(blocks))
	for _, block := range blocks {
		rendered = append(rendered, block.Path+"="+strings.Join(block.Capabilities, ",")+"@"+block.Expiration)
	}

	slices.Sort(rendered)
	return rendered
}

func (f fixture) expiry(ttl time.Duration) string {
	return f.clock.Now().Add(ttl).UTC().Format(time.RFC3339)
}

func (f fixture) approve(t *testing.T, ttl string, paths ...string) store.GrantRequest {
	t.Helper()
	inputs := make([]ItemInput, 0, len(paths))
	for _, path := range paths {
		inputs = append(inputs, read(path))
	}

	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", inputs)
	if err != nil {
		t.Fatal(err)
	}

	decisions := make([]Decision, 0, len(paths))
	for _, item := range request.Items {
		decisions = append(decisions, Decision{ItemID: item.ID, Approve: true, TTL: ttl})
	}

	decided, err := f.service.Decide(t.Context(), approver, request.ID, decisions)
	if err != nil {
		t.Fatal(err)
	}

	return decided
}

func TestAuthenticateMatchesRequesterRules(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if f.session.EntityID != "entity-a" || f.session.Display != (store.RequesterDisplay{ID: "aaa", Title: "Fix CI", Directory: "/src/app", Rule: "opencode"}) {
		t.Fatalf("requester = %#v", f.session)
	}

	// Without meta.session_id the display name, then the entity ID, identifies the Requester.
	requester, err := f.service.Authenticate(t.Context(), "token-b")
	if err != nil || requester.Display != (store.RequesterDisplay{ID: "token", Rule: "opencode"}) {
		t.Fatalf("requester = %#v, %v", requester, err)
	}

	f.bao.SetIdentity("approle-token", openbao.Identity{EntityID: "ci-entity", Path: "auth/approle/login"})
	requester, err = f.service.Authenticate(t.Context(), "approle-token")
	if err != nil || requester.EntityID != "ci-entity" || requester.Display != (store.RequesterDisplay{ID: "ci-entity", Rule: "ci"}) {
		t.Fatalf("AppRole requester = %#v, %v", requester, err)
	}

	if _, err := f.service.Authenticate(t.Context(), "unknown"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("unknown token error = %v", err)
	}

	for token, identity := range map[string]openbao.Identity{
		"human-token":    {EntityID: "human", Path: "auth/userpass/login/bob", Meta: map[string]string{"session_id": "x"}},
		"other-role":     {EntityID: "other", Role: "other-role", Path: "auth/token/create/other-role"},
		"mount-prefix":   {EntityID: "other", Path: "auth/approle-other/login"},
		"no-entity":      {Role: "opencode-session"},
		"approle-orphan": {Path: "auth/approle/login"},
	} {
		f.bao.SetIdentity(token, identity)
		if _, err := f.service.Authenticate(t.Context(), token); !errors.Is(err, ErrNotRequester) {
			t.Fatalf("%s error = %v", token, err)
		}
	}

	f.bao.Fail("LookupSelf", &openbao.HTTPError{StatusCode: http.StatusInternalServerError})
	if _, err := f.service.Authenticate(t.Context(), "token-a"); err == nil || errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrNotRequester) {
		t.Fatalf("transient lookup error = %v", err)
	}
}

func TestApproversCannotDecideTheirOwnRequests(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a")})
	if err != nil {
		t.Fatal(err)
	}

	self := store.Approver{EntityID: f.session.EntityID, Name: "Self"}
	if _, err := f.service.Decide(t.Context(), self, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true}}); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("self-approval error = %v", err)
	}

	if f.bao.Calls("WritePolicy") != 0 {
		t.Fatal("self-approval wrote a policy")
	}

	decided := f.approve(t, "", "kv/data/b")
	if err := f.service.Revoke(t.Context(), self, decided.Items[0].GrantID); err != nil {
		t.Fatalf("revoking one's own Grant: %v", err)
	}
}

func TestRequestValidationAndAlreadyGranted(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if _, err := f.service.CreateRequest(t.Context(), f.session, "token-a", " ", []ItemInput{read("kv/data/a")}); err == nil {
		t.Fatal("expected missing reason error")
	}

	if _, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "deploy", nil); err == nil {
		t.Fatal("expected missing items error")
	}

	first, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "deploy", []ItemInput{
		read("kv/data/a"), read("sys/policies/acl/x"), read("secret/x"), read("kv/data/a"),
	})
	if err != nil {
		t.Fatal(err)
	}

	states := itemStates(first)
	want := []store.ItemState{store.ItemPending, store.ItemRefused, store.ItemRefused, store.ItemRefused}
	if !slices.Equal(states, want) || first.Items[0].TTL != 8*time.Hour || !strings.Contains(first.Items[1].Reason, "hard denylist") ||
		!strings.Contains(first.Items[3].Reason, "duplicate") {
		t.Fatalf("items = %#v", first.Items)
	}

	if len(f.notifier.newPending) != 1 {
		t.Fatalf("new pending notifications = %#v", f.notifier.newPending)
	}

	other, err := f.service.Authenticate(t.Context(), "token-b")
	if err != nil {
		t.Fatal(err)
	}

	otherRequest, err := f.service.CreateRequest(t.Context(), other, "token-b", "other", []ItemInput{read("kv/data/a")})
	if err != nil {
		t.Fatal(err)
	}

	if _, readErr := f.service.Request(t.Context(), "entity-b", first.ID, 0); !errors.Is(readErr, ErrNotFound) {
		t.Fatalf("cross-session read error = %v", readErr)
	}

	if _, decideErr := f.service.Decide(t.Context(), approver, first.ID, []Decision{{ItemID: first.Items[0].ID, Approve: true}}); decideErr != nil {
		t.Fatal(decideErr)
	}

	again, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "use it", []ItemInput{read("kv/data/a")})
	if err != nil || again.Items[0].State != store.ItemAlreadyGranted || len(f.notifier.newPending) != 2 {
		t.Fatalf("already granted = %#v, %v", again.Items, err)
	}

	stillPending, err := f.service.Request(t.Context(), "entity-b", otherRequest.ID, 0)
	if err != nil || stillPending.Items[0].State != store.ItemPending {
		t.Fatalf("grant leaked to other session: %#v, %v", stillPending.Items, err)
	}
}

func TestBatchApprovalWritesSessionPolicyOnce(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "deploy", []ItemInput{
		{Path: "kv/data/a", Capabilities: []string{"update", "read"}}, read("kv/data/b"), read("kv/data/c"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, extendErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true, TTL: "9h"}}); extendErr == nil {
		t.Fatal("expected TTL extension to fail")
	}

	if _, unknownErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: "missing", Approve: true}}); unknownErr == nil {
		t.Fatal("expected unknown item to fail")
	}

	decided, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{
		{ItemID: request.Items[0].ID, Approve: true, TTL: "30m"},
		{ItemID: request.Items[1].ID, Approve: true, TTL: "1h"},
		{ItemID: request.Items[2].ID, Approve: false},
	})
	if err != nil {
		t.Fatal(err)
	}

	states := itemStates(decided)
	if !slices.Equal(states, []store.ItemState{store.ItemApproved, store.ItemApproved, store.ItemRejected}) || decided.Items[0].DecidedBy != approver {
		t.Fatalf("decided items = %#v", decided.Items)
	}

	if calls := f.bao.Calls("WritePolicy"); calls != 1 {
		t.Fatalf("policy writes = %d, want 1", calls)
	}

	want := []string{"kv/data/a=read,update@" + f.expiry(30*time.Minute), "kv/data/b=read@" + f.expiry(time.Hour)}
	if blocks := f.policyBlocks(t); !slices.Equal(blocks, want) {
		t.Fatalf("policy blocks = %#v, want %#v", blocks, want)
	}

	if policy, _ := f.bao.Policy(sessionPolicyName); policy.Expiration.UTC().Format(time.RFC3339) != f.expiry(time.Hour) {
		t.Fatalf("policy expiration = %v, want the latest block's", policy.Expiration)
	}

	if !slices.Equal(f.bao.EntityPolicies("entity-a"), []string{sessionPolicyName}) {
		t.Fatalf("entity policies = %#v", f.bao.EntityPolicies("entity-a"))
	}

	if _, conflictErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[2].ID, Approve: true}}); !errors.Is(conflictErr, ErrConflict) {
		t.Fatalf("decided item error = %v", conflictErr)
	}

	// A later approval rewrites the policy but finds the name attached.
	f.approve(t, "2h", "kv/data/d")
	if writes, attaches := f.bao.Calls("WritePolicy"), f.bao.Calls("SetEntityPolicies"); writes != 2 || attaches != 1 {
		t.Fatalf("policy writes = %d, entity writes = %d", writes, attaches)
	}

	if blocks := f.policyBlocks(t); len(blocks) != 3 {
		t.Fatalf("policy blocks = %#v", blocks)
	}

	if len(f.notifier.grants) != 3 {
		t.Fatalf("grant notifications = %#v", f.notifier.grants)
	}
}

func TestRevokeRewritesThenDeletesSessionPolicy(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	decided := f.approve(t, "1h", "kv/data/a", "kv/data/b")
	if err := f.service.Revoke(t.Context(), approver, decided.Items[0].GrantID); err != nil {
		t.Fatal(err)
	}

	if blocks := f.policyBlocks(t); !slices.Equal(blocks, []string{"kv/data/b=read@" + f.expiry(time.Hour)}) {
		t.Fatalf("policy blocks after revoke = %#v", blocks)
	}

	if err := f.service.Revoke(t.Context(), approver, decided.Items[0].GrantID); !errors.Is(err, ErrConflict) {
		t.Fatalf("second revoke error = %v", err)
	}

	if err := f.service.Revoke(t.Context(), approver, decided.Items[1].GrantID); err != nil {
		t.Fatal(err)
	}

	// The name stays attached: without the policy it grants nothing.
	if _, ok := f.bao.Policy(sessionPolicyName); ok || !slices.Equal(f.bao.EntityPolicies("entity-a"), []string{sessionPolicyName}) {
		t.Fatalf("policy not deleted or entity changed: %#v", f.bao.EntityPolicies("entity-a"))
	}

	if calls := f.bao.Calls("SetEntityPolicies"); calls != 1 {
		t.Fatalf("entity writes = %d, want 1", calls)
	}

	stored, err := f.service.Request(t.Context(), "entity-a", decided.ID, 0)
	if err != nil || !slices.Equal(itemStates(stored), []store.ItemState{store.ItemRevoked, store.ItemRevoked}) {
		t.Fatalf("items = %#v, %v", stored.Items, err)
	}

	if err := f.service.Revoke(t.Context(), approver, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown grant error = %v", err)
	}
}

func TestRewriteExcludesExpiredBlocks(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.approve(t, "5s", "kv/data/short")
	f.clock.Advance(10 * time.Second)
	f.approve(t, "1h", "kv/data/long")
	if blocks := f.policyBlocks(t); !slices.Equal(blocks, []string{"kv/data/long=read@" + f.expiry(time.Hour)}) {
		t.Fatalf("policy blocks = %#v", blocks)
	}
}

func TestRejectionsMakeNoOpenBaoCalls(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a"), read("kv/data/b")})
	if err != nil {
		t.Fatal(err)
	}

	before := f.bao.Calls("CapabilitiesSelf")
	decided, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{
		{ItemID: request.Items[0].ID, Approve: false}, {ItemID: request.Items[1].ID, Approve: false},
	})
	if err != nil || !slices.Equal(itemStates(decided), []store.ItemState{store.ItemRejected, store.ItemRejected}) {
		t.Fatalf("decided = %#v, %v", decided.Items, err)
	}

	for _, method := range []string{"WritePolicy", "DeletePolicy", "ReadEntity", "SetEntityPolicies"} {
		if calls := f.bao.Calls(method); calls != 0 {
			t.Fatalf("%s calls = %d", method, calls)
		}
	}

	if f.bao.Calls("CapabilitiesSelf") != before {
		t.Fatal("decision called capabilities-self")
	}
}

func TestFailedPolicyWriteChangesNothing(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a"), read("kv/data/b")})
	if err != nil {
		t.Fatal(err)
	}

	f.bao.Fail("WritePolicy", &openbao.HTTPError{StatusCode: http.StatusInternalServerError})
	_, err = f.service.Decide(t.Context(), approver, request.ID, []Decision{
		{ItemID: request.Items[0].ID, Approve: true}, {ItemID: request.Items[1].ID, Approve: false},
	})
	if _, ok := errors.AsType[*openbao.HTTPError](err); !ok {
		t.Fatalf("decide error = %v", err)
	}

	stored, err := f.service.Request(t.Context(), "entity-a", request.ID, 0)
	if err != nil || !slices.Equal(itemStates(stored), []store.ItemState{store.ItemPending, store.ItemPending}) {
		t.Fatalf("items after failed approval = %#v, %v", stored.Items, err)
	}

	if f.bao.Calls("ReadEntity") != 0 || len(f.bao.EntityPolicies("entity-a")) != 0 {
		t.Fatal("entity touched after the policy write failed")
	}
}

func TestFailedAttachKeepsOperatorPoliciesAndRestoresPolicy(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.bao.AddEntity(openbao.Entity{ID: "entity-a", Policies: []string{"operator-extra"}})
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a")})
	if err != nil {
		t.Fatal(err)
	}

	f.bao.Fail("SetEntityPolicies", &openbao.HTTPError{StatusCode: http.StatusForbidden, Errors: []string{"permission denied"}})
	if _, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true}}); err == nil {
		t.Fatal("expected the entity update to fail")
	}

	if _, ok := f.bao.Policy(sessionPolicyName); ok {
		t.Fatal("policy written for an unrecorded Grant was not removed")
	}

	f.bao.Fail("SetEntityPolicies", nil)
	if _, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true}}); err != nil {
		t.Fatal(err)
	}

	if want := []string{"operator-extra", sessionPolicyName}; !slices.Equal(f.bao.EntityPolicies("entity-a"), want) {
		t.Fatalf("entity policies = %v, want %v", f.bao.EntityPolicies("entity-a"), want)
	}
}

func TestFailedCommitRestoresPolicy(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.approve(t, "1h", "kv/data/a")
	kept := f.policyBlocks(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/b"), read("kv/data/c")})
	if err != nil {
		t.Fatal(err)
	}

	diskFull := errors.New("disk full")
	f.store.fail(diskFull, nil)
	_, err = f.service.Decide(t.Context(), approver, request.ID, []Decision{
		{ItemID: request.Items[0].ID, Approve: true}, {ItemID: request.Items[1].ID, Approve: false},
	})
	if !errors.Is(err, diskFull) {
		t.Fatalf("decide error = %v", err)
	}

	if blocks := f.policyBlocks(t); !slices.Equal(blocks, kept) {
		t.Fatalf("policy blocks after failed commit = %#v, want %#v", blocks, kept)
	}

	stored, err := f.service.Request(t.Context(), "entity-a", request.ID, 0)
	if err != nil || !slices.Equal(itemStates(stored), []store.ItemState{store.ItemPending, store.ItemPending}) {
		t.Fatalf("items after failed commit = %#v, %v", stored.Items, err)
	}

	// A failed revocation record restores the revoked block too.
	f.store.fail(nil, diskFull)
	active, err := f.service.Grants(t.Context(), "entity-a")
	if err != nil {
		t.Fatal(err)
	}

	if err := f.service.Revoke(t.Context(), approver, active[0].ID); !errors.Is(err, diskFull) {
		t.Fatalf("revoke error = %v", err)
	}

	if blocks := f.policyBlocks(t); !slices.Equal(blocks, kept) {
		t.Fatalf("policy blocks after failed revocation = %#v, want %#v", blocks, kept)
	}
}

func TestSessionPolicyRendersDuplicateAndSpecialPaths(t *testing.T) {
	t.Parallel()

	var special strings.Builder
	special.WriteString("kv/data/")
	for character := rune(0x21); character < 0x7f; character++ {
		if !strings.ContainsRune(`"\{}$*+`, character) {
			special.WriteRune(character)
		}
	}

	special.WriteString("é")
	if refusal := checkConcretePath(special.String()); refusal != "" {
		t.Fatalf("test path is not grantable: %s", refusal)
	}

	now := time.Now().UTC().Truncate(time.Second)
	grants := []store.Grant{
		{Path: "kv/data/a", Capabilities: []string{"read"}, ExpiresAt: now.Add(time.Minute)},
		{Path: "kv/data/a", Capabilities: []string{"read", "update"}, ExpiresAt: now.Add(time.Hour)},
		{Path: special.String(), Capabilities: []string{"list"}, ExpiresAt: now.Add(time.Second)},
	}
	document, expiresAt := sessionPolicy(grants)
	if !expiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("policy expiration = %v", expiresAt)
	}

	blocks, err := openbaotest.ParsePolicy(document)
	if err != nil {
		t.Fatalf("parse policy: %v\n%s", err, document)
	}

	if len(blocks) != len(grants) {
		t.Fatalf("blocks = %#v", blocks)
	}

	for index, grant := range grants {
		block := blocks[index]
		if block.Path != grant.Path || !slices.Equal(block.Capabilities, grant.Capabilities) || block.Expiration != grant.ExpiresAt.Format(time.RFC3339) {
			t.Fatalf("block %d = %#v, want %#v", index, block, grant)
		}
	}
}

func TestLongPollWakesOnDecisionAndExpiry(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a"), read("kv/data/b")})
	if err != nil {
		t.Fatal(err)
	}

	result := make(chan store.GrantRequest, 1)
	go func() {
		polled, pollErr := f.service.Request(t.Context(), "entity-a", request.ID, 10*time.Second)
		if pollErr != nil {
			t.Error(pollErr)
		}

		result <- polled
	}()

	time.Sleep(50 * time.Millisecond)
	if _, decideErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: false}}); decideErr != nil {
		t.Fatal(decideErr)
	}

	select {
	case polled := <-result:
		if polled.Items[0].State != store.ItemRejected {
			t.Fatalf("polled = %#v", polled.Items)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("long poll did not wake on decision")
	}

	f.clock.Advance(2 * time.Hour)
	if expireErr := f.service.ExpirePending(t.Context()); expireErr != nil {
		t.Fatal(expireErr)
	}

	expired, err := f.service.Request(t.Context(), "entity-a", request.ID, time.Second)
	if err != nil || expired.Items[1].State != store.ItemExpired {
		t.Fatalf("expired = %#v, %v", expired.Items, err)
	}

	started := time.Now()
	pending, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/c")})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.service.Request(t.Context(), "entity-a", pending.ID, 100*time.Millisecond); err != nil || time.Since(started) < 100*time.Millisecond {
		t.Fatalf("long poll returned early: %v", err)
	}
}

func TestRequestRejectsHiddenRunesAndStoresRefusalsSafely(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if _, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "deploy\u202e", []ItemInput{read("kv/data/a")}); err == nil {
		t.Fatal("expected hidden rune in reason to fail")
	}

	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "deploy\n\tthe app", []ItemInput{
		{Path: "kv/data/" + strings.Repeat("é", 600), Capabilities: []string{"read"}},
		{Path: "kv/data/b\u200b", Capabilities: []string{"read,update"}},
		{Path: "secret/x", Capabilities: []string{"read", "list"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	stored, err := f.service.Request(t.Context(), "entity-a", request.ID, 0)
	if err != nil {
		t.Fatal(err)
	}

	long, hidden, unmatched := stored.Items[0], stored.Items[1], stored.Items[2]
	if long.State != store.ItemRefused || len(long.Path) > maxPathLength || !utf8.ValidString(long.Path) {
		t.Fatalf("long path stored as %d bytes: %#v", len(long.Path), long)
	}

	if hidden.State != store.ItemRefused || hidden.Path != "kv/data/b" || len(hidden.Capabilities) != 0 {
		t.Fatalf("invalid capabilities stored: %#v", hidden)
	}

	if unmatched.State != store.ItemRefused || !slices.Equal(unmatched.Capabilities, []string{"list", "read"}) {
		t.Fatalf("valid capabilities of a refused item: %#v", unmatched)
	}

	f.bao.AddSession("token-c", "entity-c", map[string]string{"session_id": "ccc", "title": "Fix\u202e CI\x1b[2J", "directory": "/src/\u200bapp"})
	session, err := f.service.Authenticate(t.Context(), "token-c")
	if err != nil || session.Display.Title != "Fix CI[2J" || session.Display.Directory != "/src/app" {
		t.Fatalf("session display = %#v, %v", session.Display, err)
	}
}

func TestDecideRevalidatesAgainstCurrentRules(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a"), read("kv/data/b"), read("kv/data/c")})
	if err != nil || request.Items[0].TTL != 8*time.Hour {
		t.Fatalf("request = %#v, %v", request.Items, err)
	}

	// The operator narrows the rules after the items were filed.
	f.service.config.Policy.Rules = []Rule{{Name: "kv-b", Path: "kv/data/b", Capabilities: []string{"read"}, MaxTTL: time.Hour}}
	if _, ttlErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[1].ID, Approve: true, TTL: "2h"}}); ttlErr == nil {
		t.Fatal("expected approver TTL above the current cap to fail")
	}

	decided, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{
		{ItemID: request.Items[0].ID, Approve: true},
		{ItemID: request.Items[1].ID, Approve: true},
		{ItemID: request.Items[2].ID, Approve: false},
	})
	if err != nil {
		t.Fatal(err)
	}

	refused, approved, rejected := decided.Items[0], decided.Items[1], decided.Items[2]
	if refused.State != store.ItemRefused || !strings.HasPrefix(refused.Reason, "no longer grantable: ") || refused.GrantID != "" {
		t.Fatalf("refused = %#v", refused)
	}

	if approved.State != store.ItemApproved || !approved.GrantExpires.Equal(f.clock.Now().Add(time.Hour).Truncate(time.Second)) {
		t.Fatalf("approved TTL not clamped to the current cap: %#v", approved)
	}

	if rejected.State != store.ItemRejected {
		t.Fatalf("rejected = %#v", rejected)
	}

	if blocks := f.policyBlocks(t); len(blocks) != 1 || !strings.HasPrefix(blocks[0], "kv/data/b=") {
		t.Fatalf("policy blocks = %#v", blocks)
	}
}

func TestConcurrentApprovalsWriteOneGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a")})
	if err != nil {
		t.Fatal(err)
	}

	errs := make(chan error, 4)
	for range cap(errs) {
		go func() {
			_, decideErr := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true}})
			errs <- decideErr
		}()
	}

	succeeded := 0
	for range cap(errs) {
		switch decideErr := <-errs; {
		case decideErr == nil:
			succeeded++
		case !errors.Is(decideErr, ErrConflict):
			t.Fatalf("decide error = %v", decideErr)
		}
	}

	if active, _ := f.service.Grants(t.Context(), "entity-a"); succeeded != 1 || len(active) != 1 || f.bao.Calls("WritePolicy") != 1 {
		t.Fatalf("succeeded = %d, grants = %d, policy writes = %d", succeeded, len(active), f.bao.Calls("WritePolicy"))
	}
}

func TestExpiredGrantsAreAnnounced(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if err := f.service.AnnounceExpiredGrants(t.Context()); err != nil {
		t.Fatal(err)
	}

	request, err := f.service.CreateRequest(t.Context(), f.session, "token-a", "x", []ItemInput{read("kv/data/a")})
	if err != nil {
		t.Fatal(err)
	}

	decided, err := f.service.Decide(t.Context(), approver, request.ID, []Decision{{ItemID: request.Items[0].ID, Approve: true, TTL: "1m"}})
	if err != nil {
		t.Fatal(err)
	}

	grantID := decided.Items[0].GrantID
	if err := f.service.AnnounceExpiredGrants(t.Context()); err != nil || len(f.notifier.grants) != 1 {
		t.Fatalf("unexpired grant announced: %#v, %v", f.notifier.grants, err)
	}

	f.clock.Advance(2 * time.Minute)
	for range 2 {
		if err := f.service.AnnounceExpiredGrants(t.Context()); err != nil {
			t.Fatal(err)
		}
	}

	if !slices.Equal(f.notifier.grants, []string{grantID, grantID}) {
		t.Fatalf("grant notifications = %#v", f.notifier.grants)
	}
}
