package grants

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// PolicyPrefix starts every Grant policy name, so the authorizer policy can
// scope policy writes to it; OpenBao cannot restrict which names go on an
// entity. Session Grants live in PolicyPrefix plus the entity ID, attached to
// the entity; project and global Grants live in ProjectPolicyPrefix plus the
// project and in GlobalPolicy, which tokens carry from the moment they are
// minted, so those policies need no attaching.
const (
	PolicyPrefix        = "agent-grant-"
	ProjectPolicyPrefix = PolicyPrefix + "project-"
	GlobalPolicy        = PolicyPrefix + "global"
)

const (
	maxItemsPerRequest = 64
	maxReasonLength    = 4096
	maxMetaLength      = 512
	maxPathLength      = 512
	expirySweep        = 10 * time.Second
)

var (
	// ErrInvalidToken means OpenBao rejected the presented token.
	ErrInvalidToken = errors.New("OpenBao token is invalid")
	// ErrNotRequester means the token matches no Requester Rule or has no entity.
	ErrNotRequester = errors.New("token does not match any requester rule")
	// ErrSelfApproval means an Approver tried to decide their own request.
	ErrSelfApproval = errors.New("approvers cannot decide their own requests")
	// ErrNotFound means the request or Grant does not exist for the caller.
	ErrNotFound = errors.New("not found")
	// ErrConflict means the item or Grant left the state a decision expects.
	ErrConflict = errors.New("no longer pending")
)

// InvalidError is a client error with a human-readable message.
type InvalidError struct{ Message string }

func (e *InvalidError) Error() string { return e.Message }

// ConflictError names the items or Grant that left the state a decision
// expects. It matches ErrConflict.
type ConflictError struct {
	IDs     []string
	Message string
}

func (e *ConflictError) Error() string { return e.Message + ": " + ErrConflict.Error() }

func (e *ConflictError) Unwrap() error { return ErrConflict }

func conflict(id, kind, path string) error {
	return &ConflictError{IDs: []string{id}, Message: kind + " " + path}
}

func invalid(format string, args ...any) error {
	return &InvalidError{Message: fmt.Sprintf(format, args...)}
}

// OpenBao is the API surface the service needs.
type OpenBao interface {
	LookupSelf(context.Context, string) (openbao.Identity, error)
	ReadEntity(context.Context, string) (openbao.Entity, error)
	SetEntityPolicies(context.Context, string, []string) error
	WritePolicy(context.Context, string, string, time.Time) error
	DeletePolicy(context.Context, string) error
	CapabilitiesSelf(context.Context, string, []string) (map[string][]string, error)
	List(context.Context, string) ([]string, error)
}

// Store persists Grant Requests and Grants.
type Store interface {
	CreateGrantRequest(context.Context, store.GrantRequest) error
	GrantRequest(context.Context, string) (store.GrantRequest, error)
	GrantRequests(context.Context, store.RequestFilter) ([]store.GrantRequest, error)
	DecideItems(context.Context, store.GrantRequest, []store.Grant) error
	ExpirePendingItems(context.Context, time.Time) ([]string, error)
	ExpiredGrants(context.Context, time.Time, time.Time) ([]string, error)
	Grant(context.Context, string) (store.Grant, error)
	ActiveGrants(context.Context, time.Time) ([]store.Grant, error)
	RevokeGrant(context.Context, string, store.Approver, time.Time) error
}

// Notifier fans changes out to approvers. Errors are logged, never returned
// to the caller whose change already succeeded.
type Notifier interface {
	// RequestChanged reports a new or changed request; newPending is true when
	// it added items an Approver has not seen yet.
	RequestChanged(ctx context.Context, requestID string, newPending bool) error
	GrantChanged(ctx context.Context, grantID string) error
}

// Config configures a Service.
type Config struct {
	Policy     Policy
	PendingTTL time.Duration
	// Requesters decide which tokens may file Grant Requests; the first
	// matching rule wins.
	Requesters []RequesterRule
	Logger     *slog.Logger
	Now        func() time.Time
}

// RequesterRule matches tokens by exactly one of TokenRole, the `role` from
// lookup-self, or AuthMount, the auth mount the token was issued from.
type RequesterRule struct {
	Name      string
	TokenRole string
	AuthMount string
}

func (r RequesterRule) matches(identity openbao.Identity) bool {
	if r.TokenRole != "" {
		return identity.Role == r.TokenRole
	}

	return strings.HasPrefix(identity.Path, "auth/"+r.AuthMount+"/")
}

// Requester is an authenticated Requester.
type Requester struct {
	EntityID string
	Display  store.RequesterDisplay
}

// Decision is an Approver's verdict on one item. An empty Scope keeps the
// item's scope.
type Decision struct {
	ItemID  string
	Approve bool
	TTL     string
	Scope   store.Scope
}

// Scopes lists the scopes a Grant for display's Requester may take, the
// default first. Project and global Grants reach only tokens carrying their
// policy, so a token without it can't use that scope; a project's own Named
// Token has no session of its own, so it uses project scope.
func Scopes(display store.RequesterDisplay) []store.Scope {
	scopes := display.Scopes
	if scopes == nil {
		// Requests stored before scopes existed.
		scopes = []store.Scope{store.ScopeSession}
	}

	return scopes
}

func requesterScopes(project, session string, global bool) []store.Scope {
	var scopes []store.Scope
	if session != "" || project == "" {
		scopes = append(scopes, store.ScopeSession)
	}

	if project != "" {
		scopes = append(scopes, store.ScopeProject)
	}

	if global {
		scopes = append(scopes, store.ScopeGlobal)
	}

	return scopes
}

// tokenProject returns the project whose policy the token carries, or "" for
// none or more than one.
func tokenProject(policies []string) string {
	project := ""
	for _, policy := range policies {
		name, ok := strings.CutPrefix(policy, ProjectPolicyPrefix)
		if !ok {
			continue
		}

		if project != "" || !validProjectName(name) {
			return ""
		}

		project = name
	}

	return project
}

func validProjectName(name string) bool {
	if name == "" || len(name) > 63 || name[0] == '-' {
		return false
	}

	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}

	return true
}

// policyName names the policy that holds grant's block.
func policyName(grant store.Grant) string {
	switch grant.Scope {
	case store.ScopeProject:
		return ProjectPolicyPrefix + grant.Project
	case store.ScopeGlobal:
		return GlobalPolicy
	case store.ScopeSession:
	}

	return PolicyPrefix + grant.EntityID
}

// Service implements Grant Requests, decisions and Grants.
type Service struct {
	bao      OpenBao
	store    Store
	notifier Notifier
	config   Config
	logger   *slog.Logger
	now      func() time.Time
	changes  changeSignal

	discoveries discoveryCache

	// policyMu serializes Grant policy writes and decisions. Project and
	// global policies are shared by many Requesters, and decisions are rare,
	// so one in-process lock suffices; one authorizer instance owns a database.
	policyMu sync.Mutex

	grantSweepMu sync.Mutex
	grantSweepAt time.Time
}

// New constructs a Service.
func New(bao OpenBao, storage Store, notifier Notifier, config Config) *Service {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		bao: bao, store: storage, notifier: notifier, config: config, logger: logger, now: now,
		changes: changeSignal{ch: make(chan struct{})},
	}
}

// Authenticate resolves a token to its Requester. Only tokens with an entity
// that match a Requester Rule qualify, so Grants always land on an identity
// and human or machine tokens outside every rule are refused.
func (s *Service) Authenticate(ctx context.Context, token string) (Requester, error) {
	identity, err := s.bao.LookupSelf(ctx, token)
	if err != nil {
		var httpErr *openbao.HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusUnauthorized) {
			return Requester{}, ErrInvalidToken
		}

		return Requester{}, fmt.Errorf("look up requester token: %w", err)
	}

	index := slices.IndexFunc(s.config.Requesters, func(rule RequesterRule) bool { return rule.matches(identity) })
	if index < 0 || identity.EntityID == "" {
		return Requester{}, ErrNotRequester
	}

	session := sanitizeText(identity.Meta["session"], maxMetaLength)
	id := session
	if id == "" {
		id = sanitizeText(identity.Meta["identity"], maxMetaLength)
	}

	if id == "" {
		id = sanitizeText(identity.DisplayName, maxMetaLength)
	}

	if id == "" {
		id = identity.EntityID
	}

	// The token's own policies, not its metadata, decide which project and
	// global Grants it can use.
	project := tokenProject(identity.Policies)
	return Requester{EntityID: identity.EntityID, Display: store.RequesterDisplay{
		ID:        id,
		Title:     sanitizeText(identity.Meta["title"], maxMetaLength),
		Directory: sanitizeText(identity.Meta["directory"], maxMetaLength),
		Rule:      s.config.Requesters[index].Name,
		Project:   project,
		Session:   session,
		Scopes:    requesterScopes(project, session, slices.Contains(identity.Policies, GlobalPolicy)),
	}}, nil
}

// CreateRequest validates items and stores a Grant Request. token is the
// Requester's token; it is used for capabilities-self and never stored.
func (s *Service) CreateRequest(ctx context.Context, requester Requester, token, reason string, inputs []ItemInput) (store.GrantRequest, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return store.GrantRequest{}, invalid("reason is required")
	}

	if len(reason) > maxReasonLength {
		return store.GrantRequest{}, invalid("reason must be at most %d characters", maxReasonLength)
	}

	if !checkText(reason, "\n\t") {
		return store.GrantRequest{}, invalid("reason contains control or invisible formatting characters")
	}

	if len(inputs) == 0 || len(inputs) > maxItemsPerRequest {
		return store.GrantRequest{}, invalid("between 1 and %d items are required", maxItemsPerRequest)
	}

	scopes := Scopes(requester.Display)
	for _, input := range inputs {
		if input.Scope != "" && !slices.Contains(scopes, input.Scope) {
			return store.GrantRequest{}, invalid("scope %s is not available to this Requester; available: %s", input.Scope, joinScopes(scopes))
		}
	}

	requestID, err := store.NewID()
	if err != nil {
		return store.GrantRequest{}, err
	}

	now := s.now().UTC()
	items := make([]store.Item, len(inputs))
	resolved := make([]Resolved, len(inputs))
	checkPaths := make([]string, 0, len(inputs))
	seen := make(map[string]bool, len(inputs))
	for index, input := range inputs {
		itemID, itemErr := store.NewID()
		if itemErr != nil {
			return store.GrantRequest{}, itemErr
		}

		item := store.Item{ID: itemID, Scope: cmp.Or(input.Scope, scopes[0])}
		result, refusal := s.config.Policy.Resolve(input)
		if refusal == "" {
			key := result.Path + "\x00" + strings.Join(result.Capabilities, ",")
			if seen[key] {
				refusal = "duplicate of another item in this request"
			}

			seen[key] = true
		}

		if refusal != "" {
			// Refused input is stored for display only; capabilities are
			// kept only in normalized form so a comma cannot split them.
			item.State = store.ItemRefused
			item.Reason = refusal
			item.Path = sanitizeText(input.Path, maxPathLength)
			item.Capabilities = []string{}
			if capabilities, capabilitiesRefusal := normalizeCapabilities(input.Capabilities); capabilitiesRefusal == "" {
				item.Capabilities = capabilities
			}
		} else {
			item.Path = result.Path
			item.Capabilities = result.Capabilities
			item.TTL = result.TTL
			item.State = store.ItemPending
			if !slices.Contains(checkPaths, result.Path) {
				checkPaths = append(checkPaths, result.Path)
			}
		}

		items[index] = item
		resolved[index] = result
	}

	if len(checkPaths) > 0 {
		capabilities, capabilitiesErr := s.bao.CapabilitiesSelf(ctx, token, checkPaths)
		if capabilitiesErr != nil {
			// Without the check an Approver still decides; a redundant Grant is harmless.
			s.logger.Warn("capabilities-self failed; items stay pending", "error", capabilitiesErr)
		}

		for index := range items {
			if items[index].State == store.ItemPending && Covers(capabilities[resolved[index].Path], items[index].Capabilities) {
				items[index].State = store.ItemAlreadyGranted
				items[index].Reason = "the Requester already has these capabilities"
			}
		}
	}

	request := store.GrantRequest{
		ID: requestID, EntityID: requester.EntityID, Requester: requester.Display, Reason: reason,
		CreatedAt: now, PendingUntil: now.Add(s.config.PendingTTL), Items: items,
	}
	if err := s.store.CreateGrantRequest(ctx, request); err != nil {
		return store.GrantRequest{}, err
	}

	newPending := hasPending(request)
	s.changes.notify()
	s.notify(func() error { return s.notifier.RequestChanged(context.WithoutCancel(ctx), request.ID, newPending) })
	return request, nil
}

// Request returns a request owned by entityID. With wait > 0 and pending
// items it blocks until any item changes state or wait elapses.
func (s *Service) Request(ctx context.Context, entityID, requestID string, wait time.Duration) (store.GrantRequest, error) {
	request, err := s.ownedRequest(ctx, entityID, requestID)
	if err != nil || wait <= 0 || !hasPending(request) {
		return request, err
	}

	initial := itemStates(request)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		changed := s.changes.wait()
		current, err := s.ownedRequest(ctx, entityID, requestID)
		if err != nil {
			return store.GrantRequest{}, err
		}

		if !slices.Equal(itemStates(current), initial) {
			return current, nil
		}

		select {
		case <-changed:
		case <-timer.C:
			return current, nil
		case <-ctx.Done():
			return current, nil
		}
	}
}

func (s *Service) ownedRequest(ctx context.Context, entityID, requestID string) (store.GrantRequest, error) {
	request, err := s.store.GrantRequest(ctx, requestID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && request.EntityID != entityID) {
		// Other Requesters' requests are indistinguishable from missing ones.
		return store.GrantRequest{}, ErrNotFound
	}

	return request, err
}

func hasPending(request store.GrantRequest) bool {
	return slices.ContainsFunc(request.Items, func(item store.Item) bool { return item.State == store.ItemPending })
}

func itemStates(request store.GrantRequest) []store.ItemState {
	states := make([]store.ItemState, len(request.Items))
	for index, item := range request.Items {
		states[index] = item.State
	}

	return states
}

// Requests lists requests for Approvers.
func (s *Service) Requests(ctx context.Context, filter store.RequestFilter) ([]store.GrantRequest, error) {
	return s.store.GrantRequests(ctx, filter)
}

// Grants lists every active Grant, for Approvers.
func (s *Service) Grants(ctx context.Context) ([]store.Grant, error) {
	return s.store.ActiveGrants(ctx, s.now())
}

// RequesterGrants lists the active Grants that reach requester: its session
// Grants and those of the project and global scopes it may use.
func (s *Service) RequesterGrants(ctx context.Context, requester Requester) ([]store.Grant, error) {
	active, err := s.store.ActiveGrants(ctx, s.now())
	if err != nil {
		return nil, err
	}

	scopes := Scopes(requester.Display)
	return slices.DeleteFunc(active, func(grant store.Grant) bool {
		switch grant.Scope {
		case store.ScopeProject:
			return !slices.Contains(scopes, store.ScopeProject) || grant.Project != requester.Display.Project
		case store.ScopeGlobal:
			return !slices.Contains(scopes, store.ScopeGlobal)
		case store.ScopeSession:
		}

		return grant.EntityID != requester.EntityID
	}), nil
}

func joinScopes(scopes []store.Scope) string {
	names := make([]string, len(scopes))
	for index, scope := range scopes {
		names[index] = string(scope)
	}

	return strings.Join(names, ", ")
}

// Decide applies an Approver's decisions to items of one request, all or
// nothing: approvals become blocks of the policies of their scopes, each
// written once, and every decision is stored in one transaction. An Approver never decides a
// request filed by their own entity, since that would let them grant
// themselves access.
func (s *Service) Decide(ctx context.Context, approver store.Approver, requestID string, decisions []Decision) (store.GrantRequest, error) {
	if len(decisions) == 0 {
		return store.GrantRequest{}, invalid("at least one decision is required")
	}

	request, err := s.store.GrantRequest(ctx, requestID)
	if errors.Is(err, store.ErrNotFound) {
		return store.GrantRequest{}, ErrNotFound
	}

	if err != nil {
		return store.GrantRequest{}, err
	}

	if request.EntityID == approver.EntityID {
		return store.GrantRequest{}, ErrSelfApproval
	}

	s.policyMu.Lock()
	request, grants, err := s.decide(ctx, approver, requestID, decisions)
	s.policyMu.Unlock()
	if err != nil {
		return store.GrantRequest{}, err
	}

	s.changes.notify()
	s.notify(func() error { return s.notifier.RequestChanged(context.WithoutCancel(ctx), requestID, false) })
	for _, grant := range grants {
		s.notify(func() error { return s.notifier.GrantChanged(context.WithoutCancel(ctx), grant.ID) })
	}

	return request, nil
}

// decide must run under policyMu. It re-reads the request so a
// concurrent decision on the same item cannot add a second Grant.
func (s *Service) decide(ctx context.Context, approver store.Approver, requestID string, decisions []Decision) (store.GrantRequest, []store.Grant, error) {
	request, err := s.store.GrantRequest(ctx, requestID)
	if err != nil {
		return store.GrantRequest{}, nil, err
	}

	now := s.now().UTC()
	grants := make([]store.Grant, 0, len(decisions))
	seen := make(map[string]bool, len(decisions))
	for _, decision := range decisions {
		index := slices.IndexFunc(request.Items, func(item store.Item) bool { return item.ID == decision.ItemID })
		if index < 0 {
			return store.GrantRequest{}, nil, invalid("item %q is not part of this request", decision.ItemID)
		}

		if seen[decision.ItemID] {
			return store.GrantRequest{}, nil, invalid("item %q is decided more than once", decision.ItemID)
		}

		seen[decision.ItemID] = true
		item := &request.Items[index]
		if item.State != store.ItemPending || !now.Before(request.PendingUntil) {
			return store.GrantRequest{}, nil, conflict(item.ID, "item", item.Path)
		}

		if (decision.TTL != "" || decision.Scope != "") && !decision.Approve {
			return store.GrantRequest{}, nil, invalid("ttl and scope apply only to approvals")
		}

		scope := cmp.Or(decision.Scope, item.Scope, store.ScopeSession)
		if scopes := Scopes(request.Requester); !slices.Contains(scopes, scope) {
			return store.GrantRequest{}, nil, invalid("scope %s is not available to this Requester; available: %s", scope, joinScopes(scopes))
		}

		item.DecidedAt = now
		if !decision.Approve {
			item.State = store.ItemRejected
			item.DecidedBy = approver
			continue
		}

		ttl, refusal, ttlErr := s.approvalTTL(*item, decision.TTL)
		if ttlErr != nil {
			return store.GrantRequest{}, nil, ttlErr
		}

		if refusal != "" {
			// A system decision, so no Approver is recorded.
			item.State = store.ItemRefused
			item.Reason = refusal
			continue
		}

		grantID, idErr := store.NewID()
		if idErr != nil {
			return store.GrantRequest{}, nil, idErr
		}

		// Whole seconds, because policy expirations are RFC 3339 seconds.
		expiresAt := now.Add(ttl).Truncate(time.Second)
		item.State, item.DecidedBy, item.GrantID, item.GrantExpires, item.Scope = store.ItemApproved, approver, grantID, expiresAt, scope
		grant := store.Grant{
			ID: grantID, RequestID: request.ID, ItemID: item.ID, EntityID: request.EntityID, Scope: scope, Path: item.Path,
			Capabilities: item.Capabilities, Requester: request.Requester, CreatedAt: now, ExpiresAt: expiresAt, ApprovedBy: approver.Name,
		}
		if scope == store.ScopeProject {
			grant.Project = request.Requester.Project
		}

		grants = append(grants, grant)
	}

	written, err := s.writeGrantPolicies(ctx, request.EntityID, grants, now)
	if err != nil {
		return store.GrantRequest{}, nil, err
	}

	if err := s.store.DecideItems(ctx, request, grants); err != nil {
		s.restorePolicies(ctx, written)

		if errors.Is(err, store.ErrStatusChanged) {
			ids := make([]string, 0, len(decisions))
			for _, decision := range decisions {
				ids = append(ids, decision.ItemID)
			}

			return store.GrantRequest{}, nil, &ConflictError{IDs: ids, Message: "items of request " + request.ID}
		}

		return store.GrantRequest{}, nil, err
	}

	return request, grants, nil
}

// approvalTTL re-runs rule resolution, because the configuration may have
// changed since the item was filed, and checks the Approver's TTL. A
// non-empty refusal means the item is no longer grantable.
func (s *Service) approvalTTL(item store.Item, requestedTTL string) (time.Duration, string, error) {
	current, refusal := s.config.Policy.Resolve(ItemInput{Path: item.Path, Capabilities: item.Capabilities})
	if refusal != "" {
		return 0, "no longer grantable: " + refusal, nil
	}

	ttl := min(item.TTL, current.MaxTTL)
	if requestedTTL == "" {
		return ttl, "", nil
	}

	parsed, err := time.ParseDuration(requestedTTL)
	if err != nil || parsed < time.Second {
		return 0, "", invalid("ttl %q must be a duration of at least 1s", requestedTTL)
	}

	if parsed > ttl {
		return 0, "", invalid("ttl %s may only shorten the resolved %s", FormatDuration(parsed), FormatDuration(ttl))
	}

	return parsed.Truncate(time.Second), "", nil
}

// Revoke removes a Grant's block from its policy, which ends access
// immediately, and then records the revocation.
func (s *Service) Revoke(ctx context.Context, approver store.Approver, grantID string) error {
	grant, err := s.store.Grant(ctx, grantID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	s.policyMu.Lock()
	err = s.revoke(ctx, approver, grant)
	s.policyMu.Unlock()
	if err != nil {
		return err
	}

	s.changes.notify()
	s.notify(func() error { return s.notifier.GrantChanged(context.WithoutCancel(ctx), grant.ID) })
	return nil
}

// RevokeOwn revokes a Grant filed by requester's own identity. Other
// Requesters' Grants are indistinguishable from missing ones, so a Requester
// can't end another's access, even to a project or global Grant.
func (s *Service) RevokeOwn(ctx context.Context, requester Requester, grantID string) error {
	grant, err := s.store.Grant(ctx, grantID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && grant.EntityID != requester.EntityID) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	// Recorded like an Approver's revocation, named after the Requester.
	revoker := store.Approver{EntityID: requester.EntityID, Name: requester.Display.ID + " (requester)"}
	s.policyMu.Lock()
	err = s.revoke(ctx, revoker, grant)
	s.policyMu.Unlock()
	if err != nil {
		return err
	}

	s.changes.notify()
	s.notify(func() error { return s.notifier.GrantChanged(context.WithoutCancel(ctx), grant.ID) })
	return nil
}

// revoke must run under policyMu.
func (s *Service) revoke(ctx context.Context, approver store.Approver, grant store.Grant) error {
	now := s.now()
	name := policyName(grant)
	active, err := s.policyGrants(ctx, name, now)
	if err != nil {
		return err
	}

	remaining := slices.DeleteFunc(slices.Clone(active), func(other store.Grant) bool { return other.ID == grant.ID })
	if len(remaining) == len(active) {
		return conflict(grant.ID, "grant", grant.Path)
	}

	if err := s.writePolicy(ctx, name, remaining); err != nil {
		return err
	}

	if err := s.store.RevokeGrant(ctx, grant.ID, approver, now); err != nil {
		s.restorePolicies(ctx, []string{name})
		if errors.Is(err, store.ErrStatusChanged) {
			return conflict(grant.ID, "grant", grant.Path)
		}

		return err
	}

	return nil
}

// policyGrants lists the stored active Grants held by the policy name.
func (s *Service) policyGrants(ctx context.Context, name string, now time.Time) ([]store.Grant, error) {
	active, err := s.store.ActiveGrants(ctx, now)
	if err != nil {
		return nil, err
	}

	return slices.DeleteFunc(active, func(grant store.Grant) bool { return policyName(grant) != name }), nil
}

// writeGrantPolicies adds new Grants to the policies of their scopes and
// attaches a session policy to the entity. It returns the names written; on
// failure it restores those from the store first. It must run under policyMu.
func (s *Service) writeGrantPolicies(ctx context.Context, entityID string, grants []store.Grant, now time.Time) ([]string, error) {
	byPolicy := make(map[string][]store.Grant)
	var names []string
	for _, grant := range grants {
		name := policyName(grant)
		if byPolicy[name] == nil {
			names = append(names, name)
		}

		byPolicy[name] = append(byPolicy[name], grant)
	}

	slices.Sort(names)
	for index, name := range names {
		active, err := s.policyGrants(ctx, name, now)
		if err == nil {
			err = s.writePolicy(ctx, name, append(active, byPolicy[name]...))
		}

		if err == nil && name == PolicyPrefix+entityID {
			err = s.attachPolicy(ctx, entityID)
		}

		if err != nil {
			// Restoring the failed policy too is harmless when it was never
			// written.
			s.restorePolicies(ctx, names[:index+1])
			return nil, err
		}
	}

	return names, nil
}

// writePolicy replaces the policy name with one block per Grant, or deletes
// it when no Grant is left. It must run under policyMu.
func (s *Service) writePolicy(ctx context.Context, name string, grants []store.Grant) error {
	if len(grants) == 0 {
		if err := s.bao.DeletePolicy(ctx, name); err != nil {
			return fmt.Errorf("delete Grant policy: %w", err)
		}

		return nil
	}

	document, expiresAt := grantPolicy(grants)
	if err := s.bao.WritePolicy(ctx, name, document, expiresAt); err != nil {
		return fmt.Errorf("write Grant policy: %w", err)
	}

	return nil
}

// restorePolicies rewrites the named policies from the stored active Grants
// after OpenBao and the store diverged.
func (s *Service) restorePolicies(ctx context.Context, names []string) {
	ctx = context.WithoutCancel(ctx)
	for _, name := range names {
		active, err := s.policyGrants(ctx, name, s.now())
		if err == nil {
			err = s.writePolicy(ctx, name, active)
		}

		if err != nil {
			s.logger.Error("restore Grant policy from stored grants", "policy", name, "error", err)
		}
	}
}

// attachPolicy adds the Requester policy to the Requester's entity, keeping
// policies an operator attached. The name is never detached: once the policy
// is deleted or expired it grants nothing, and leaving it saves entity writes.
func (s *Service) attachPolicy(ctx context.Context, entityID string) error {
	entity, err := s.bao.ReadEntity(ctx, entityID)
	if err != nil {
		return fmt.Errorf("read requester entity: %w", err)
	}

	if slices.Contains(entity.Policies, PolicyPrefix+entityID) {
		return nil
	}

	if err := s.bao.SetEntityPolicies(ctx, entityID, append(entity.Policies, PolicyPrefix+entityID)); err != nil {
		return fmt.Errorf("update requester entity policies: %w", err)
	}

	return nil
}

// grantPolicy renders one path block per Grant, each with its own
// expiration, so each scope needs one policy however many Grants it holds.
// JSON policies cannot repeat a path key, so it is HCL; json.Marshal quotes
// strings in a form HCL parses, and paths exclude the characters HCL would
// interpret. The policy expires with its last block.
func grantPolicy(grants []store.Grant) (string, time.Time) {
	var document strings.Builder
	var expiresAt time.Time
	for _, grant := range grants {
		path, _ := json.Marshal(grant.Path)
		capabilities, _ := json.Marshal(grant.Capabilities)
		fmt.Fprintf(&document, "path %s {\n  capabilities = %s\n  expiration = %q\n}\n", path, capabilities, grant.ExpiresAt.UTC().Format(time.RFC3339))
		if grant.ExpiresAt.After(expiresAt) {
			expiresAt = grant.ExpiresAt
		}
	}

	return document.String(), expiresAt
}

// ExpirePending expires undecided items past their pending deadline.
func (s *Service) ExpirePending(ctx context.Context) error {
	requestIDs, err := s.store.ExpirePendingItems(ctx, s.now())
	if err != nil {
		return err
	}

	if len(requestIDs) == 0 {
		return nil
	}

	s.changes.notify()
	for _, id := range requestIDs {
		s.notify(func() error { return s.notifier.RequestChanged(ctx, id, false) })
	}

	return nil
}

// AnnounceExpiredGrants notifies Approvers of Grants that expired since the
// previous call. OpenBao enforces the expiry; this only refreshes views. The
// first call sets the starting point and announces nothing.
func (s *Service) AnnounceExpiredGrants(ctx context.Context) error {
	s.grantSweepMu.Lock()
	defer s.grantSweepMu.Unlock()
	now := s.now()
	if s.grantSweepAt.IsZero() {
		s.grantSweepAt = now
		return nil
	}

	grantIDs, err := s.store.ExpiredGrants(ctx, s.grantSweepAt, now)
	if err != nil {
		return err
	}

	s.grantSweepAt = now
	for _, id := range grantIDs {
		s.notify(func() error { return s.notifier.GrantChanged(ctx, id) })
	}

	return nil
}

// Run expires pending items and announces expired Grants until ctx ends.
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(expirySweep)
	defer ticker.Stop()
	for {
		if err := s.ExpirePending(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Error("expire pending items", "error", err)
		}

		if err := s.AnnounceExpiredGrants(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger.Error("announce expired grants", "error", err)
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) notify(send func() error) {
	if s.notifier == nil {
		return
	}

	if err := send(); err != nil {
		s.logger.Warn("notify approvers", "error", err)
	}
}

// changeSignal wakes long-polls whenever any item may have changed state.
type changeSignal struct {
	mu sync.Mutex
	ch chan struct{}
}

func (c *changeSignal) wait() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ch
}

func (c *changeSignal) notify() {
	c.mu.Lock()
	defer c.mu.Unlock()
	close(c.ch)
	c.ch = make(chan struct{})
}
