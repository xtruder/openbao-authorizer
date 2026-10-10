package grants

import (
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

// PolicyPrefix plus the entity ID names each Agent Session's policy. The
// authorizer policy can scope policy writes to it, but OpenBao cannot restrict
// which names go on an entity.
const PolicyPrefix = "agent-grant-"

const (
	maxItemsPerRequest = 64
	maxReasonLength    = 4096
	maxMetaLength      = 512
	maxPathLength      = 512
	expirySweep        = 10 * time.Second
)

var (
	// ErrInvalidToken means OpenBao rejected the presented Session Token.
	ErrInvalidToken = errors.New("OpenBao token is invalid")
	// ErrNotSession means the token does not belong to an Agent Session.
	ErrNotSession = errors.New("token does not belong to an agent session")
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
	ActiveGrants(context.Context, string, time.Time) ([]store.Grant, error)
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
	// SessionTokenRole is the token role every Session Token is created with.
	SessionTokenRole string
	Logger           *slog.Logger
	Now              func() time.Time
}

// Session is an authenticated Agent Session.
type Session struct {
	EntityID string
	Display  store.SessionDisplay
}

// Decision is an Approver's verdict on one item.
type Decision struct {
	ItemID  string
	Approve bool
	TTL     string
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

	sessionLocksMu sync.Mutex
	sessionLocks   map[string]*sessionLock

	grantSweepMu sync.Mutex
	grantSweepAt time.Time
}

type sessionLock struct {
	mu   sync.Mutex
	refs int
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
		changes:      changeSignal{ch: make(chan struct{})},
		sessionLocks: make(map[string]*sessionLock),
	}
}

// Authenticate resolves a Session Token to its Agent Session. Only tokens
// created through the session token role qualify: only the minter can use that
// role, and it pins one entity alias per session, so human and machine tokens
// are rejected without reading the entity.
func (s *Service) Authenticate(ctx context.Context, token string) (Session, error) {
	identity, err := s.bao.LookupSelf(ctx, token)
	if err != nil {
		var httpErr *openbao.HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusForbidden || httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusUnauthorized) {
			return Session{}, ErrInvalidToken
		}

		return Session{}, fmt.Errorf("look up session token: %w", err)
	}

	if identity.Role != s.config.SessionTokenRole || identity.EntityID == "" {
		return Session{}, ErrNotSession
	}

	sessionID := sanitizeText(identity.Meta["session_id"], maxMetaLength)
	if sessionID == "" {
		sessionID = identity.EntityID
	}

	return Session{EntityID: identity.EntityID, Display: store.SessionDisplay{
		ID:        sessionID,
		Title:     sanitizeText(identity.Meta["title"], maxMetaLength),
		Directory: sanitizeText(identity.Meta["directory"], maxMetaLength),
	}}, nil
}

// CreateRequest validates items and stores a Grant Request. token is the
// requester's Session Token; it is used for capabilities-self and never stored.
func (s *Service) CreateRequest(ctx context.Context, session Session, token, reason string, inputs []ItemInput) (store.GrantRequest, error) {
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

		item := store.Item{ID: itemID}
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
				items[index].Reason = "the session already has these capabilities"
			}
		}
	}

	request := store.GrantRequest{
		ID: requestID, EntityID: session.EntityID, Session: session.Display, Reason: reason,
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
		// Other sessions' requests are indistinguishable from missing ones.
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

// Grants lists active Grants, for one session or, with an empty entityID, all.
func (s *Service) Grants(ctx context.Context, entityID string) ([]store.Grant, error) {
	return s.store.ActiveGrants(ctx, entityID, s.now())
}

// Decide applies an Approver's decisions to items of one request, all or
// nothing: approvals become blocks of the session policy, written once, and
// every decision is stored in one transaction.
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

	unlock := s.lockSession(request.EntityID)
	request, grants, err := s.decide(ctx, approver, requestID, decisions)
	unlock()
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

// decide must run under the session lock. It re-reads the request so a
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

		if decision.TTL != "" && !decision.Approve {
			return store.GrantRequest{}, nil, invalid("ttl applies only to approvals")
		}

		item.DecidedAt = now
		if !decision.Approve {
			item.State = store.ItemRejected
			item.DecidedBy = approver
			continue
		}

		ttl, refusal, err := s.approvalTTL(*item, decision.TTL)
		if err != nil {
			return store.GrantRequest{}, nil, err
		}

		if refusal != "" {
			// A system decision, so no Approver is recorded.
			item.State = store.ItemRefused
			item.Reason = refusal
			continue
		}

		grantID, err := store.NewID()
		if err != nil {
			return store.GrantRequest{}, nil, err
		}

		// Whole seconds, because policy expirations are RFC 3339 seconds.
		expiresAt := now.Add(ttl).Truncate(time.Second)
		item.State, item.DecidedBy, item.GrantID, item.GrantExpires = store.ItemApproved, approver, grantID, expiresAt
		grants = append(grants, store.Grant{
			ID: grantID, RequestID: request.ID, ItemID: item.ID, EntityID: request.EntityID, Path: item.Path, Capabilities: item.Capabilities,
			Session: request.Session, CreatedAt: now, ExpiresAt: expiresAt, ApprovedBy: approver.Name,
		})
	}

	if len(grants) > 0 {
		active, err := s.store.ActiveGrants(ctx, request.EntityID, now)
		if err != nil {
			return store.GrantRequest{}, nil, err
		}

		if err := s.writePolicy(ctx, request.EntityID, append(active, grants...)); err != nil {
			return store.GrantRequest{}, nil, err
		}

		if err := s.attachPolicy(ctx, request.EntityID); err != nil {
			s.restorePolicy(ctx, request.EntityID)
			return store.GrantRequest{}, nil, err
		}
	}

	if err := s.store.DecideItems(ctx, request, grants); err != nil {
		if len(grants) > 0 {
			s.restorePolicy(ctx, request.EntityID)
		}

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

// Revoke removes a Grant's block from the session policy, which ends access
// immediately, and then records the revocation.
func (s *Service) Revoke(ctx context.Context, approver store.Approver, grantID string) error {
	grant, err := s.store.Grant(ctx, grantID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}

	if err != nil {
		return err
	}

	unlock := s.lockSession(grant.EntityID)
	err = s.revoke(ctx, approver, grant)
	unlock()
	if err != nil {
		return err
	}

	s.changes.notify()
	s.notify(func() error { return s.notifier.GrantChanged(context.WithoutCancel(ctx), grant.ID) })
	return nil
}

// revoke must run under the session lock.
func (s *Service) revoke(ctx context.Context, approver store.Approver, grant store.Grant) error {
	now := s.now()
	active, err := s.store.ActiveGrants(ctx, grant.EntityID, now)
	if err != nil {
		return err
	}

	remaining := slices.DeleteFunc(slices.Clone(active), func(other store.Grant) bool { return other.ID == grant.ID })
	if len(remaining) == len(active) {
		return conflict(grant.ID, "grant", grant.Path)
	}

	if err := s.writePolicy(ctx, grant.EntityID, remaining); err != nil {
		return err
	}

	if err := s.store.RevokeGrant(ctx, grant.ID, approver, now); err != nil {
		s.restorePolicy(ctx, grant.EntityID)
		if errors.Is(err, store.ErrStatusChanged) {
			return conflict(grant.ID, "grant", grant.Path)
		}

		return err
	}

	return nil
}

// writePolicy replaces the session policy with one block per Grant, or
// deletes it when no Grant is left. It must run under the session lock.
func (s *Service) writePolicy(ctx context.Context, entityID string, grants []store.Grant) error {
	if len(grants) == 0 {
		if err := s.bao.DeletePolicy(ctx, PolicyPrefix+entityID); err != nil {
			return fmt.Errorf("delete session policy: %w", err)
		}

		return nil
	}

	document, expiresAt := sessionPolicy(grants)
	if err := s.bao.WritePolicy(ctx, PolicyPrefix+entityID, document, expiresAt); err != nil {
		return fmt.Errorf("write session policy: %w", err)
	}

	return nil
}

// restorePolicy rewrites the session policy from the stored active Grants
// after OpenBao and the store diverged.
func (s *Service) restorePolicy(ctx context.Context, entityID string) {
	ctx = context.WithoutCancel(ctx)
	active, err := s.store.ActiveGrants(ctx, entityID, s.now())
	if err == nil {
		err = s.writePolicy(ctx, entityID, active)
	}

	if err != nil {
		s.logger.Error("restore session policy from stored grants", "entity", entityID, "error", err)
	}
}

// attachPolicy adds the session policy to the Session Identity, keeping
// policies an operator attached. The name is never detached: once the policy
// is deleted or expired it grants nothing, and leaving it saves entity writes.
func (s *Service) attachPolicy(ctx context.Context, entityID string) error {
	entity, err := s.bao.ReadEntity(ctx, entityID)
	if err != nil {
		return fmt.Errorf("read session entity: %w", err)
	}

	if slices.Contains(entity.Policies, PolicyPrefix+entityID) {
		return nil
	}

	if err := s.bao.SetEntityPolicies(ctx, entityID, append(entity.Policies, PolicyPrefix+entityID)); err != nil {
		return fmt.Errorf("update session entity policies: %w", err)
	}

	return nil
}

// sessionPolicy renders one path block per Grant, each with its own
// expiration, so a session needs one policy however many Grants it holds.
// JSON policies cannot repeat a path key, so it is HCL; json.Marshal quotes
// strings in a form HCL parses, and paths exclude the characters HCL would
// interpret. The policy expires with its last block.
func sessionPolicy(grants []store.Grant) (string, time.Time) {
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

// lockSession serializes session policy writes and decisions for one Agent
// Session. It is in-process, so one authorizer instance owns a database.
func (s *Service) lockSession(entityID string) func() {
	s.sessionLocksMu.Lock()
	lock := s.sessionLocks[entityID]
	if lock == nil {
		lock = &sessionLock{}
		s.sessionLocks[entityID] = lock
	}

	lock.refs++
	s.sessionLocksMu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		s.sessionLocksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			delete(s.sessionLocks, entityID)
		}

		s.sessionLocksMu.Unlock()
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
