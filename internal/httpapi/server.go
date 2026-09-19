// Package httpapi exposes the same-origin application API.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

const (
	maxBodyBytes      = 1 << 20
	defaultSessionTTL = 30 * 24 * time.Hour
)

// OpenBao is the API surface needed by authenticated handlers.
type OpenBao interface {
	LoginUserpass(context.Context, string, string) (openbao.AuthToken, error)
	RenewSelf(context.Context, string) error
	RevokeSelf(context.Context, string) error
	LookupSelf(context.Context, string) (openbao.Identity, error)
	Authorize(context.Context, string, string) (bool, error)
	ControlGroupRequest(context.Context, string) (openbao.ControlGroupRequest, error)
}

// Store is the persistence surface needed by the HTTP API.
type Store interface {
	List(context.Context) ([]store.Request, error)
	Accessor(context.Context, string) (string, error)
	Upsert(context.Context, string, openbao.ControlGroupRequest) (bool, error)
	SetApproved(context.Context, string, bool) error
	PutSession(context.Context, store.Session) error
	DeleteSession(context.Context, string) error
	PutSubscription(context.Context, store.Subscription) error
	DeleteSubscriptionForEntity(context.Context, string, string) error
	DeleteSubscriptionsByEntity(context.Context, string) error
}

// Options configures the application HTTP handler.
type Options struct {
	OpenBao              OpenBao
	Store                Store
	Events               *EventBus
	Logger               *slog.Logger
	PublicOrigin         string
	VAPIDPublicKey       string
	ApproverPolicy       string
	ExposeRequestData    bool
	InsecureCookies      bool
	Sessions             *Sessions
	ValidatePushEndpoint func(context.Context, string) error
}

type server struct {
	bao                  OpenBao
	store                Store
	events               *EventBus
	logger               *slog.Logger
	publicOrigin         string
	vapidPublicKey       string
	approverPolicy       string
	exposeRequestData    bool
	insecureCookies      bool
	sessions             *Sessions
	validatePushEndpoint func(context.Context, string) error
}

type session struct {
	Token     string
	CSRFToken string
	Identity  openbao.Identity
	ExpiresAt time.Time
}

// Sessions holds opaque server-side human-token sessions.
type Sessions struct {
	mu       sync.RWMutex
	sessions map[string]session
}

// NewSessions creates an empty session registry.
func NewSessions() *Sessions { return &Sessions{sessions: make(map[string]session)} }

// Restore loads encrypted durable sessions into the process-local registry.
func (s *Sessions) Restore(records []store.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, record := range records {
		s.sessions[record.ID] = session{
			Token: record.Token, CSRFToken: record.CSRFToken,
			Identity: record.Identity, ExpiresAt: record.ExpiresAt,
		}
	}
}

// AllActiveTokens returns each distinct token for a non-expired session.
func (s *Sessions) AllActiveTokens(now time.Time) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	unique := make(map[string]struct{})
	for _, value := range s.sessions {
		if now.Before(value.ExpiresAt) {
			unique[value.Token] = struct{}{}
		}
	}
	tokens := make([]string, 0, len(unique))
	for token := range unique {
		tokens = append(tokens, token)
	}
	return tokens
}

// DeleteToken removes sessions that use a revoked or expired OpenBao token.
func (s *Sessions) DeleteToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.sessions {
		if value.Token == token {
			delete(s.sessions, id)
		}
	}
}

// ActiveTokens returns every unexpired token for an entity. Push delivery must
// treat all of them as candidate proofs of an active, eligible session.
func (s *Sessions) ActiveTokens(entityID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	tokens := make([]string, 0, 1)
	for _, value := range s.sessions {
		if value.Identity.EntityID == entityID && now.Before(value.ExpiresAt) {
			tokens = append(tokens, value.Token)
		}
	}
	return tokens
}

// DeleteEntity removes every session belonging to an entity.
func (s *Sessions) DeleteEntity(entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, value := range s.sessions {
		if value.Identity.EntityID == entityID {
			delete(s.sessions, id)
		}
	}
}

// DeleteExpired removes expired sessions so stored OpenBao tokens do not linger
// in memory after their cookie is gone. Returns the entity IDs that lost their
// last session.
func (s *Sessions) DeleteExpired(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	lastForEntity := make(map[string]string)
	for id, value := range s.sessions {
		if now.After(value.ExpiresAt) {
			delete(s.sessions, id)
			continue
		}
		lastForEntity[value.Identity.EntityID] = id
	}
	removed := make([]string, 0, len(lastForEntity))
	for entityID := range lastForEntity {
		removed = append(removed, entityID)
	}
	return removed
}

// New constructs the HTTP API handler.
func New(options Options) http.Handler {
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}
	events := options.Events
	if events == nil {
		events = NewEventBus()
	}
	sessions := options.Sessions
	if sessions == nil {
		sessions = NewSessions()
	}
	s := &server{
		bao:                  options.OpenBao,
		store:                options.Store,
		events:               events,
		logger:               logger,
		publicOrigin:         strings.TrimSuffix(options.PublicOrigin, "/"),
		vapidPublicKey:       options.VAPIDPublicKey,
		approverPolicy:       options.ApproverPolicy,
		exposeRequestData:    options.ExposeRequestData,
		insecureCookies:      options.InsecureCookies,
		sessions:             sessions,
		validatePushEndpoint: options.ValidatePushEndpoint,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/session", s.login)
	mux.HandleFunc("GET /api/v1/session", s.authenticated(s.currentSession))
	mux.HandleFunc("DELETE /api/v1/session", s.authenticated(s.logout))
	mux.HandleFunc("GET /api/v1/requests", s.authenticated(s.listRequests))
	mux.HandleFunc("POST /api/v1/requests/{id}/approve", s.authenticated(s.approve))
	mux.HandleFunc("GET /api/v1/events", s.authenticated(s.streamEvents))
	mux.HandleFunc("GET /api/v1/push/public-key", s.authenticated(s.pushPublicKey))
	mux.HandleFunc("POST /api/v1/push/subscriptions", s.authenticated(s.putSubscription))
	mux.HandleFunc("DELETE /api/v1/push/subscriptions", s.authenticated(s.deleteSubscription))
	return s.securityHeaders(mux)
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(w, r, true) {
		return
	}
	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	payload.Username = strings.TrimSpace(payload.Username)
	if payload.Username == "" || payload.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	auth, err := s.bao.LoginUserpass(r.Context(), payload.Username, payload.Password)
	payload.Password = ""
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OpenBao username or password is invalid")
		return
	}
	keepToken := false
	defer func() {
		if !keepToken {
			if revokeErr := s.bao.RevokeSelf(r.Context(), auth.Token); revokeErr != nil {
				s.logger.Warn("revoke rejected OpenBao login token", "error", revokeErr)
			}
		}
	}()
	if !auth.Renewable {
		writeError(w, http.StatusServiceUnavailable, "OpenBao approver login must issue a renewable token")
		return
	}
	identity, err := s.bao.LookupSelf(r.Context(), auth.Token)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "OpenBao token is invalid")
		return
	}
	if identity.EntityID == "" {
		writeError(w, http.StatusForbidden, "OpenBao token is not associated with an identity entity")
		return
	}
	if s.approverPolicy == "" || !identity.HasPolicy(s.approverPolicy) {
		writeError(w, http.StatusForbidden, "OpenBao identity is not an application approver")
		return
	}
	sessionID, err := randomToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	csrfToken, err := randomToken()
	if err != nil {
		s.internalError(w, err)
		return
	}
	ttl := defaultSessionTTL
	value := session{Token: auth.Token, CSRFToken: csrfToken, Identity: identity, ExpiresAt: time.Now().Add(ttl)}
	if err := s.store.PutSession(r.Context(), store.Session{
		ID: sessionID, Token: value.Token, CSRFToken: value.CSRFToken,
		Identity: value.Identity, ExpiresAt: value.ExpiresAt,
	}); err != nil {
		s.internalError(w, err)
		return
	}
	s.sessions.mu.Lock()
	s.sessions.sessions[sessionID] = value
	s.sessions.mu.Unlock()
	keepToken = true
	// #nosec G124 -- Secure is disabled only in explicit local development mode.
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Expires:  value.ExpiresAt,
		HttpOnly: true,
		Secure:   !s.insecureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"identity": identity, "csrfToken": csrfToken})
}

func (s *server) currentSession(w http.ResponseWriter, _ *http.Request, value session) {
	writeJSON(w, http.StatusOK, map[string]any{"identity": value.Identity, "csrfToken": value.CSRFToken})
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, value session) {
	if !s.validMutationWithCSRF(w, r, value) {
		return
	}
	cookie, _ := r.Cookie(s.cookieName())
	if cookie != nil {
		s.deleteSession(r.Context(), cookie.Value)
	}
	if err := s.bao.RevokeSelf(r.Context(), value.Token); err != nil {
		s.logger.Warn("revoke OpenBao token on logout", "error", err)
	}
	if err := s.store.DeleteSubscriptionsByEntity(r.Context(), value.Identity.EntityID); err != nil {
		s.logger.Error("delete push subscriptions on logout", "error", err)
	}
	// #nosec G124 -- Secure is disabled only in explicit local development mode.
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !s.insecureCookies, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listRequests(w http.ResponseWriter, r *http.Request, _ session) {
	requests, err := s.store.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !s.exposeRequestData {
		for index := range requests {
			requests[index].Data = nil
		}
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *server) approve(w http.ResponseWriter, r *http.Request, value session) {
	if !s.validMutationWithCSRF(w, r, value) {
		return
	}
	accessor, err := s.store.Accessor(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "request not found")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	approved, err := s.bao.Authorize(r.Context(), value.Token, accessor)
	if err != nil {
		var httpErr *openbao.HTTPError
		if errors.As(err, &httpErr) && (httpErr.StatusCode == http.StatusBadRequest || httpErr.StatusCode == http.StatusForbidden) {
			writeError(w, http.StatusForbidden, "OpenBao rejected this approval")
			return
		}
		s.internalError(w, err)
		return
	}
	fresh, err := s.bao.ControlGroupRequest(r.Context(), accessor)
	if err == nil {
		_, err = s.store.Upsert(r.Context(), accessor, fresh)
		approved = fresh.Approved
	} else {
		err = s.store.SetApproved(r.Context(), r.PathValue("id"), approved)
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.events.Publish("status", map[string]any{"id": r.PathValue("id"), "approved": approved})
	requests, err := s.store.List(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	for _, request := range requests {
		if request.ID == r.PathValue("id") {
			if !s.exposeRequestData {
				request.Data = nil
			}
			writeJSON(w, http.StatusOK, request)
			return
		}
	}
	writeError(w, http.StatusNotFound, "request not found")
}

func (s *server) streamEvents(w http.ResponseWriter, r *http.Request, value session) {
	cookie, cookieErr := r.Cookie(s.cookieName())
	if cookieErr != nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	sessionID := cookie.Value
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	channel, unsubscribe := s.events.Subscribe()
	defer unsubscribe()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	sessionLive := time.NewTimer(time.Until(value.ExpiresAt))
	defer sessionLive.Stop()
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case event := <-channel:
			_, _ = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.ID, event.Type, event.Data)
			flusher.Flush()
		case <-heartbeat.C:
			// A stream stays authorized only while its application session
			// still exists; logout or entity wipe ends it immediately.
			s.sessions.mu.RLock()
			_, alive := s.sessions.sessions[sessionID]
			s.sessions.mu.RUnlock()
			if !alive {
				return
			}
			identity, err := s.bao.LookupSelf(r.Context(), value.Token)
			if err != nil || !identity.HasPolicy(s.approverPolicy) {
				return
			}
			_, _ = fmt.Fprint(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-sessionLive.C:
			s.deleteSession(r.Context(), sessionID)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *server) pushPublicKey(w http.ResponseWriter, _ *http.Request, _ session) {
	if s.vapidPublicKey == "" {
		writeError(w, http.StatusNotFound, "Web Push is not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"publicKey": s.vapidPublicKey})
}

func (s *server) putSubscription(w http.ResponseWriter, r *http.Request, value session) {
	if !s.validMutationWithCSRF(w, r, value) {
		return
	}
	var payload struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256DH string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	endpoint, err := url.Parse(payload.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || len(payload.Endpoint) > 4096 {
		writeError(w, http.StatusBadRequest, "invalid push subscription")
		return
	}
	p256dh, p256dhErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload.Keys.P256DH, "="))
	auth, authErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload.Keys.Auth, "="))
	if p256dhErr != nil || authErr != nil || len(p256dh) != 65 || len(auth) != 16 {
		writeError(w, http.StatusBadRequest, "invalid push subscription keys")
		return
	}
	if s.validatePushEndpoint == nil {
		writeError(w, http.StatusBadRequest, "push endpoint is not allowed")
		return
	}
	if validateErr := s.validatePushEndpoint(r.Context(), payload.Endpoint); validateErr != nil {
		s.logger.Warn("rejected push endpoint", "host", endpoint.Hostname(), "error", validateErr)
		writeError(w, http.StatusBadRequest, "push endpoint is not allowed")
		return
	}
	if err := s.store.PutSubscription(r.Context(), store.Subscription{
		EntityID: value.Identity.EntityID, Endpoint: payload.Endpoint, P256DH: payload.Keys.P256DH, Auth: payload.Keys.Auth, ExpiresAt: value.ExpiresAt,
	}); err != nil {
		s.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) deleteSubscription(w http.ResponseWriter, r *http.Request, value session) {
	if !s.validMutationWithCSRF(w, r, value) {
		return
	}
	var payload struct {
		Endpoint string `json:"endpoint"`
	}
	if !decodeJSON(w, r, &payload) || payload.Endpoint == "" {
		return
	}
	if err := s.store.DeleteSubscriptionForEntity(r.Context(), value.Identity.EntityID, payload.Endpoint); err != nil {
		s.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) authenticated(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(s.cookieName())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		s.sessions.mu.RLock()
		value, ok := s.sessions.sessions[cookie.Value]
		s.sessions.mu.RUnlock()
		if !ok || time.Now().After(value.ExpiresAt) {
			if ok {
				s.deleteSession(r.Context(), cookie.Value)
			}
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		identity, lookupErr := s.bao.LookupSelf(r.Context(), value.Token)
		if lookupErr != nil {
			s.deleteSession(r.Context(), cookie.Value)
			writeError(w, http.StatusUnauthorized, "OpenBao session is no longer valid")
			return
		}
		if !identity.HasPolicy(s.approverPolicy) {
			s.deleteSession(r.Context(), cookie.Value)
			writeError(w, http.StatusForbidden, "OpenBao identity is no longer an application approver")
			return
		}
		value.Identity = identity
		// Refresh only when the same session still exists; a concurrent logout
		// or entity wipe must not be resurrected here.
		s.sessions.mu.Lock()
		if current, exists := s.sessions.sessions[cookie.Value]; exists && current.CSRFToken == value.CSRFToken {
			s.sessions.sessions[cookie.Value] = value
		}
		s.sessions.mu.Unlock()
		next(w, r, value)
	}
}

func (s *server) deleteSession(ctx context.Context, id string) {
	s.sessions.mu.Lock()
	delete(s.sessions.sessions, id)
	s.sessions.mu.Unlock()
	if err := s.store.DeleteSession(ctx, id); err != nil {
		s.logger.Error("delete durable session", "error", err)
	}
}

func (s *server) validMutationWithCSRF(w http.ResponseWriter, r *http.Request, value session) bool {
	if !s.validMutation(w, r, true) {
		return false
	}
	if !constantTimeEqual(r.Header.Get("X-CSRF-Token"), value.CSRFToken) {
		writeError(w, http.StatusForbidden, "invalid CSRF token")
		return false
	}
	return true
}

func (s *server) validMutation(w http.ResponseWriter, r *http.Request, requireJSON bool) bool {
	if requireJSON {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return false
		}
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeError(w, http.StatusForbidden, "cross-site request rejected")
		return false
	}
	origin := strings.TrimSuffix(r.Header.Get("Origin"), "/")
	if origin != "" {
		expected := s.publicOrigin
		if expected == "" {
			scheme := "https"
			if s.insecureCookies {
				scheme = "http"
			}
			expected = scheme + "://" + r.Host
		}
		if origin != expected {
			writeError(w, http.StatusForbidden, "origin rejected")
			return false
		}
	}
	return true
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *server) cookieName() string {
	if s.insecureCookies {
		return "openbao-authorizer-session"
	}
	return "__Host-openbao-authorizer-session"
}

func (s *server) internalError(w http.ResponseWriter, err error) {
	s.logger.Error("request failed", "error", err)
	writeError(w, http.StatusInternalServerError, "internal server error")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, output any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range len(left) {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
