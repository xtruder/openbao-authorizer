// Package api serves the ConnectRPC API: the bearer-token GrantService and the
// same-origin, cookie-authenticated ApproverService.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
	"github.com/xtruder/openbao-authorizer/internal/config"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

const (
	maxBodyBytes      = 1 << 20
	defaultSessionTTL = 168 * time.Hour
	// DefaultHeartbeatInterval keeps idle streams alive through proxies.
	DefaultHeartbeatInterval = 25 * time.Second
	// streamDeadlineSlack is added to the heartbeat interval when a stream
	// extends its write deadline, so a stalled client is cut off but a live
	// one never is.
	streamDeadlineSlack = 30 * time.Second
)

// OpenBao is the API surface needed to authenticate Approvers.
type OpenBao interface {
	RevokeSelf(context.Context, string) error
	LookupSelf(context.Context, string) (openbao.Identity, error)
}

// Store is the persistence surface needed by the API.
type Store interface {
	PutSession(context.Context, store.Session) error
	Session(context.Context, string, time.Time) (store.Session, error)
	DeleteSession(context.Context, string) error
	PutSubscription(context.Context, store.Subscription) error
	DeleteSubscriptionForEntity(context.Context, string, string) error
	DeleteSubscriptionsByEntity(context.Context, string) error
}

// Options configures the application HTTP handler.
type Options struct {
	OpenBao              OpenBao
	Store                Store
	Grants               *grants.Service
	Events               *EventBus
	Logger               *slog.Logger
	PublicOrigin         string
	VAPIDPublicKey       string
	ApproverPolicy       string
	ApproverLogin        config.ApproverLogin
	InsecureCookies      bool
	ValidatePushEndpoint func(context.Context, string) error
	// SessionTTL defaults to 168h.
	SessionTTL time.Duration
	// HeartbeatInterval defaults to DefaultHeartbeatInterval.
	HeartbeatInterval time.Duration
}

type server struct {
	bao                  OpenBao
	store                Store
	grants               *grants.Service
	events               *EventBus
	logger               *slog.Logger
	publicOrigin         string
	vapidPublicKey       string
	approverPolicy       string
	loginOptions         *authorizerv1.GetLoginOptionsResponse
	insecureCookies      bool
	validatePushEndpoint func(context.Context, string) error
	sessionTTL           time.Duration
	heartbeatInterval    time.Duration

	sessionsMu sync.Mutex
	// sessionDeleted is closed and replaced whenever a session is deleted, so
	// live streams end on logout or re-login without polling.
	sessionDeleted chan struct{}
}

// New constructs the HTTP API handler. It serves the services under /api, so
// it is meant to be mounted at /api/ on the application mux.
func New(options Options) http.Handler {
	logger := options.Logger
	if logger == nil {
		logger = slog.Default()
	}

	events := options.Events
	if events == nil {
		events = NewEventBus()
	}

	sessionTTL := options.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = defaultSessionTTL
	}

	heartbeat := options.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = DefaultHeartbeatInterval
	}

	s := &server{
		bao:                  options.OpenBao,
		store:                options.Store,
		grants:               options.Grants,
		events:               events,
		logger:               logger,
		publicOrigin:         strings.TrimSuffix(options.PublicOrigin, "/"),
		vapidPublicKey:       options.VAPIDPublicKey,
		approverPolicy:       options.ApproverPolicy,
		loginOptions:         loginOptionsProto(options.ApproverLogin),
		insecureCookies:      options.InsecureCookies,
		validatePushEndpoint: options.ValidatePushEndpoint,
		sessionTTL:           sessionTTL,
		heartbeatInterval:    heartbeat,
		sessionDeleted:       make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.Handle(authorizerv1connect.NewGrantServiceHandler(grantService{s},
		connect.WithReadMaxBytes(maxBodyBytes),
		connect.WithInterceptors(streamHeaders{}, authInterceptor(s.authorizeRequester)),
	))
	mux.Handle(authorizerv1connect.NewApproverServiceHandler(approverService{s},
		connect.WithReadMaxBytes(maxBodyBytes),
		connect.WithInterceptors(streamHeaders{}, authInterceptor(s.authorizeApprover)),
	))
	return s.securityHeaders(withRequestInfo(http.StripPrefix("/api", mux)))
}

// requestInfo carries what interceptors and streams need from the HTTP layer
// but connect does not expose: the Host for same-origin checks and the
// response controller for per-stream deadlines.
type requestInfo struct {
	host       string
	controller *http.ResponseController
}

type requestInfoKey struct{}

func withRequestInfo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := requestInfo{host: r.Host, controller: http.NewResponseController(w)}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, info)))
	})
}

func requestInfoFrom(ctx context.Context) requestInfo {
	info, _ := ctx.Value(requestInfoKey{}).(requestInfo)
	return info
}

// extendStreamDeadline pushes the write deadline past the next heartbeat.
// The server-wide write timeout would otherwise cut every stream short, while
// a client that stops reading is still cut off.
func (s *server) extendStreamDeadline(ctx context.Context) {
	if controller := requestInfoFrom(ctx).controller; controller != nil {
		_ = controller.SetWriteDeadline(time.Now().Add(s.heartbeatInterval + streamDeadlineSlack))
	}
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

func (s *server) sessionCookie(value string, expiresAt time.Time) *http.Cookie {
	// #nosec G124 -- Secure is disabled only in explicit local development mode.
	cookie := &http.Cookie{
		Name:     s.cookieName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.insecureCookies,
		SameSite: http.SameSiteStrictMode,
	}
	if value == "" {
		cookie.MaxAge = -1
		return cookie
	}

	cookie.MaxAge = int(time.Until(expiresAt).Seconds())
	cookie.Expires = expiresAt
	return cookie
}

func (s *server) deleteSession(ctx context.Context, id string) {
	if err := s.store.DeleteSession(ctx, id); err != nil {
		s.logger.Error("delete session", "error", err)
	}

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	close(s.sessionDeleted)
	s.sessionDeleted = make(chan struct{})
}

// sessionDeletions returns a channel closed on the next session deletion.
func (s *server) sessionDeletions() <-chan struct{} {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	return s.sessionDeleted
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}

	return hex.EncodeToString(buffer), nil
}
