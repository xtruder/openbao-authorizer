package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1/authorizerv1connect"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// authInterceptor authorizes every handler call, unary and streaming, before
// it reaches the service; the returned context carries the caller.
type authInterceptor func(ctx context.Context, procedure string, header http.Header) (context.Context, error)

func (authorize authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := authorize(ctx, request.Spec().Procedure, request.Header())
		if err != nil {
			return nil, err
		}

		return next(ctx, request)
	}
}

func (authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (authorize authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := authorize(ctx, conn.Spec().Procedure, conn.RequestHeader())
		if err != nil {
			return err
		}

		return next(ctx, conn)
	}
}

type requesterCaller struct {
	grants.Requester

	token string
}

type requesterKey struct{}

func requesterFrom(ctx context.Context) requesterCaller {
	value, _ := ctx.Value(requesterKey{}).(requesterCaller)
	return value
}

// authorizeRequester accepts only a bearer OpenBao token. Grant RPCs use no
// cookies, so browsers cannot be tricked into sending the credential.
func (s *server) authorizeRequester(ctx context.Context, _ string, header http.Header) (context.Context, error) {
	scheme, token, found := strings.Cut(header.Get("Authorization"), " ")
	token = strings.TrimSpace(token)
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, bearerChallenge(apiError(connect.CodeUnauthenticated, reasonInvalidToken, "a bearer OpenBao token is required"))
	}

	requester, err := s.authenticateRequester(ctx, token)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, requesterKey{}, requesterCaller{Requester: requester, token: token}), nil
}

func (s *server) authenticateRequester(ctx context.Context, token string) (grants.Requester, error) {
	requester, err := s.grants.Authenticate(ctx, token)
	switch {
	case errors.Is(err, grants.ErrInvalidToken):
		return grants.Requester{}, bearerChallenge(apiError(connect.CodeUnauthenticated, reasonInvalidToken, err.Error()))
	case errors.Is(err, grants.ErrNotRequester):
		return grants.Requester{}, apiError(connect.CodePermissionDenied, reasonNotRequester, err.Error())
	case err != nil:
		return grants.Requester{}, s.openBaoUnavailable("requester lookup", err)
	}

	return requester, nil
}

// streamHeaders keeps reverse proxies such as nginx from buffering server
// streams, which would hold back snapshots and heartbeats until the buffer
// fills. Cache-Control: no-store is already set on every API response.
type streamHeaders struct{}

func (streamHeaders) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc { return next }

func (streamHeaders) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (streamHeaders) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		conn.ResponseHeader().Set("X-Accel-Buffering", "no")
		return next(ctx, conn)
	}
}

func bearerChallenge(err *connect.Error) *connect.Error {
	err.Meta().Set("WWW-Authenticate", "Bearer")
	return err
}

type approverSessionKey struct{}

func approverFrom(ctx context.Context) store.Session {
	value, _ := ctx.Value(approverSessionKey{}).(store.Session)
	return value
}

// authorizeApprover requires a same-origin request on every approver RPC and,
// except for GetLoginOptions and CreateSession, a live session cookie. Streams are covered too, so a
// cross-site page cannot read dashboard snapshots. No CSRF token is needed:
// the cookie is SameSite=Strict, Connect's content types force a CORS
// preflight that is never granted, and the origin check rejects sibling sites.
func (s *server) authorizeApprover(ctx context.Context, procedure string, header http.Header) (context.Context, error) {
	if err := s.checkSameOrigin(ctx, header); err != nil {
		return nil, err
	}

	if procedure == authorizerv1connect.ApproverServiceGetLoginOptionsProcedure || procedure == authorizerv1connect.ApproverServiceCreateSessionProcedure {
		return ctx, nil
	}

	cookie, err := (&http.Request{Header: header}).Cookie(s.cookieName())
	if err != nil {
		return nil, sessionExpired()
	}

	value, err := s.store.Session(ctx, cookie.Value, time.Now())
	if errors.Is(err, store.ErrNotFound) {
		return nil, sessionExpired()
	}

	if err != nil {
		return nil, s.internalError(err)
	}

	return context.WithValue(ctx, approverSessionKey{}, value), nil
}

func (s *server) checkSameOrigin(ctx context.Context, header http.Header) error {
	if header.Get("Sec-Fetch-Site") == "cross-site" {
		return apiError(connect.CodePermissionDenied, reasonCrossOrigin, "cross-site request rejected")
	}

	origin := strings.TrimSuffix(header.Get("Origin"), "/")
	if origin == "" {
		return nil
	}

	expected := s.publicOrigin
	if expected == "" {
		scheme := "https"
		if s.insecureCookies {
			scheme = "http"
		}

		expected = scheme + "://" + requestInfoFrom(ctx).host
	}

	if origin != expected {
		return apiError(connect.CodePermissionDenied, reasonCrossOrigin, "origin rejected")
	}

	return nil
}

func approverOf(value store.Session) store.Approver {
	name := value.DisplayName
	if name == "" {
		name = value.EntityID
	}

	return store.Approver{EntityID: value.EntityID, Name: name}
}
