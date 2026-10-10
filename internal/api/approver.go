package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// approverService implements ApproverService; authorizeApprover has already
// checked same-origin and, except for GetLoginOptions and CreateSession, the
// session.
type approverService struct{ *server }

var requestFilters = map[authorizerv1.GrantRequestFilter]store.RequestFilter{
	authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_UNSPECIFIED: store.AllRequests,
	authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_PENDING:     store.PendingRequests,
	authorizerv1.GrantRequestFilter_GRANT_REQUEST_FILTER_DECIDED:     store.DecidedRequests,
}

func identityProto(value store.Session) *authorizerv1.Identity {
	return &authorizerv1.Identity{EntityId: value.EntityID, DisplayName: value.DisplayName}
}

func (a approverService) GetLoginOptions(context.Context, *connect.Request[authorizerv1.GetLoginOptionsRequest]) (*connect.Response[authorizerv1.GetLoginOptionsResponse], error) {
	return connect.NewResponse(a.loginOptions), nil
}

// CreateSession checks the Approver against OpenBao once and then revokes the
// token: the application session never calls OpenBao on the Approver's behalf,
// so removing the approver policy takes effect at the next sign-in.
func (a approverService) CreateSession(ctx context.Context, request *connect.Request[authorizerv1.CreateSessionRequest]) (*connect.Response[authorizerv1.CreateSessionResponse], error) {
	token := strings.TrimSpace(request.Msg.GetOpenbaoToken())
	keepToken := request.Msg.GetKeepToken()
	request.Msg.OpenbaoToken = ""
	if token == "" {
		return nil, invalidArgument("openbao_token is required")
	}

	identity, err := a.bao.LookupSelf(ctx, token)
	if err != nil && isAuthoritativeTokenError(err) {
		return nil, apiError(connect.CodeUnauthenticated, reasonInvalidToken, "OpenBao token is invalid")
	}

	// A token obtained just for this exchange is revoked, even when refused,
	// so no live credential outlives it. A pasted token may be the user's
	// working token, so it is kept; it is never stored either way.
	if !keepToken {
		if revokeErr := a.bao.RevokeSelf(context.WithoutCancel(ctx), token); revokeErr != nil {
			a.logger.Warn("revoke OpenBao approver token", "error", revokeErr)
		}
	}

	if err != nil {
		return nil, a.openBaoUnavailable("token lookup", err)
	}

	if identity.EntityID == "" {
		return nil, apiError(connect.CodePermissionDenied, reasonNotApprover, "OpenBao token is not associated with an identity entity")
	}

	if a.approverPolicy == "" || !identity.HasPolicy(a.approverPolicy) {
		return nil, apiError(connect.CodePermissionDenied, reasonNotApprover, "OpenBao identity is not an application approver")
	}

	if cookie, cookieErr := (&http.Request{Header: request.Header()}).Cookie(a.cookieName()); cookieErr == nil {
		a.deleteSession(ctx, cookie.Value)
	}

	sessionID, err := randomToken()
	if err != nil {
		return nil, a.internalError(err)
	}

	value := store.Session{ID: sessionID, EntityID: identity.EntityID, DisplayName: identity.DisplayName, ExpiresAt: time.Now().Add(a.sessionTTL)}
	if err := a.store.PutSession(ctx, value); err != nil {
		return nil, a.internalError(err)
	}

	response := connect.NewResponse(&authorizerv1.CreateSessionResponse{Identity: identityProto(value)})
	response.Header().Add("Set-Cookie", a.sessionCookie(sessionID, value.ExpiresAt).String())
	return response, nil
}

func (a approverService) GetSession(ctx context.Context, _ *connect.Request[authorizerv1.GetSessionRequest]) (*connect.Response[authorizerv1.GetSessionResponse], error) {
	return connect.NewResponse(&authorizerv1.GetSessionResponse{Identity: identityProto(approverFrom(ctx))}), nil
}

func (a approverService) Logout(ctx context.Context, _ *connect.Request[authorizerv1.LogoutRequest]) (*connect.Response[authorizerv1.LogoutResponse], error) {
	value := approverFrom(ctx)
	a.deleteSession(ctx, value.ID)
	if err := a.store.DeleteSubscriptionsByEntity(ctx, value.EntityID); err != nil {
		a.logger.Error("delete push subscriptions on logout", "error", err)
	}

	response := connect.NewResponse(&authorizerv1.LogoutResponse{})
	response.Header().Add("Set-Cookie", a.sessionCookie("", time.Time{}).String())
	return response, nil
}

func (a approverService) ListGrantRequests(ctx context.Context, request *connect.Request[authorizerv1.ListGrantRequestsRequest]) (*connect.Response[authorizerv1.ListGrantRequestsResponse], error) {
	filter, ok := requestFilters[request.Msg.GetFilter()]
	if !ok {
		return nil, invalidArgument("unknown grant request filter")
	}

	requests, err := a.grants.Requests(ctx, filter)
	if err != nil {
		return nil, a.internalError(err)
	}

	return connect.NewResponse(&authorizerv1.ListGrantRequestsResponse{GrantRequests: requestsProto(requests)}), nil
}

func (a approverService) DecideItems(ctx context.Context, request *connect.Request[authorizerv1.DecideItemsRequest]) (*connect.Response[authorizerv1.DecideItemsResponse], error) {
	decisions := make([]grants.Decision, 0, len(request.Msg.GetDecisions()))
	for _, decision := range request.Msg.GetDecisions() {
		verdict := decision.GetDecision()
		if verdict != authorizerv1.Decision_DECISION_APPROVE && verdict != authorizerv1.Decision_DECISION_REJECT {
			return nil, invalidArgument("decision must be approve or reject")
		}

		ttl, ok := durationInput(decision.GetTtl())
		if !ok {
			return nil, invalidArgument("ttl is not a valid duration")
		}

		decisions = append(decisions, grants.Decision{ItemID: decision.GetItemId(), Approve: verdict == authorizerv1.Decision_DECISION_APPROVE, TTL: ttl})
	}

	decided, err := a.grants.Decide(ctx, approverOf(approverFrom(ctx)), request.Msg.GetGrantRequestId(), decisions)
	if err != nil {
		return nil, a.grantError("grant decision", reasonItemNotPending, err)
	}

	return connect.NewResponse(&authorizerv1.DecideItemsResponse{GrantRequest: requestProto(decided, true)}), nil
}

func (a approverService) ListGrants(ctx context.Context, _ *connect.Request[authorizerv1.ListGrantsRequest]) (*connect.Response[authorizerv1.ListGrantsResponse], error) {
	active, err := a.grants.Grants(ctx, "")
	if err != nil {
		return nil, a.internalError(err)
	}

	return connect.NewResponse(&authorizerv1.ListGrantsResponse{Grants: grantsProto(active, true)}), nil
}

func (a approverService) RevokeGrant(ctx context.Context, request *connect.Request[authorizerv1.RevokeGrantRequest]) (*connect.Response[authorizerv1.RevokeGrantResponse], error) {
	if err := a.grants.Revoke(ctx, approverOf(approverFrom(ctx)), request.Msg.GetGrantId()); err != nil {
		return nil, a.grantError("grant revocation", reasonGrantNotActive, err)
	}

	return connect.NewResponse(&authorizerv1.RevokeGrantResponse{}), nil
}

func (a approverService) WatchEvents(ctx context.Context, _ *connect.Request[authorizerv1.WatchEventsRequest], stream *connect.ServerStream[authorizerv1.WatchEventsResponse]) error {
	current := approverFrom(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ended := a.watchSessionEnd(ctx, current)
	// Subscribe before the first snapshot so no change between them is missed.
	changes, unsubscribe := a.events.Subscribe()
	defer unsubscribe()
	watch := a.newStreamWatch(ctx, func() error {
		return stream.Send(&authorizerv1.WatchEventsResponse{Event: &authorizerv1.WatchEventsResponse_Heartbeat{Heartbeat: &authorizerv1.Heartbeat{}}})
	})
	defer watch.stop()

	var last *authorizerv1.DashboardSnapshot
	for {
		snapshot, err := a.snapshot(ctx)
		if err != nil {
			return err
		}

		// Unrelated wake-ups, e.g. grants announced twice, are not resent.
		if !proto.Equal(snapshot, last) {
			a.extendStreamDeadline(ctx)
			if err := stream.Send(&authorizerv1.WatchEventsResponse{Event: &authorizerv1.WatchEventsResponse_Snapshot{Snapshot: snapshot}}); err != nil {
				return err
			}

			last = snapshot
		}

		if err := watch.wait(changes, ended, nil); err != nil {
			return err
		}
	}
}

func (a approverService) snapshot(ctx context.Context) (*authorizerv1.DashboardSnapshot, error) {
	pending, err := a.grants.Requests(ctx, store.PendingRequests)
	if err != nil {
		return nil, a.internalError(err)
	}

	decided, err := a.grants.Requests(ctx, store.DecidedRequests)
	if err != nil {
		return nil, a.internalError(err)
	}

	active, err := a.grants.Grants(ctx, "")
	if err != nil {
		return nil, a.internalError(err)
	}

	return &authorizerv1.DashboardSnapshot{
		PendingRequests: requestsProto(pending), DecidedRequests: requestsProto(decided), ActiveGrants: grantsProto(active, true),
	}, nil
}

// watchSessionEnd returns a channel closed once the approver session is
// deleted (logout, re-login) or expires. Its goroutine exits with ctx.
func (a approverService) watchSessionEnd(ctx context.Context, current store.Session) <-chan struct{} {
	ended := make(chan struct{})
	go func() {
		expiry := time.NewTimer(time.Until(current.ExpiresAt))
		defer expiry.Stop()
		for {
			deletions := a.sessionDeletions()
			if _, err := a.store.Session(ctx, current.ID, time.Now()); errors.Is(err, store.ErrNotFound) {
				close(ended)
				return
			}

			select {
			case <-deletions:
			case <-expiry.C:
				close(ended)
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return ended
}

func (a approverService) GetPushPublicKey(context.Context, *connect.Request[authorizerv1.GetPushPublicKeyRequest]) (*connect.Response[authorizerv1.GetPushPublicKeyResponse], error) {
	return connect.NewResponse(&authorizerv1.GetPushPublicKeyResponse{PublicKey: a.vapidPublicKey}), nil
}

func (a approverService) RegisterPushSubscription(ctx context.Context, request *connect.Request[authorizerv1.RegisterPushSubscriptionRequest]) (*connect.Response[authorizerv1.RegisterPushSubscriptionResponse], error) {
	message := request.Msg
	endpoint, err := url.Parse(message.GetEndpoint())
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || len(message.GetEndpoint()) > 4096 {
		return nil, invalidArgument("invalid push subscription")
	}

	p256dh, p256dhErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(message.GetP256Dh(), "="))
	auth, authErr := base64.RawURLEncoding.DecodeString(strings.TrimRight(message.GetAuth(), "="))
	if p256dhErr != nil || authErr != nil || len(p256dh) != 65 || len(auth) != 16 {
		return nil, invalidArgument("invalid push subscription keys")
	}

	if a.validatePushEndpoint == nil {
		return nil, invalidArgument("push endpoint is not allowed")
	}

	if validateErr := a.validatePushEndpoint(ctx, message.GetEndpoint()); validateErr != nil {
		a.logger.Warn("rejected push endpoint", "host", endpoint.Hostname(), "error", validateErr)
		return nil, invalidArgument("push endpoint is not allowed")
	}

	value := approverFrom(ctx)
	if err := a.store.PutSubscription(ctx, store.Subscription{
		EntityID: value.EntityID, Endpoint: message.GetEndpoint(), P256DH: message.GetP256Dh(), Auth: message.GetAuth(), ExpiresAt: value.ExpiresAt,
	}); err != nil {
		return nil, a.internalError(err)
	}

	return connect.NewResponse(&authorizerv1.RegisterPushSubscriptionResponse{}), nil
}

func (a approverService) DeletePushSubscription(ctx context.Context, request *connect.Request[authorizerv1.DeletePushSubscriptionRequest]) (*connect.Response[authorizerv1.DeletePushSubscriptionResponse], error) {
	if request.Msg.GetEndpoint() == "" {
		return nil, invalidArgument("endpoint is required")
	}

	if err := a.store.DeleteSubscriptionForEntity(ctx, approverFrom(ctx).EntityID, request.Msg.GetEndpoint()); err != nil {
		return nil, a.internalError(err)
	}

	return connect.NewResponse(&authorizerv1.DeletePushSubscriptionResponse{}), nil
}
