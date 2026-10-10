package api

import (
	"context"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// grantService implements GrantService; authorizeRequester has already
// resolved the caller's Requester.
type grantService struct{ *server }

func (a grantService) CreateGrantRequest(ctx context.Context, request *connect.Request[authorizerv1.CreateGrantRequestRequest]) (*connect.Response[authorizerv1.CreateGrantRequestResponse], error) {
	caller := requesterFrom(ctx)
	inputs := make([]grants.ItemInput, 0, len(request.Msg.GetItems()))
	for _, item := range request.Msg.GetItems() {
		ttl, ok := durationInput(item.GetTtl())
		if !ok {
			return nil, invalidArgument("ttl is not a valid duration")
		}

		inputs = append(inputs, grants.ItemInput{Path: item.GetPath(), Capabilities: item.GetCapabilities(), TTL: ttl})
	}

	created, err := a.grants.CreateRequest(ctx, caller.Requester, caller.token, request.Msg.GetReason(), inputs)
	if err != nil {
		return nil, a.requesterGrantError("grant request", err)
	}

	return connect.NewResponse(&authorizerv1.CreateGrantRequestResponse{GrantRequest: requestProto(created, false)}), nil
}

func (a grantService) GetGrantRequest(ctx context.Context, request *connect.Request[authorizerv1.GetGrantRequestRequest]) (*connect.Response[authorizerv1.GetGrantRequestResponse], error) {
	current, err := a.grants.Request(ctx, requesterFrom(ctx).EntityID, request.Msg.GetId(), 0)
	if err != nil {
		return nil, a.requesterGrantError("grant request", err)
	}

	return connect.NewResponse(&authorizerv1.GetGrantRequestResponse{GrantRequest: requestProto(current, false)}), nil
}

func (a grantService) WatchGrantRequest(ctx context.Context, request *connect.Request[authorizerv1.WatchGrantRequestRequest], stream *connect.ServerStream[authorizerv1.WatchGrantRequestResponse]) error {
	caller := requesterFrom(ctx)
	entityID := caller.EntityID
	// Subscribe before the first read so no change between them is missed.
	changes, unsubscribe := a.events.Subscribe()
	defer unsubscribe()
	watch := a.newStreamWatch(ctx, func() error {
		return stream.Send(&authorizerv1.WatchGrantRequestResponse{Event: &authorizerv1.WatchGrantRequestResponse_Heartbeat{Heartbeat: &authorizerv1.Heartbeat{}}})
	})
	defer watch.stop()
	// A revoked token ends the stream at the next heartbeat; transient
	// OpenBao failures do not.
	reauthenticate := func() error {
		if _, err := a.authenticateRequester(ctx, caller.token); err != nil && connect.CodeOf(err) != connect.CodeUnavailable {
			return err
		}

		return nil
	}

	var last *authorizerv1.GrantRequest
	for {
		current, err := a.grants.Request(ctx, entityID, request.Msg.GetId(), 0)
		if err != nil {
			return a.requesterGrantError("grant request", err)
		}

		// Unrelated changes also wake the stream; only real ones are sent.
		if rendered := requestProto(current, false); !proto.Equal(rendered, last) {
			a.extendStreamDeadline(ctx)
			if err := stream.Send(&authorizerv1.WatchGrantRequestResponse{Event: &authorizerv1.WatchGrantRequestResponse_GrantRequest{GrantRequest: rendered}}); err != nil {
				return err
			}

			last = rendered
		}

		if !slices.ContainsFunc(current.Items, func(item store.Item) bool { return item.State == store.ItemPending }) {
			return nil
		}

		if err := watch.wait(changes, nil, reauthenticate); err != nil {
			return err
		}
	}
}

func (a grantService) ListMyGrants(ctx context.Context, _ *connect.Request[authorizerv1.ListMyGrantsRequest]) (*connect.Response[authorizerv1.ListMyGrantsResponse], error) {
	active, err := a.grants.Grants(ctx, requesterFrom(ctx).EntityID)
	if err != nil {
		return nil, a.internalError(err)
	}

	return connect.NewResponse(&authorizerv1.ListMyGrantsResponse{Grants: grantsProto(active, false)}), nil
}

func (a grantService) ListGrantables(ctx context.Context, _ *connect.Request[authorizerv1.ListGrantablesRequest]) (*connect.Response[authorizerv1.ListGrantablesResponse], error) {
	return connect.NewResponse(&authorizerv1.ListGrantablesResponse{Grantables: grantablesProto(a.grants.Grantables(ctx))}), nil
}

// streamWatch waits for the next change on a live stream while sending
// heartbeats in between.
type streamWatch struct {
	server    *server
	ctx       context.Context
	heartbeat *time.Ticker
	send      func() error
}

func (s *server) newStreamWatch(ctx context.Context, sendHeartbeat func() error) *streamWatch {
	return &streamWatch{server: s, ctx: ctx, heartbeat: time.NewTicker(s.heartbeatInterval), send: sendHeartbeat}
}

func (w *streamWatch) stop() { w.heartbeat.Stop() }

// wait returns nil once changes fires, and SESSION_EXPIRED once ended closes.
// onHeartbeat, when set, runs before each heartbeat and may end the stream.
func (w *streamWatch) wait(changes, ended <-chan struct{}, onHeartbeat func() error) error {
	for {
		select {
		case <-changes:
			return nil
		case <-ended:
			return sessionExpired()
		case <-w.heartbeat.C:
			if onHeartbeat != nil {
				if err := onHeartbeat(); err != nil {
					return err
				}
			}

			w.server.extendStreamDeadline(w.ctx)
			if err := w.send(); err != nil {
				return err
			}
		case <-w.ctx.Done():
			return w.ctx.Err()
		}
	}
}
