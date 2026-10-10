package api

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/internal/config"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

var itemStates = map[store.ItemState]authorizerv1.ItemState{
	store.ItemPending:        authorizerv1.ItemState_ITEM_STATE_PENDING,
	store.ItemAlreadyGranted: authorizerv1.ItemState_ITEM_STATE_ALREADY_GRANTED,
	store.ItemApproved:       authorizerv1.ItemState_ITEM_STATE_APPROVED,
	store.ItemRejected:       authorizerv1.ItemState_ITEM_STATE_REJECTED,
	store.ItemRefused:        authorizerv1.ItemState_ITEM_STATE_REFUSED,
	store.ItemExpired:        authorizerv1.ItemState_ITEM_STATE_EXPIRED,
	store.ItemRevoked:        authorizerv1.ItemState_ITEM_STATE_REVOKED,
}

func optionalTimestamp(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}

	return timestamppb.New(value)
}

var loginMethodTypes = map[string]authorizerv1.LoginMethodType{
	"token":    authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_TOKEN,
	"userpass": authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_USERPASS,
	"ldap":     authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_LDAP,
	"github":   authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_GITHUB,
	"oidc":     authorizerv1.LoginMethodType_LOGIN_METHOD_TYPE_OIDC,
}

func loginOptionsProto(login config.ApproverLogin) *authorizerv1.GetLoginOptionsResponse {
	rendered := &authorizerv1.GetLoginOptionsResponse{OpenbaoAddress: login.OpenBaoAddress, Namespace: login.Namespace}
	for _, method := range login.Methods {
		rendered.Methods = append(rendered.Methods, &authorizerv1.LoginMethod{
			Type: loginMethodTypes[method.Type], Mount: method.Mount, Label: method.Label, OidcRole: method.OIDCRole,
		})
	}

	return rendered
}

func requesterProto(entityID string, display store.RequesterDisplay) *authorizerv1.Requester {
	return &authorizerv1.Requester{Id: display.ID, Title: display.Title, Directory: display.Directory, EntityId: entityID, Rule: display.Rule}
}

// requestProto renders a request; forApprover adds the Requester and decision
// metadata that Requesters do not need.
func requestProto(request store.GrantRequest, forApprover bool) *authorizerv1.GrantRequest {
	rendered := &authorizerv1.GrantRequest{
		Id: request.ID, Reason: request.Reason, CreatedAt: timestamppb.New(request.CreatedAt),
		Items: make([]*authorizerv1.PermissionItem, 0, len(request.Items)),
	}
	if forApprover {
		rendered.Requester = requesterProto(request.EntityID, request.Requester)
	}

	for _, item := range request.Items {
		renderedItem := &authorizerv1.PermissionItem{
			Id: item.ID, Path: item.Path, Capabilities: item.Capabilities, State: itemStates[item.State], Reason: item.Reason,
		}
		if item.TTL > 0 {
			renderedItem.Ttl = durationpb.New(item.TTL)
		}

		switch item.State {
		case store.ItemPending:
			renderedItem.ExpiresAt = optionalTimestamp(request.PendingUntil)
		case store.ItemApproved, store.ItemRevoked:
			renderedItem.ExpiresAt = optionalTimestamp(item.GrantExpires)
		case store.ItemAlreadyGranted, store.ItemRejected, store.ItemRefused, store.ItemExpired:
		}

		if forApprover {
			renderedItem.DecidedBy = item.DecidedBy.Name
			renderedItem.DecidedAt = optionalTimestamp(item.DecidedAt)
			renderedItem.GrantId = item.GrantID
		}

		rendered.Items = append(rendered.Items, renderedItem)
	}

	return rendered
}

func requestsProto(requests []store.GrantRequest) []*authorizerv1.GrantRequest {
	rendered := make([]*authorizerv1.GrantRequest, 0, len(requests))
	for _, request := range requests {
		rendered = append(rendered, requestProto(request, true))
	}

	return rendered
}

func grantsProto(values []store.Grant, forApprover bool) []*authorizerv1.Grant {
	rendered := make([]*authorizerv1.Grant, 0, len(values))
	for _, grant := range values {
		renderedGrant := &authorizerv1.Grant{
			Id: grant.ID, ItemId: grant.ItemID, Path: grant.Path, Capabilities: grant.Capabilities,
			CreatedAt: timestamppb.New(grant.CreatedAt), ExpiresAt: timestamppb.New(grant.ExpiresAt),
		}
		if forApprover {
			renderedGrant.ApprovedBy = grant.ApprovedBy
			renderedGrant.Requester = requesterProto(grant.EntityID, grant.Requester)
		}

		rendered = append(rendered, renderedGrant)
	}

	return rendered
}

func grantablesProto(values []grants.Grantable) []*authorizerv1.Grantable {
	rendered := make([]*authorizerv1.Grantable, 0, len(values))
	for _, value := range values {
		rendered = append(rendered, &authorizerv1.Grantable{
			Name: value.Name, Path: value.Path, Capabilities: value.Capabilities, MaxTtl: durationpb.New(value.MaxTTL),
			Description: value.Description, Paths: value.Paths, DiscoverError: value.DiscoverError,
		})
	}

	return rendered
}

// durationInput converts an optional proto duration into the string form the
// grants package validates; an absent duration means "not requested".
func durationInput(value *durationpb.Duration) (string, bool) {
	if value == nil {
		return "", true
	}

	if value.CheckValid() != nil {
		return "", false
	}

	return value.AsDuration().String(), true
}
