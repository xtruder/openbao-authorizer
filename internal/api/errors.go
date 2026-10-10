package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	authorizerv1 "github.com/xtruder/openbao-authorizer/gen/go/openbao/authorizer/v1"
	"github.com/xtruder/openbao-authorizer/internal/grants"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

// Stable ErrorDetail reasons clients branch on.
const (
	reasonInvalidToken       = "INVALID_TOKEN"
	reasonSessionExpired     = "SESSION_EXPIRED"
	reasonNotRequester       = "NOT_REQUESTER"
	reasonSelfApproval       = "SELF_APPROVAL"
	reasonNotApprover        = "NOT_APPROVER"
	reasonCrossOrigin        = "CROSS_ORIGIN"
	reasonInvalidRequest     = "INVALID_REQUEST"
	reasonNotFound           = "NOT_FOUND"
	reasonItemNotPending     = "ITEM_NOT_PENDING"
	reasonGrantNotActive     = "GRANT_NOT_ACTIVE"
	reasonOpenBaoUnavailable = "OPENBAO_UNAVAILABLE"
)

func apiError(code connect.Code, reason, message string, ids ...string) *connect.Error {
	err := connect.NewError(code, errors.New(message))
	if detail, detailErr := connect.NewErrorDetail(&authorizerv1.ErrorDetail{Reason: reason, Ids: ids}); detailErr == nil {
		err.AddDetail(detail)
	}

	return err
}

func invalidArgument(message string) *connect.Error {
	return apiError(connect.CodeInvalidArgument, reasonInvalidRequest, message)
}

func sessionExpired() *connect.Error {
	return apiError(connect.CodeUnauthenticated, reasonSessionExpired, "authentication required")
}

func (s *server) internalError(err error) *connect.Error {
	s.logger.Error("request failed", "error", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal server error"))
}

// grantError maps grants.Service errors for Approvers. conflictReason tells a
// non-pending item apart from an inactive Grant, which the error alone does
// not.
func (s *server) grantError(action, conflictReason string, err error) *connect.Error {
	var invalidErr *grants.InvalidError
	var conflictErr *grants.ConflictError
	var httpErr *openbao.HTTPError
	switch {
	case errors.As(err, &invalidErr):
		return invalidArgument(invalidErr.Message)
	case errors.Is(err, grants.ErrNotFound):
		return apiError(connect.CodeNotFound, reasonNotFound, "not found")
	case errors.Is(err, grants.ErrSelfApproval):
		return apiError(connect.CodePermissionDenied, reasonSelfApproval, err.Error())
	case errors.As(err, &conflictErr):
		return apiError(connect.CodeFailedPrecondition, conflictReason, conflictErr.Error(), conflictErr.IDs...)
	case errors.As(err, &httpErr):
		s.logger.Error("OpenBao request failed", "action", action, "error", err)
		message := fmt.Sprintf("OpenBao %s failed (HTTP %d)", action, httpErr.StatusCode)
		if len(httpErr.Errors) > 0 {
			message += ": " + strings.Join(httpErr.Errors, "; ")
		}

		return apiError(connect.CodeUnavailable, reasonOpenBaoUnavailable, message)
	default:
		return s.internalError(err)
	}
}

// requesterGrantError hides OpenBao error text from Requesters: it comes from
// calls made with the authorizer's own token and may describe its policy.
func (s *server) requesterGrantError(action string, err error) *connect.Error {
	if _, ok := errors.AsType[*openbao.HTTPError](err); !ok {
		return s.grantError(action, reasonItemNotPending, err)
	}

	return s.openBaoUnavailable(action, err)
}

func (s *server) openBaoUnavailable(action string, err error) *connect.Error {
	s.logger.Error("OpenBao request failed", "action", action, "error", err)
	return apiError(connect.CodeUnavailable, reasonOpenBaoUnavailable, "OpenBao request failed")
}

// isAuthoritativeTokenError reports whether OpenBao rejected the token itself,
// as opposed to a transient transport or server failure.
func isAuthoritativeTokenError(err error) bool {
	var httpErr *openbao.HTTPError
	if !errors.As(err, &httpErr) {
		return false
	}

	switch httpErr.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}
