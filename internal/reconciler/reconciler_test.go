package reconciler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

type fakeBao struct {
	requests map[string]openbao.ControlGroupRequest
	errors   map[string]error
	calls    []string
}

func (f *fakeBao) ControlGroupRequest(_ context.Context, accessor string) (openbao.ControlGroupRequest, error) {
	f.calls = append(f.calls, accessor)
	if err := f.errors[accessor]; err != nil {
		return openbao.ControlGroupRequest{}, err
	}

	return f.requests[accessor], nil
}

type notifier struct {
	statuses []store.GroupStatus
}

func (n *notifier) StatusChanged(_ context.Context, _ string, status store.GroupStatus) error {
	n.statuses = append(n.statuses, status)
	return nil
}

func TestReconcileOnlyRefreshesSubmittedGroups(t *testing.T) {
	t.Parallel()
	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	entity := openbao.Entity{ID: "requester"}
	group, _, err := database.CreateGroup(t.Context(), store.CreateGroupInput{
		IdempotencyKey: "one",
		Entity:         entity,
		Requests: []store.SubmittedRequest{
			{Accessor: "approved", Request: openbao.ControlGroupRequest{Operation: "read", Path: "secret/a", Entity: entity}},
			{Accessor: "expired", Request: openbao.ControlGroupRequest{Operation: "read", Path: "secret/b", Entity: entity}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{
			"approved": {Approved: true, Operation: "read", Path: "secret/a", Entity: entity},
		},
		errors: map[string]error{"expired": fmt.Errorf("%w: gone", openbao.ErrNotControlGroup)},
	}
	notifications := &notifier{}
	if reconcileErr := New(bao, database, notifications, nil).Reconcile(t.Context()); reconcileErr != nil {
		t.Fatal(reconcileErr)
	}

	got, err := database.Group(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != store.GroupExpired || got.Requests[0].Status != store.RequestApproved || got.Requests[1].Status != store.RequestExpired {
		t.Fatalf("reconciled group = %#v", got)
	}

	if len(notifications.statuses) != 1 || notifications.statuses[0] != store.GroupExpired {
		t.Fatalf("notifications = %#v", notifications.statuses)
	}
}

func TestReconcileSkipsApprovedMissingMemberAndKeepsGroupPending(t *testing.T) {
	t.Parallel()
	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	entity := openbao.Entity{ID: "requester"}
	approved := openbao.ControlGroupRequest{Approved: true, Operation: "read", Path: "secret/approved", Entity: entity}
	pending := openbao.ControlGroupRequest{
		Operation: "read",
		Path:      "secret/pending",
		Entity:    entity,
		ApprovalContext: &openbao.ApprovalContext{
			Available: true,
			Data:      json.RawMessage(`{"reviewed":"snapshot"}`),
		},
	}
	freshPending := pending
	freshPending.ApprovalContext = &openbao.ApprovalContext{Available: true, Data: json.RawMessage(`{"reviewed":"changed"}`)}
	group, _, err := database.CreateGroup(t.Context(), store.CreateGroupInput{
		IdempotencyKey: "approved-member-gone",
		Entity:         entity,
		Requests: []store.SubmittedRequest{
			{Accessor: "approved", Request: approved},
			{Accessor: "pending", Request: pending},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{"pending": freshPending},
		errors:   map[string]error{"approved": fmt.Errorf("%w: gone", openbao.ErrNotControlGroup)},
	}
	if reconcileErr := New(bao, database, nil, nil).Reconcile(t.Context()); reconcileErr != nil {
		t.Fatal(reconcileErr)
	}

	if len(bao.calls) != 1 || bao.calls[0] != "pending" {
		t.Fatalf("OpenBao calls = %#v", bao.calls)
	}

	got, err := database.Group(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != store.GroupPending || got.Requests[0].Status != store.RequestApproved || got.Requests[1].Status != store.RequestPending {
		t.Fatalf("reconciled group = %#v", got)
	}

	if string(got.Requests[1].ApprovalContext.Data) != `{"reviewed":"snapshot"}` {
		t.Fatalf("approval context changed during reconciliation: %s", got.Requests[1].ApprovalContext.Data)
	}
}

func TestReconcileRejectionFailedGroupSkipsRejectedMissingMember(t *testing.T) {
	t.Parallel()
	database, err := store.Open(filepath.Join(t.TempDir(), "app.db"), bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = database.Close() })
	entity := openbao.Entity{ID: "requester"}
	rejected := openbao.ControlGroupRequest{Operation: "read", Path: "secret/rejected", Entity: entity}
	pending := openbao.ControlGroupRequest{Operation: "read", Path: "secret/pending", Entity: entity}
	group, _, err := database.CreateGroup(t.Context(), store.CreateGroupInput{
		IdempotencyKey: "rejection-failed",
		Entity:         entity,
		Requests: []store.SubmittedRequest{
			{Accessor: "rejected", Request: rejected},
			{Accessor: "pending", Request: pending},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if changed, transitionErr := database.TransitionStatus(t.Context(), group.Requests[0].ID, store.RequestPending, store.RequestRejected); transitionErr != nil || !changed {
		t.Fatalf("reject member = %v, error = %v", changed, transitionErr)
	}

	if statusErr := database.SetGroupStatus(t.Context(), group.ID, store.GroupRejectionFailed); statusErr != nil {
		t.Fatal(statusErr)
	}

	bao := &fakeBao{
		requests: map[string]openbao.ControlGroupRequest{"pending": pending},
		errors:   map[string]error{"rejected": fmt.Errorf("%w: gone", openbao.ErrNotControlGroup)},
	}
	if reconcileErr := New(bao, database, nil, nil).Reconcile(t.Context()); reconcileErr != nil {
		t.Fatal(reconcileErr)
	}

	if len(bao.calls) != 1 || bao.calls[0] != "pending" {
		t.Fatalf("OpenBao calls = %#v", bao.calls)
	}

	got, err := database.Group(t.Context(), group.ID)
	if err != nil {
		t.Fatal(err)
	}

	if got.Status != store.GroupRejectionFailed || got.Requests[0].Status != store.RequestRejected || got.Requests[1].Status != store.RequestPending {
		t.Fatalf("reconciled group = %#v", got)
	}
}
