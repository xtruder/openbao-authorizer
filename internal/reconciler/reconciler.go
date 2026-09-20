// Package reconciler refreshes explicitly submitted OpenBao control-group requests.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// OpenBao reads explicitly submitted control-group requests.
type OpenBao interface {
	ControlGroupRequest(context.Context, string) (openbao.ControlGroupRequest, error)
}

// Store persists reconciled request and group state.
type Store interface {
	Groups(context.Context) ([]store.Group, error)
	Group(context.Context, string) (store.Group, error)
	GroupAccessors(context.Context, string) ([]store.RequestAccessor, error)
	UpdateRequest(context.Context, string, openbao.ControlGroupRequest, store.UpsertOptions) error
	TransitionStatus(context.Context, string, store.RequestStatus, store.RequestStatus) (bool, error)
	SetGroupStatus(context.Context, string, store.GroupStatus) error
}

// Notifier publishes group lifecycle transitions.
type Notifier interface {
	StatusChanged(context.Context, string, store.GroupStatus) error
}

// Reconciler refreshes pending approval groups from OpenBao.
type Reconciler struct {
	bao       OpenBao
	store     Store
	notifier  Notifier
	decisions *sync.Mutex
}

// New creates a reconciler.
func New(bao OpenBao, storage Store, notifier Notifier, decisions *sync.Mutex) *Reconciler {
	if decisions == nil {
		decisions = &sync.Mutex{}
	}

	return &Reconciler{bao: bao, store: storage, notifier: notifier, decisions: decisions}
}

// Reconcile refreshes all groups that can still change state.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	groups, err := r.store.Groups(ctx)
	if err != nil {
		return fmt.Errorf("list submitted approval groups: %w", err)
	}

	var reconcileErrors []error
	for _, group := range groups {
		if group.Status != store.GroupPending && group.Status != store.GroupApprovalFailed && group.Status != store.GroupRejectionFailed {
			continue
		}

		if err := r.reconcileGroup(ctx, group); err != nil {
			reconcileErrors = append(reconcileErrors, fmt.Errorf("reconcile approval group %s: %w", group.ID, err))
		}
	}

	return errors.Join(reconcileErrors...)
}

func (r *Reconciler) reconcileGroup(ctx context.Context, group store.Group) error {
	r.decisions.Lock()
	defer r.decisions.Unlock()
	group, err := r.store.Group(ctx, group.ID)
	if err != nil {
		return err
	}

	if group.Status != store.GroupPending && group.Status != store.GroupApprovalFailed && group.Status != store.GroupRejectionFailed {
		return nil
	}

	accessors, err := r.store.GroupAccessors(ctx, group.ID)
	if err != nil {
		return err
	}

	if len(accessors) != len(group.Requests) {
		return errors.New("stored group membership is inconsistent")
	}

	allApproved := true
	allRejected := true
	expired := false
	var reconcileErrors []error
	for index, member := range group.Requests {
		switch member.Status {
		case store.RequestPending:
		case store.RequestApproved:
			allRejected = false
			continue
		case store.RequestRejected:
			allApproved = false
			continue
		case store.RequestExpired:
			allApproved = false
			allRejected = false
			expired = true
			continue
		}

		allRejected = false
		fresh, err := r.bao.ControlGroupRequest(ctx, accessors[index].Accessor)
		if openbao.IsNotControlGroup(err) {
			if member.Status != store.RequestExpired {
				if _, transitionErr := r.store.TransitionStatus(ctx, member.ID, member.Status, store.RequestExpired); transitionErr != nil {
					reconcileErrors = append(reconcileErrors, transitionErr)
				}
			}

			expired = true
			allApproved = false
			continue
		}

		if err != nil {
			reconcileErrors = append(reconcileErrors, err)
			allApproved = false
			continue
		}

		if fresh.Entity.ID != group.Entity.ID || fresh.Operation != member.Operation || fresh.Path != member.Path {
			reconcileErrors = append(reconcileErrors, errors.New("submitted request identity, operation, or path changed"))
			allApproved = false
			continue
		}

		if err := r.store.UpdateRequest(ctx, member.ID, fresh, store.UpsertOptions{ApprovalContext: store.PreserveApprovalContext}); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		}

		allApproved = allApproved && fresh.Approved
	}

	status := group.Status
	switch {
	case expired:
		status = store.GroupExpired
	case allApproved:
		status = store.GroupApproved
	case allRejected:
		status = store.GroupRejected
	}

	if status != group.Status {
		if err := r.store.SetGroupStatus(ctx, group.ID, status); err != nil {
			reconcileErrors = append(reconcileErrors, err)
		} else if r.notifier != nil {
			if err := r.notifier.StatusChanged(ctx, group.ID, status); err != nil {
				reconcileErrors = append(reconcileErrors, err)
			}
		}
	}

	return errors.Join(reconcileErrors...)
}
