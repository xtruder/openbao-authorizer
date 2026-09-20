// Package scanner discovers pending OpenBao control-group requests.
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/xtruder/openbao-authorizer/internal/approvalcontext"
	"github.com/xtruder/openbao-authorizer/internal/openbao"
	"github.com/xtruder/openbao-authorizer/internal/store"
)

// OpenBao is the read-only API surface used by the scanner.
type OpenBao interface {
	ListAccessors(context.Context) ([]string, error)
	ControlGroupRequest(context.Context, string) (openbao.ControlGroupRequest, error)
	Read(context.Context, string) (json.RawMessage, error)
}

// Sink persists discovered requests and reports whether they are new.
type Sink interface {
	Upsert(context.Context, string, openbao.ControlGroupRequest, store.UpsertOptions) (string, bool, error)
	ExpireMissing(context.Context, []string) ([]string, error)
}

// Notifier emits a notification for a newly discovered request.
type Notifier interface {
	NewRequest(context.Context, string, openbao.ControlGroupRequest) error
}

type statusNotifier interface {
	StatusChanged(context.Context, string, store.RequestStatus) error
}

// Scanner probes service-token accessors with bounded concurrency.
type Scanner struct {
	bao         OpenBao
	sink        Sink
	notifier    Notifier
	contexts    *approvalcontext.Resolver
	concurrency int
}

// New constructs a scanner.
func New(bao OpenBao, sink Sink, notifier Notifier, contexts *approvalcontext.Resolver, concurrency int) *Scanner {
	if concurrency < 1 {
		concurrency = 1
	}

	if contexts == nil {
		contexts, _ = approvalcontext.New(nil)
	}

	return &Scanner{bao: bao, sink: sink, notifier: notifier, contexts: contexts, concurrency: concurrency}
}

// Scan performs one complete accessor snapshot scan.
func (s *Scanner) Scan(ctx context.Context) error {
	accessors, err := s.bao.ListAccessors(ctx)
	if err != nil {
		return fmt.Errorf("list token accessors: %w", err)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var errorMu sync.Mutex
	var scanErrors []error

	worker := func() {
		defer wg.Done()
		for accessor := range jobs {
			request, requestErr := s.bao.ControlGroupRequest(ctx, accessor)
			if openbao.IsNotControlGroup(requestErr) {
				continue
			}

			if requestErr != nil {
				errorMu.Lock()
				scanErrors = append(scanErrors, fmt.Errorf("inspect accessor: %w", requestErr))
				errorMu.Unlock()
				continue
			}

			options := store.UpsertOptions{ApprovalContext: store.PreserveApprovalContext}
			if !request.Approved {
				options.ApprovalContext = store.ReplaceApprovalContext
				if contextPath, matched := s.contexts.Resolve(request.Path); matched {
					contextData, contextErr := s.bao.Read(ctx, contextPath)
					request.ApprovalContext = &openbao.ApprovalContext{Available: contextErr == nil, Data: contextData}
				}
			}

			id, isNew, sinkErr := s.sink.Upsert(ctx, accessor, request, options)
			if sinkErr != nil {
				errorMu.Lock()
				scanErrors = append(scanErrors, fmt.Errorf("store request: %w", sinkErr))
				errorMu.Unlock()
				continue
			}

			if isNew && s.notifier != nil {
				if notifyErr := s.notifier.NewRequest(ctx, id, request); notifyErr != nil {
					errorMu.Lock()
					scanErrors = append(scanErrors, fmt.Errorf("notify request: %w", notifyErr))
					errorMu.Unlock()
				}
			}
		}
	}

	wg.Add(s.concurrency)
	for range s.concurrency {
		go worker()
	}

	for _, accessor := range accessors {
		select {
		case jobs <- accessor:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return context.Cause(ctx)
		}
	}

	close(jobs)
	wg.Wait()
	expired, expireErr := s.sink.ExpireMissing(ctx, accessors)
	if expireErr != nil {
		scanErrors = append(scanErrors, fmt.Errorf("expire missing requests: %w", expireErr))
	} else if notifier, ok := s.notifier.(statusNotifier); ok {
		for _, id := range expired {
			if notifyErr := notifier.StatusChanged(ctx, id, store.RequestExpired); notifyErr != nil {
				scanErrors = append(scanErrors, fmt.Errorf("notify request status: %w", notifyErr))
			}
		}
	}

	return errors.Join(scanErrors...)
}
