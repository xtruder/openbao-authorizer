// Package scanner discovers pending OpenBao control-group requests.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/xtruder/openbao-authorizer/internal/openbao"
)

// OpenBao is the read-only API surface used by the scanner.
type OpenBao interface {
	ListAccessors(context.Context) ([]string, error)
	ControlGroupRequest(context.Context, string) (openbao.ControlGroupRequest, error)
}

// Sink persists discovered requests and reports whether they are new.
type Sink interface {
	Upsert(context.Context, string, openbao.ControlGroupRequest) (bool, error)
}

// Notifier emits a notification for a newly discovered request.
type Notifier interface {
	NewRequest(context.Context, string, openbao.ControlGroupRequest) error
}

// Scanner probes service-token accessors with bounded concurrency.
type Scanner struct {
	bao         OpenBao
	sink        Sink
	notifier    Notifier
	concurrency int
}

// New constructs a scanner.
func New(bao OpenBao, sink Sink, notifier Notifier, concurrency int) *Scanner {
	if concurrency < 1 {
		concurrency = 1
	}

	return &Scanner{bao: bao, sink: sink, notifier: notifier, concurrency: concurrency}
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

			isNew, sinkErr := s.sink.Upsert(ctx, accessor, request)
			if sinkErr != nil {
				errorMu.Lock()
				scanErrors = append(scanErrors, fmt.Errorf("store request: %w", sinkErr))
				errorMu.Unlock()
				continue
			}

			if isNew && s.notifier != nil {
				if notifyErr := s.notifier.NewRequest(ctx, accessor, request); notifyErr != nil {
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

	return errors.Join(scanErrors...)
}
