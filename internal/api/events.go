package api

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// pushTimeout bounds one Web Push fan-out, which runs after the agent's
// request has been answered.
const pushTimeout = 30 * time.Second

// EventBus is a process-local change signal for live streams. It carries no
// payload: streams re-read the store and send full snapshots, so coalescing
// several changes into one wake-up loses nothing.
type EventBus struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
}

// NewEventBus creates an event bus.
func NewEventBus() *EventBus {
	return &EventBus{subscribers: make(map[chan struct{}]struct{})}
}

// Publish wakes every subscriber without blocking the publisher.
func (b *EventBus) Publish() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for subscriber := range b.subscribers {
		select {
		case subscriber <- struct{}{}:
		default:
		}
	}
}

// Subscribe registers a change channel that holds at most one pending wake-up.
func (b *EventBus) Subscribe() (<-chan struct{}, func()) {
	channel := make(chan struct{}, 1)
	b.mu.Lock()
	b.subscribers[channel] = struct{}{}
	b.mu.Unlock()
	return channel, func() {
		b.mu.Lock()
		delete(b.subscribers, channel)
		b.mu.Unlock()
	}
}

// PushSender delivers a generic Web Push hint for a Grant Request.
type PushSender interface {
	NewRequest(context.Context, string) error
}

// Notifier wakes live streams on Grant changes and pushes new pending items.
type Notifier struct {
	Events *EventBus
	Push   PushSender
	Logger *slog.Logger
}

// RequestChanged wakes live streams, plus sends Web Push when the request
// added items no Approver has seen. Push runs in the background so slow push
// services never delay the agent that filed the request.
func (n *Notifier) RequestChanged(ctx context.Context, id string, newPending bool) error {
	n.Events.Publish()
	if !newPending || n.Push == nil {
		return nil
	}

	go func() {
		pushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pushTimeout)
		defer cancel()
		if err := n.Push.NewRequest(pushCtx, id); err != nil {
			n.logger().Warn("send push notifications", "error", err)
		}
	}()

	return nil
}

func (n *Notifier) logger() *slog.Logger {
	if n.Logger == nil {
		return slog.Default()
	}

	return n.Logger
}

// GrantChanged wakes live streams.
func (n *Notifier) GrantChanged(context.Context, string) error {
	n.Events.Publish()
	return nil
}
