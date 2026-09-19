package httpapi

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
)

// Event is a live application event delivered over SSE.
type Event struct {
	ID   uint64          `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// EventBus is a process-local fan-out bus. REST remains the source of truth.
type EventBus struct {
	next        atomic.Uint64
	mu          sync.RWMutex
	subscribers map[chan Event]struct{}
}

// NewEventBus creates an event bus.
func NewEventBus() *EventBus {
	return &EventBus{subscribers: make(map[chan Event]struct{})}
}

// Publish broadcasts an event without blocking scanner progress.
func (b *EventBus) Publish(eventType string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}

	event := Event{ID: b.next.Add(1), Type: eventType, Data: data}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for subscriber := range b.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}

	return nil
}

// Subscribe registers a bounded live-event channel.
func (b *EventBus) Subscribe() (<-chan Event, func()) {
	channel := make(chan Event, 16)
	b.mu.Lock()
	b.subscribers[channel] = struct{}{}
	b.mu.Unlock()
	return channel, func() {
		b.mu.Lock()
		if _, ok := b.subscribers[channel]; ok {
			delete(b.subscribers, channel)
			close(channel)
		}

		b.mu.Unlock()
	}
}
