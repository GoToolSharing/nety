// Package bus is the in-process publish/subscribe hub that carries live scan
// events from the scan runner to the WebSocket clients.
//
// Requirement R1 (docs/ARCHITECTURE.md) says no result may wait for the end of
// a scan, so the runner publishes here the moment a row is written. Delivery
// is best effort by design: a slow browser must never stall a scan, so a
// subscriber whose buffer is full misses events and is told how many (the UI
// then refetches the affected table rather than showing a stale view).
package bus

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/vaadata/nety/internal/model"
)

// DefaultBuffer is the per-subscriber queue depth.
const DefaultBuffer = 512

// Bus fans events out to subscribers, filtered by mission.
type Bus struct {
	mu     sync.RWMutex
	subs   map[int64]*Subscription
	nextID int64
	closed bool
}

// Subscription is one client's event stream.
type Subscription struct {
	id        int64
	missionID int64 // 0 = every mission
	ch        chan model.Event
	bus       *Bus
	dropped   atomic.Int64
	once      sync.Once
}

// New creates an empty bus.
func New() *Bus {
	return &Bus{subs: make(map[int64]*Subscription)}
}

// Subscribe returns a subscription receiving the events of one mission
// (missionID 0 subscribes to everything, used by the admin dashboard).
func (b *Bus) Subscribe(missionID int64, buffer int) *Subscription {
	if buffer <= 0 {
		buffer = DefaultBuffer
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextID++
	s := &Subscription{
		id:        b.nextID,
		missionID: missionID,
		ch:        make(chan model.Event, buffer),
		bus:       b,
	}
	if !b.closed {
		b.subs[s.id] = s
	} else {
		close(s.ch)
	}
	return s
}

// Publish delivers an event to every matching subscriber. It never blocks.
func (b *Bus) Publish(ev model.Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, s := range b.subs {
		if s.missionID != 0 && s.missionID != ev.MissionID {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			s.dropped.Add(1)
		}
	}
}

// PublishData is a convenience wrapper building the envelope.
func (b *Bus) PublishData(t model.EventType, missionID, scanID int64, data any) {
	b.Publish(model.Event{
		Type:      t,
		MissionID: missionID,
		ScanID:    scanID,
		Time:      time.Now().UTC(),
		Data:      data,
	})
}

// Subscribers reports how many streams are attached (status endpoint).
func (b *Bus) Subscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}

// Close shuts every subscription down.
func (b *Bus) Close() {
	b.mu.Lock()
	subs := b.subs
	b.subs = make(map[int64]*Subscription)
	b.closed = true
	b.mu.Unlock()
	for _, s := range subs {
		s.once.Do(func() { close(s.ch) })
	}
}

// C is the channel to range over. It is closed when the subscription ends.
func (s *Subscription) C() <-chan model.Event { return s.ch }

// Dropped reports how many events this subscriber missed because it could not
// keep up. A non-zero value tells the client to resynchronise.
func (s *Subscription) Dropped() int64 { return s.dropped.Load() }

// Close detaches the subscription.
func (s *Subscription) Close() {
	s.bus.mu.Lock()
	_, stillThere := s.bus.subs[s.id]
	delete(s.bus.subs, s.id)
	s.bus.mu.Unlock()
	if stillThere {
		s.once.Do(func() { close(s.ch) })
	}
}
