package netif

import (
	"errors"
	"log/slog"
	"sync"
)

// Every function in this package that changes the system registers an undo
// action here. RestoreAll replays them in reverse order, so a sub-interface is
// only deleted after the routes and addresses that were added on it.
//
// The registry is process-wide on purpose: a panic or a SIGINT handler
// anywhere in NETY can call netif.RestoreAll() and be sure nothing NETY
// created is left behind on the operator's machine or on the client's switch.

type change struct {
	id   uint64
	desc string
	undo func() error
}

var tracker = struct {
	mu      sync.Mutex
	changes []change
	nextID  uint64
}{}

// trackChange registers an undo action and returns its id.
func trackChange(desc string, undo func() error) uint64 {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.nextID++
	id := tracker.nextID
	tracker.changes = append(tracker.changes, change{id: id, desc: desc, undo: undo})
	return id
}

// forgetChange drops a registered undo action without running it. It is called
// when the change has already been reverted explicitly (e.g. DelRoute after
// AddRoute), so RestoreAll does not try again.
func forgetChange(id uint64) {
	if id == 0 {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	for i := range tracker.changes {
		if tracker.changes[i].id == id {
			tracker.changes = append(tracker.changes[:i], tracker.changes[i+1:]...)
			return
		}
	}
}

// PendingChanges lists the system changes NETY has made and not yet undone,
// oldest first. The UI shows it so an operator can see what is still applied.
func PendingChanges() []string {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	out := make([]string, 0, len(tracker.changes))
	for _, c := range tracker.changes {
		out = append(out, c.desc)
	}
	return out
}

// RestoreAll undoes every change NETY made, most recent first, and clears the
// registry. It keeps going after a failure and returns the joined errors, so
// one stuck route never prevents the rest of the cleanup.
//
// It is idempotent and safe to call from a deferred recover.
func RestoreAll() error {
	return restoreAll(nil)
}

// RestoreAllLogged is RestoreAll with a logger for per-change reporting.
func RestoreAllLogged(log *slog.Logger) error { return restoreAll(log) }

func restoreAll(log *slog.Logger) error {
	tracker.mu.Lock()
	pending := tracker.changes
	tracker.changes = nil
	tracker.mu.Unlock()

	var errs []error
	for i := len(pending) - 1; i >= 0; i-- {
		c := pending[i]
		err := runUndo(c)
		if err != nil {
			errs = append(errs, errors.New("netif: restore "+c.desc+": "+err.Error()))
			if log != nil {
				log.Warn("netif cleanup failed", "change", c.desc, "err", err)
			}
			continue
		}
		if log != nil {
			log.Debug("netif cleanup", "change", c.desc)
		}
	}
	return errors.Join(errs...)
}

// runUndo isolates a panicking undo action so the rest of the cleanup runs.
func runUndo(c change) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic during undo")
		}
	}()
	if c.undo == nil {
		return nil
	}
	return c.undo()
}
