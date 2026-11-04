package netif

import (
	"errors"
	"log/slog"
	"net/netip"
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
	keys    map[string]uint64
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

// trackKeyed registers an undo action under a stable key so that an explicit
// revert (DelRoute after AddRoute) can drop it from the registry.
func trackKeyed(key, desc string, undo func() error) {
	id := trackChange(desc, undo)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if tracker.keys == nil {
		tracker.keys = map[string]uint64{}
	}
	tracker.keys[key] = id
}

// forgetKeyed drops the undo registered under key, if any.
func forgetKeyed(key string) {
	tracker.mu.Lock()
	id, ok := tracker.keys[key]
	if ok {
		delete(tracker.keys, key)
	}
	tracker.mu.Unlock()
	if ok {
		forgetChange(id)
	}
}

// Keys under which the creating functions register their undo action. They
// live here, not in the Linux-only file, because the keyed-undo helpers below
// are part of the portable API.

func vlanKey(name string) string { return "vlan|" + name }

func addrKey(iface string, p netip.Prefix) string {
	return "addr|" + iface + "|" + p.String()
}

func routeKey(dst netip.Prefix, via netip.Addr, iface string) string {
	return "route|" + dst.String() + "|" + via.String() + "|" + iface
}

// undoKeyed runs the undo action registered under key, if there is one, and
// drops it. When there is none - because the thing already existed and NETY
// did not create it - it does nothing and reports no error.
//
// This is the safe way for a caller to unwind: it reverts exactly what NETY
// made and never touches a sub-interface, address or route that was already
// on the operator's machine.
func undoKeyed(key string) error {
	tracker.mu.Lock()
	id, ok := tracker.keys[key]
	if ok {
		delete(tracker.keys, key)
	}
	var undo func() error
	if ok {
		for i := range tracker.changes {
			if tracker.changes[i].id == id {
				undo = tracker.changes[i].undo
				tracker.changes = append(tracker.changes[:i], tracker.changes[i+1:]...)
				break
			}
		}
	}
	tracker.mu.Unlock()

	if undo == nil {
		return nil
	}
	return undo()
}

// UndoVLAN deletes the sub-interface only if NETY created it.
func UndoVLAN(name string) error { return undoKeyed(vlanKey(name)) }

// UndoAddr removes the address only if NETY added it.
func UndoAddr(iface string, p netip.Prefix) error { return undoKeyed(addrKey(iface, p)) }

// UndoRoute removes the route only if NETY added it.
func UndoRoute(dst netip.Prefix, via netip.Addr, iface string) error {
	return undoKeyed(routeKey(dst, via, iface))
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
	tracker.keys = nil
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
