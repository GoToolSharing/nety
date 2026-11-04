package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// TestUpgradeFromAPreTriageDatabase is the upgrade path: someone has been
// using NETY for a week, pulls a new build, and their database must open.
//
// schema.sql runs against existing databases as well as new ones, so anything
// in it that references a column added later fails the startup for exactly the
// people who already have data. This builds a database in the old shape and
// opens it with the current code.
func TestUpgradeFromAPreTriageDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// A services table as it looked before triage existed.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE missions (
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
			client TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
			scope_cidrs TEXT NOT NULL DEFAULT '[]', exclude_cidrs TEXT NOT NULL DEFAULT '[]',
			archived INTEGER NOT NULL DEFAULT 0, created_by INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)`,
		`INSERT INTO missions (id, name, created_at, updated_at) VALUES (1, 'old mission', 1, 1)`,
		`CREATE TABLE services (
			id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL,
			network_id INTEGER NOT NULL, host_id INTEGER NOT NULL, ip TEXT NOT NULL,
			port INTEGER NOT NULL, protocol TEXT NOT NULL,
			state TEXT NOT NULL DEFAULT 'open', reason TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '', product TEXT NOT NULL DEFAULT '',
			version TEXT NOT NULL DEFAULT '', extra_info TEXT NOT NULL DEFAULT '',
			os_type TEXT NOT NULL DEFAULT '', cpes TEXT NOT NULL DEFAULT '[]',
			tunnel TEXT NOT NULL DEFAULT '', banner TEXT NOT NULL DEFAULT '',
			tls TEXT, http TEXT, ssh TEXT, extra TEXT NOT NULL DEFAULT '{}',
			confidence INTEGER NOT NULL DEFAULT 0, method TEXT NOT NULL DEFAULT '',
			first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
			last_scan_id INTEGER NOT NULL DEFAULT 0,
			UNIQUE (mission_id, network_id, ip, port, protocol))`,
		`INSERT INTO services (mission_id, network_id, host_id, ip, port, protocol, name, first_seen, last_seen)
		 VALUES (1, 1, 0, '10.0.0.5', 445, 'tcp', 'microsoft-ds', 1, 1)`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed old schema: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	// The current code must open it, migrate it, and keep the data.
	s, err := Open(path, nil)
	if err != nil {
		t.Fatalf("opening a pre-triage database must work: %v", err)
	}
	defer s.Close()

	services, err := s.ListServices(ctx, ServiceFilter{MissionID: 1})
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("expected the existing service to survive, got %d", len(services))
	}
	if services[0].Triage.Status != model.TriageTodo {
		t.Fatalf("migrated rows should default to todo, got %q", services[0].Triage.Status)
	}

	// And triage works on it from there.
	status := model.TriageDone
	if _, err := s.SetServiceTriage(ctx, services[0].ID, &status, nil, 1); err != nil {
		t.Fatalf("triage after migration: %v", err)
	}
	counts, err := s.TriageCounts(ctx, 1, 0)
	if err != nil || counts[model.TriageDone] != 1 {
		t.Fatalf("counts after migration: %+v err=%v", counts, err)
	}

	// Re-opening is a no-op, not a second migration.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path, nil)
	if err != nil {
		t.Fatalf("reopening must be idempotent: %v", err)
	}
	defer again.Close()
}
