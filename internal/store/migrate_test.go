package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

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
	counts, err := s.TriageCounts(ctx, 1, 0, false)
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

// TestUpgradeFromAPreFindingTriageDatabase is the same upgrade path one
// release later: a database that already has service triage but not the
// finding columns must open, keep its findings, and gain the new ones.
func TestUpgradeFromAPreFindingTriageDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// A findings table as it looked before findings could be triaged.
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
		`CREATE TABLE findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL,
			network_id INTEGER NOT NULL, host_id INTEGER NOT NULL DEFAULT 0,
			service_id INTEGER NOT NULL DEFAULT 0, ip TEXT NOT NULL,
			port INTEGER NOT NULL DEFAULT 0, protocol TEXT NOT NULL DEFAULT '',
			check_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '',
			remediation TEXT NOT NULL DEFAULT '', refs TEXT NOT NULL DEFAULT '[]',
			first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
			last_scan_id INTEGER NOT NULL DEFAULT 0,
			UNIQUE (mission_id, network_id, ip, port, protocol, check_id))`,
		`INSERT INTO findings (mission_id, network_id, ip, port, protocol, check_id, title, severity, first_seen, last_seen)
		 VALUES (1, 1, '10.0.0.5', 445, 'tcp', 'smb-signing-not-required', 'SMB signing not required', 'medium', 1, 1)`,
		// The database is already past the service triage migration, so only
		// the finding one has anything left to do.
		`PRAGMA user_version = 1`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed old schema: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, nil)
	if err != nil {
		t.Fatalf("opening a pre-finding-triage database must work: %v", err)
	}
	defer s.Close()

	findings, err := s.ListFindings(ctx, FindingFilter{MissionID: 1})
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the existing finding to survive, got %d", len(findings))
	}
	if findings[0].Triage.Status != model.TriageTodo {
		t.Fatalf("migrated rows should default to todo, got %q", findings[0].Triage.Status)
	}

	// And triage works on it from there.
	status := model.TriageFlagged
	if _, err := s.SetFindingTriage(ctx, findings[0].ID, &status, nil, 1); err != nil {
		t.Fatalf("triage after migration: %v", err)
	}
	counts, err := s.FindingTriageCounts(ctx, 1, 0, false)
	if err != nil || counts[model.TriageFlagged] != 1 {
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

// TestUpgradeFromAPreHostTriageDatabase is the same upgrade path one release
// later again: a database that can triage services and findings but not hosts
// or machines must open, keep what it has, and gain the new columns.
func TestUpgradeFromAPreHostTriageDatabase(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "old.db")

	// Hosts and assets as they looked before either could be skipped.
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
		`CREATE TABLE hosts (
			id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL,
			network_id INTEGER NOT NULL, asset_id INTEGER NOT NULL DEFAULT 0,
			ip TEXT NOT NULL, mac TEXT NOT NULL DEFAULT '',
			vendor TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
			hostnames TEXT NOT NULL DEFAULT '[]', domain TEXT NOT NULL DEFAULT '',
			os TEXT NOT NULL DEFAULT '', ttl INTEGER NOT NULL DEFAULT 0,
			discovered_by TEXT NOT NULL DEFAULT '[]',
			first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
			last_scan_id INTEGER NOT NULL DEFAULT 0,
			UNIQUE (mission_id, network_id, ip))`,
		`INSERT INTO hosts (mission_id, network_id, ip, hostname, first_seen, last_seen)
		 VALUES (1, 1, '10.0.0.5', 'ws-042', 1, 1)`,
		`CREATE TABLE assets (
			id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id INTEGER NOT NULL,
			label TEXT NOT NULL DEFAULT '', hostname TEXT NOT NULL DEFAULT '',
			domain TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL DEFAULT 'unknown', tags TEXT NOT NULL DEFAULT '[]',
			notes TEXT NOT NULL DEFAULT '',
			first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)`,
		`INSERT INTO assets (id, mission_id, label, first_seen, last_seen)
		 VALUES (1, 1, 'ws-042', 1, 1)`,
		// Services and findings are already triageable in this database.
		`PRAGMA user_version = 2`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("seed old schema: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path, nil)
	if err != nil {
		t.Fatalf("opening a pre-host-triage database must work: %v", err)
	}
	defer s.Close()

	hosts, err := s.ListHosts(ctx, 1, 0)
	if err != nil {
		t.Fatalf("list after migration: %v", err)
	}
	if len(hosts) != 1 || hosts[0].Hostname != "ws-042" {
		t.Fatalf("expected the existing host to survive, got %+v", hosts)
	}
	if hosts[0].Triage.Status != model.TriageTodo {
		t.Fatalf("migrated rows should default to todo, got %q", hosts[0].Triage.Status)
	}
	asset, err := s.Asset(ctx, 1)
	if err != nil {
		t.Fatalf("asset after migration: %v", err)
	}
	if asset.Triage.Status != model.TriageTodo {
		t.Fatalf("migrated assets should default to todo, got %q", asset.Triage.Status)
	}

	// And skipping works on it from there, hosts and machines alike.
	status := model.TriageSkipped
	if _, err := s.SetHostTriage(ctx, hosts[0].ID, &status, nil, 1); err != nil {
		t.Fatalf("triage after migration: %v", err)
	}
	counts, err := s.HostTriageCounts(ctx, 1, 0)
	if err != nil || counts[model.TriageSkipped] != 1 {
		t.Fatalf("counts after migration: %+v err=%v", counts, err)
	}
	if _, _, err := s.SetAssetTriage(ctx, asset.ID, &status, nil, 1); err != nil {
		t.Fatalf("asset triage after migration: %v", err)
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

// A database that already carries every triage column but no service history
// has to gain the table and the stamp that says when the recording started,
// without disturbing anything that is already there.
func TestUpgradeToServiceChangeHistory(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v3.db")

	st, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	mis, err := st.CreateMission(ctx, model.Mission{Name: "before"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertService(ctx, model.Service{
		MissionID: mis.ID, NetworkID: 1, IP: "10.0.0.4", Port: 22,
		Protocol: model.TCP, State: model.PortOpen, Product: "OpenSSH", Version: "8.4p1",
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Put it back as it was before the history existed.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP TABLE service_changes`,
		`DELETE FROM settings WHERE key = 'service_changes_since'`,
		`PRAGMA user_version = 3`,
	} {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	raw.Close()

	st, err = Open(path, nil)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer st.Close()

	services, err := st.ListServices(ctx, ServiceFilter{MissionID: mis.ID})
	if err != nil || len(services) != 1 {
		t.Fatalf("the service did not survive the upgrade: %d, %v", len(services), err)
	}
	since, err := st.Setting(ctx, "service_changes_since")
	if err != nil || since == "" {
		t.Fatalf("the upgrade must stamp when the recording started: %q, %v", since, err)
	}

	// The table works, and a second open changes nothing.
	sv := services[0]
	sv.Version = "9.6p1"
	sv.LastScanID = 7
	if _, err := st.UpsertService(ctx, sv); err != nil {
		t.Fatal(err)
	}
	changes, err := st.serviceChangesBetween(ctx, mis.ID,
		time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got := changes[sv.ID]["version"].From; got != "8.4p1" {
		t.Fatalf("the previous version was not recorded: %q", got)
	}
	st.Close()
	if st, err = Open(path, nil); err != nil {
		t.Fatalf("reopening after the upgrade: %v", err)
	}
}
