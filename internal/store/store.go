// Package store is the SQLite persistence layer of NETY.
//
// Results are written the moment they are discovered (see R1 in
// docs/ARCHITECTURE.md), and scan progress is tracked as persisted work units
// (see R2) so a scan survives a pause, a stop or a crash.
//
// Concurrency model: SQLite in WAL mode with two pools - a single-connection
// writer (SQLite allows one writer at a time anyway, serialising in Go avoids
// SQLITE_BUSY entirely) and a multi-connection reader pool. Every exported
// method is safe for concurrent use.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned on a unique-constraint violation that the caller is
// expected to handle (duplicate username, duplicate mission name...).
var ErrConflict = errors.New("store: already exists")

// Store owns the database handles.
type Store struct {
	w    *sql.DB
	r    *sql.DB
	path string
	log  *slog.Logger

	wmu sync.Mutex // serialises write transactions
}

// Open opens (and creates/migrates) the database at path.
func Open(path string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create directory: %w", err)
		}
	}

	writer, err := openDB(path, true)
	if err != nil {
		return nil, err
	}
	reader, err := openDB(path, false)
	if err != nil {
		writer.Close()
		return nil, err
	}

	s := &Store{w: writer, r: reader, path: path, log: log}
	if err := s.migrate(context.Background()); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func openDB(path string, writer bool) (*sql.DB, error) {
	// modernc.org/sqlite honours PRAGMA statements passed as _pragma query
	// parameters. busy_timeout guards against the rare writer/checkpoint race.
	dsn := path + "?_pragma=busy_timeout(10000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=temp_store(MEMORY)" +
		"&_pragma=cache_size(-20000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if writer {
		db.SetMaxOpenConns(1)
	} else {
		db.SetMaxOpenConns(max(4, runtime.NumCPU()))
	}
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping %s: %w", path, err)
	}
	return db, nil
}

// Close releases both pools.
func (s *Store) Close() error {
	var errs []error
	if s.w != nil {
		// A final checkpoint keeps the -wal file from growing across runs.
		_, _ = s.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		errs = append(errs, s.w.Close())
	}
	if s.r != nil {
		errs = append(errs, s.r.Close())
	}
	return errors.Join(errs...)
}

// Path is the database file location.
func (s *Store) Path() string { return s.path }

// migrate applies the schema and any incremental migration.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.w.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	var version int
	if err := s.w.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	for i := version; i < len(migrations); i++ {
		m := migrations[i]
		s.log.Info("applying database migration", "version", i+1, "name", m.name)
		if err := s.tx(ctx, func(tx *sql.Tx) error { return m.apply(ctx, tx) }); err != nil {
			return fmt.Errorf("store: migration %d (%s): %w", i+1, m.name, err)
		}
		if _, err := s.w.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			return fmt.Errorf("store: set schema version: %w", err)
		}
	}
	return nil
}

type migration struct {
	name  string
	apply func(ctx context.Context, tx *sql.Tx) error
}

// migrations are applied in order, once each. Append only - never edit or
// reorder an entry that has shipped.
//
// schema.sql only ever runs CREATE ... IF NOT EXISTS, so it creates new
// databases but cannot alter an existing table. Anything added to a table that
// has already shipped needs an entry here as well.
var migrations = []migration{
	{
		name: "service triage columns",
		apply: func(ctx context.Context, tx *sql.Tx) error {
			cols := map[string]string{
				"triage_status": "TEXT NOT NULL DEFAULT 'todo'",
				"triage_note":   "TEXT NOT NULL DEFAULT ''",
				"triage_by":     "INTEGER NOT NULL DEFAULT 0",
				"triage_at":     "INTEGER",
			}
			existing, err := tableColumns(ctx, tx, "services")
			if err != nil {
				return err
			}
			for name, decl := range cols {
				if existing[name] {
					continue
				}
				if _, err := tx.ExecContext(ctx,
					fmt.Sprintf(`ALTER TABLE services ADD COLUMN %s %s`, name, decl)); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx,
				`CREATE INDEX IF NOT EXISTS idx_services_triage ON services(mission_id, triage_status)`)
			return err
		},
	},
	{
		// Findings get the same operator-owned record as services. Written out
		// in full rather than sharing code with the entry above: a migration
		// is a historical record of what ran, and it should not change shape
		// because a later one needed something slightly different.
		name: "finding triage columns",
		apply: func(ctx context.Context, tx *sql.Tx) error {
			cols := map[string]string{
				"triage_status": "TEXT NOT NULL DEFAULT 'todo'",
				"triage_note":   "TEXT NOT NULL DEFAULT ''",
				"triage_by":     "INTEGER NOT NULL DEFAULT 0",
				"triage_at":     "INTEGER",
			}
			existing, err := tableColumns(ctx, tx, "findings")
			if err != nil {
				return err
			}
			for name, decl := range cols {
				if existing[name] {
					continue
				}
				if _, err := tx.ExecContext(ctx,
					fmt.Sprintf(`ALTER TABLE findings ADD COLUMN %s %s`, name, decl)); err != nil {
					return err
				}
			}
			_, err = tx.ExecContext(ctx,
				`CREATE INDEX IF NOT EXISTS idx_findings_triage ON findings(mission_id, triage_status)`)
			return err
		},
	},
	{
		// Hosts and assets get the same operator-owned record, which is how a
		// machine that is out of scope gets parked in one gesture instead of
		// service by service. Both tables are done here in one entry because
		// they are one feature: an asset is skipped by skipping its hosts, so
		// a database with the columns on only one of them would be broken.
		name: "host and asset triage columns",
		apply: func(ctx context.Context, tx *sql.Tx) error {
			cols := map[string]string{
				"triage_status": "TEXT NOT NULL DEFAULT 'todo'",
				"triage_note":   "TEXT NOT NULL DEFAULT ''",
				"triage_by":     "INTEGER NOT NULL DEFAULT 0",
				"triage_at":     "INTEGER",
			}
			for _, table := range []string{"hosts", "assets"} {
				existing, err := tableColumns(ctx, tx, table)
				if err != nil {
					return err
				}
				for name, decl := range cols {
					if existing[name] {
						continue
					}
					if _, err := tx.ExecContext(ctx,
						fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, name, decl)); err != nil {
						return err
					}
				}
				if _, err := tx.ExecContext(ctx, fmt.Sprintf(
					`CREATE INDEX IF NOT EXISTS idx_%s_triage ON %s(mission_id, triage_status)`,
					table, table)); err != nil {
					return err
				}
			}
			return nil
		},
	},
	{
		name: "service change history",
		apply: func(ctx context.Context, tx *sql.Tx) error {
			// Kept identical to the definition in schema.sql, which is what a
			// fresh database gets. A service row holds only its latest merged
			// description, so without this an upsert destroys the evidence
			// that a version ever changed.
			if _, err := tx.ExecContext(ctx, `
				CREATE TABLE IF NOT EXISTS service_changes (
				    id         INTEGER PRIMARY KEY AUTOINCREMENT,
				    mission_id INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
				    service_id INTEGER NOT NULL,
				    scan_id    INTEGER NOT NULL DEFAULT 0,
				    at         INTEGER NOT NULL,
				    field      TEXT    NOT NULL,
				    old_value  TEXT    NOT NULL DEFAULT '',
				    new_value  TEXT    NOT NULL DEFAULT ''
				)`); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx,
				`CREATE INDEX IF NOT EXISTS idx_service_changes ON service_changes(mission_id, at)`); err != nil {
				return err
			}
			// Stamp when the recording started. Everything scanned before
			// this moment has no history, and a diff reaching back past it
			// has to say so rather than report that nothing changed.
			_, err := tx.ExecContext(ctx,
				`INSERT INTO settings (key, value) VALUES ('service_changes_since', ?)
				 ON CONFLICT (key) DO NOTHING`,
				strconv.FormatInt(time.Now().UTC().UnixMilli(), 10))
			return err
		},
	},
	{
		// Addresses are stored as text, which cannot be ordered numerically
		// and cannot express a subnet. Every table that carries an address
		// gains a key derived from it (see internal/store/ipsort.go) that can
		// do both, and the rows already stored are given theirs here: a
		// database that has been in use for a week must come back sorted, not
		// empty at the top of every listing.
		name: "address sort key",
		apply: func(ctx context.Context, tx *sql.Tx) error {
			for _, table := range []string{"hosts", "services", "findings", "asset_ips"} {
				existing, err := tableColumns(ctx, tx, table)
				if err != nil {
					return err
				}
				if !existing["ip_sort"] {
					if _, err := tx.ExecContext(ctx, fmt.Sprintf(
						`ALTER TABLE %s ADD COLUMN ip_sort TEXT NOT NULL DEFAULT ''`,
						table)); err != nil {
						return err
					}
				}
				if err := backfillIPSort(ctx, tx, table); err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx, fmt.Sprintf(
					`CREATE INDEX IF NOT EXISTS idx_%s_ip_sort ON %s(mission_id, ip_sort)`,
					table, table)); err != nil {
					return err
				}
			}
			return nil
		},
	},
}

// backfillIPSort fills the new key for the rows a table already holds.
//
// The work is one UPDATE per distinct address rather than per row, because a
// mission has thousands of services spread over hundreds of addresses. The
// addresses are read into memory first: the update runs on the same single
// writer connection as the query that found them, and SQLite will not have a
// statement stepping over a table while another writes to it.
func backfillIPSort(ctx context.Context, tx *sql.Tx, table string) error {
	rows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT ip FROM `+table+` WHERE ip_sort = '' AND ip <> ''`)
	if err != nil {
		return err
	}
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return err
		}
		ips = append(ips, ip)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, ip := range ips {
		key := ipSortKey(ip)
		if key == "" {
			// Not an address we can place; leave the empty key rather than
			// invent an order for it.
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE `+table+` SET ip_sort = ? WHERE ip = ? AND ip_sort = ''`, key, ip); err != nil {
			return err
		}
	}
	return nil
}

// tableColumns lists the columns a table currently has.
func tableColumns(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

// tx runs fn in a write transaction, serialised against other writers.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.txLocked(ctx, fn)
}

func (s *Store) txLocked(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// ms converts a time to unix milliseconds; the zero time becomes 0.
func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// msPtr converts an optional time.
func msPtr(t *time.Time) *int64 {
	if t == nil || t.IsZero() {
		return nil
	}
	v := t.UnixMilli()
	return &v
}

// toTime converts unix milliseconds back to a time; 0 becomes the zero time.
func toTime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func toTimePtr(v sql.NullInt64) *time.Time {
	if !v.Valid || v.Int64 == 0 {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

// jsonEnc marshals v, returning "null"-safe defaults for empty containers so
// the columns never hold NULL.
func jsonEnc(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func jsonList[T any](v []T) string {
	if v == nil {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func jsonMap(v map[string]string) string {
	if v == nil {
		return "{}"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// jsonDec unmarshals a column into v, tolerating empty strings and NULL.
func jsonDec(s string, v any) {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return
	}
	_ = json.Unmarshal([]byte(s), v)
}

// jsonDecPtr decodes an optional JSON column into a newly allocated *T.
func jsonDecPtr[T any](s sql.NullString) *T {
	if !s.Valid {
		return nil
	}
	t := strings.TrimSpace(s.String)
	if t == "" || t == "null" {
		return nil
	}
	var v T
	if err := json.Unmarshal([]byte(t), &v); err != nil {
		return nil
	}
	return &v
}

// jsonEncPtr marshals an optional struct into a NULL-able column.
func jsonEncPtr(v any, isNil bool) any {
	if isNil {
		return nil
	}
	return jsonEnc(v)
}

// isUnique reports whether err is a unique-constraint violation.
func isUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE")
}

// Vacuum compacts the database. Safe to call while idle.
func (s *Store) Vacuum(ctx context.Context) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if _, err := s.w.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("store: vacuum: %w", err)
	}
	return nil
}

// Stats returns rough table counts, for the status endpoint.
func (s *Store) Stats(ctx context.Context) (map[string]int64, error) {
	tables := []string{"missions", "networks", "scans", "hosts", "services", "assets", "findings", "reach_results"}
	out := make(map[string]int64, len(tables))
	for _, t := range tables {
		var n int64
		if err := s.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+t).Scan(&n); err != nil {
			return nil, fmt.Errorf("store: count %s: %w", t, err)
		}
		out[t] = n
	}
	if fi, err := os.Stat(s.path); err == nil {
		out["db_bytes"] = fi.Size()
	}
	return out, nil
}
