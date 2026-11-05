package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// Moving a whole mission between installations.
//
// The case this exists for: a mission is finished, the machine it ran on is about to be
// wiped, and the engagement has to come back months later exactly as it was. A CSV or a
// report is a reading of the results; this is the results themselves, down to the paused
// work units of an unfinished scan and the note an operator wrote against one service.
//
// It is deliberately driven by the table list below rather than by the Go model. Every
// column a table has travels, whatever it is, so a column added later is carried without
// anyone remembering to update an exporter. The price is that the bundle is tied to the
// schema, which is why it carries a format version and the schema version it came from.

// TransferFormat is the bundle layout. Raise it only for a change an older NETY could not
// read correctly, since a bundle states it and an import refuses what it does not
// understand.
const TransferFormat = 1

// MissionBundle is a whole mission, portable between installations.
type MissionBundle struct {
	Format        int            `json:"format"`
	SchemaVersion int            `json:"schema_version"`
	Version       string         `json:"nety_version,omitempty"`
	ExportedAt    time.Time      `json:"exported_at"`
	MissionName   string         `json:"mission_name"`
	Users         []BundleUser   `json:"users"`
	Tables        []BundleTable  `json:"tables"`
	Checksum      string         `json:"checksum,omitempty"`
	Counts        map[string]int `json:"counts,omitempty"`
}

// BundleUser is an account some row of the bundle points at: the author of a triage note,
// whoever started a scan, a member of the mission. Only what is needed to find the same
// person again on the other installation travels, and no password hash ever does.
type BundleUser struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role,omitempty"`
}

// BundleTable is one table's rows, as the database holds them.
type BundleTable struct {
	Name    string   `json:"name"`
	Columns []string `json:"columns"`
	Rows    [][]any  `json:"rows"`
}

// transferTable describes how one table is collected and put back.
type transferTable struct {
	name string
	// where is the predicate that selects this mission's rows, with one placeholder for
	// the mission id.
	where string
	// refs maps a column to the table whose ids it holds. "users" is special: those are
	// resolved by username rather than by a remembered id, because the accounts on the
	// other installation are not the same accounts.
	refs map[string]string
	// referenced says other tables point at this one's ids, so the mapping from old id to
	// new has to be kept.
	referenced bool
	// required lists the reference columns a row cannot do without. Most reference
	// columns are allowed to be 0, meaning "none", but a row that exists only to join two
	// others has nothing left to say once one of them is gone, and the database refuses
	// it anyway.
	required []string
}

// transferTables is in insertion order: a table only ever refers to one listed before it,
// so a single pass can remap as it goes.
var transferTables = []transferTable{
	{name: "missions", where: "id = ?", referenced: true},
	{
		name: "mission_users", where: "mission_id = ?",
		refs:     map[string]string{"mission_id": "missions", "user_id": "users"},
		required: []string{"mission_id", "user_id"},
	},
	{
		name: "networks", where: "mission_id = ?", referenced: true,
		refs: map[string]string{"mission_id": "missions"},
	},
	{
		name: "scans", where: "mission_id = ?", referenced: true,
		refs: map[string]string{"mission_id": "missions", "network_id": "networks", "created_by": "users"},
	},
	{
		name: "scan_work", where: "scan_id IN (SELECT id FROM scans WHERE mission_id = ?)",
		refs:     map[string]string{"scan_id": "scans"},
		required: []string{"scan_id"},
	},
	{
		name: "scan_logs", where: "scan_id IN (SELECT id FROM scans WHERE mission_id = ?)",
		refs:     map[string]string{"scan_id": "scans"},
		required: []string{"scan_id"},
	},
	{
		name: "assets", where: "mission_id = ?", referenced: true,
		refs: map[string]string{"mission_id": "missions", "triage_by": "users"},
	},
	{
		name: "asset_keys", where: "mission_id = ?",
		refs:     map[string]string{"asset_id": "assets", "mission_id": "missions"},
		required: []string{"asset_id", "mission_id"},
	},
	{
		name: "asset_ips", where: "mission_id = ?",
		refs:     map[string]string{"asset_id": "assets", "mission_id": "missions", "network_id": "networks"},
		required: []string{"asset_id", "mission_id"},
	},
	{
		name: "hosts", where: "mission_id = ?", referenced: true,
		refs: map[string]string{
			"mission_id": "missions", "network_id": "networks", "asset_id": "assets",
			"triage_by": "users", "last_scan_id": "scans",
		},
	},
	{
		name: "services", where: "mission_id = ?", referenced: true,
		refs: map[string]string{
			"mission_id": "missions", "network_id": "networks", "host_id": "hosts",
			"triage_by": "users", "last_scan_id": "scans",
		},
	},
	{
		name: "service_changes", where: "mission_id = ?",
		refs: map[string]string{"mission_id": "missions", "service_id": "services", "scan_id": "scans"},
	},
	{
		name: "findings", where: "mission_id = ?", referenced: true,
		refs: map[string]string{
			"mission_id": "missions", "network_id": "networks", "host_id": "hosts",
			"service_id": "services", "triage_by": "users", "last_scan_id": "scans",
		},
	},
	{
		name: "reach_results", where: "mission_id = ?",
		refs: map[string]string{
			"mission_id": "missions", "scan_id": "scans",
			"source_network_id": "networks", "target_network_id": "networks",
			"target_host_id": "hosts", "target_service_id": "services",
		},
	},
}

// ExportMission collects a whole mission into a portable bundle.
//
// The audit log is deliberately left behind: it belongs to the installation and not to
// the mission, and a single entry of it can name work on another client. Sessions and
// password hashes never travel either.
func (s *Store) ExportMission(ctx context.Context, missionID int64, version string) (MissionBundle, error) {
	b := MissionBundle{
		Format:     TransferFormat,
		Version:    version,
		ExportedAt: time.Now().UTC(),
		Counts:     map[string]int{},
	}
	if err := s.r.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&b.SchemaVersion); err != nil {
		return b, fmt.Errorf("store: export: schema version: %w", err)
	}
	if err := s.r.QueryRowContext(ctx,
		`SELECT name FROM missions WHERE id = ?`, missionID).Scan(&b.MissionName); err != nil {
		if err == sql.ErrNoRows {
			return b, ErrNotFound
		}
		return b, fmt.Errorf("store: export: mission: %w", err)
	}

	userIDs := map[int64]bool{}
	for _, t := range transferTables {
		cols, err := s.tableColumnList(ctx, t.name)
		if err != nil {
			return b, err
		}
		if len(cols) == 0 {
			// A table this build does not have cannot be exported, and that is not an
			// error: it simply has nothing to say.
			continue
		}
		rows, err := s.r.QueryContext(ctx,
			`SELECT `+quoteCols(cols)+` FROM `+t.name+` WHERE `+t.where, missionID)
		if err != nil {
			return b, fmt.Errorf("store: export %s: %w", t.name, err)
		}
		dump := BundleTable{Name: t.name, Columns: cols}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return b, fmt.Errorf("store: export %s: %w", t.name, err)
			}
			for i, v := range vals {
				// Every text column comes back as bytes. Left as bytes it would travel
				// base64 encoded and come back a different type, so it is turned into the
				// string it already is.
				if raw, ok := v.([]byte); ok {
					vals[i] = string(raw)
				}
				if ref, ok := t.refs[cols[i]]; ok && ref == "users" {
					if id := asInt64(vals[i]); id > 0 {
						userIDs[id] = true
					}
				}
			}
			dump.Rows = append(dump.Rows, vals)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return b, fmt.Errorf("store: export %s: %w", t.name, err)
		}
		rows.Close()
		b.Tables = append(b.Tables, dump)
		b.Counts[t.name] = len(dump.Rows)
	}

	users, err := s.bundleUsers(ctx, userIDs)
	if err != nil {
		return b, err
	}
	b.Users = users
	b.Checksum = bundleChecksum(b)
	return b, nil
}

// bundleUsers describes the accounts the bundle's rows point at.
func (s *Store) bundleUsers(ctx context.Context, ids map[int64]bool) ([]BundleUser, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	list := make([]int64, 0, len(ids))
	for id := range ids {
		list = append(list, id)
	}
	sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })

	args := make([]any, len(list))
	for i, id := range list {
		args[i] = id
	}
	rows, err := s.r.QueryContext(ctx,
		`SELECT id, username, display_name, role FROM users WHERE id IN (?`+
			repeatComma(len(list)-1)+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: export users: %w", err)
	}
	defer rows.Close()
	var out []BundleUser
	for rows.Next() {
		var u BundleUser
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role); err != nil {
			return nil, fmt.Errorf("store: export users: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ImportOptions steers a restore.
type ImportOptions struct {
	// Name overrides the mission's name. Empty keeps the one in the bundle.
	Name string
	// CreateMissingUsers recreates, disabled and with no usable password, the accounts
	// the bundle names and this installation does not have. Without it their work is
	// imported unattributed, which on a report that has to say who tested what is a real
	// loss.
	CreateMissingUsers bool
	// OwnerID is added to the mission's members, so whoever imported it can open it even
	// when none of the original members exist here.
	OwnerID int64
}

// ImportResult says what came back, and what could not.
type ImportResult struct {
	MissionID int64          `json:"mission_id"`
	Name      string         `json:"name"`
	Counts    map[string]int `json:"counts"`
	// UsersCreated and UsersUnmatched name accounts, so an administrator can see whose
	// work was reattached and whose was not.
	UsersCreated   []string `json:"users_created,omitempty"`
	UsersUnmatched []string `json:"users_unmatched,omitempty"`
	// SkippedColumns names what the bundle carried and this build has no column for,
	// which is what a restore onto an older NETY loses.
	SkippedColumns []string `json:"skipped_columns,omitempty"`
	// DroppedRows counts, per table, the rows that lost something they could not exist
	// without, which in practice is a membership whose account is not on this
	// installation.
	DroppedRows map[string]int `json:"dropped_rows,omitempty"`
}

// ImportMission writes a bundle back as a new mission.
//
// It never merges into an existing mission and never overwrites one. A restore that
// silently reconciled two versions of the same engagement would be a very good way to
// lose evidence, so this always creates, and the operator deletes what they meant to
// replace.
func (s *Store) ImportMission(ctx context.Context, b MissionBundle, opts ImportOptions) (ImportResult, error) {
	res := ImportResult{Counts: map[string]int{}}
	if b.Format > TransferFormat {
		return res, fmt.Errorf("store: import: this bundle is format %d and this build understands up to %d",
			b.Format, TransferFormat)
	}
	if len(b.Tables) == 0 {
		return res, fmt.Errorf("store: import: the bundle has no table")
	}
	if b.Checksum != "" {
		if got := bundleChecksum(b); got != b.Checksum {
			return res, fmt.Errorf("store: import: the bundle is damaged, its contents do not match its checksum")
		}
	}
	byName := make(map[string]BundleTable, len(b.Tables))
	for _, t := range b.Tables {
		byName[t.Name] = t
	}
	if len(byName["missions"].Rows) != 1 {
		return res, fmt.Errorf("store: import: a bundle holds exactly one mission, this one holds %d",
			len(byName["missions"].Rows))
	}

	err := s.tx(ctx, func(tx *sql.Tx) error {
		users, created, unmatched, err := resolveBundleUsers(ctx, tx, b.Users, opts.CreateMissingUsers)
		if err != nil {
			return err
		}
		res.UsersCreated, res.UsersUnmatched = created, unmatched

		// ids maps a table to "the id this row had in the bundle" against "the id it has
		// here". Nothing in the bundle's numbering survives: this database has its own.
		ids := map[string]map[int64]int64{"users": users}
		skipped := map[string]bool{}

		for _, t := range transferTables {
			dump, ok := byName[t.name]
			if !ok || len(dump.Rows) == 0 {
				continue
			}
			target, err := txTableColumns(ctx, tx, t.name)
			if err != nil {
				return err
			}
			if len(target) == 0 {
				for _, c := range dump.Columns {
					skipped[t.name+"."+c] = true
				}
				continue
			}

			// Only the columns both sides have travel. A column this build does not know
			// is reported rather than dropped in silence.
			var use []int
			var cols []string
			for i, c := range dump.Columns {
				if c == "id" {
					continue
				}
				if !target[c] {
					skipped[t.name+"."+c] = true
					continue
				}
				use = append(use, i)
				cols = append(cols, c)
			}
			if len(cols) == 0 {
				continue
			}
			idAt := columnIndex(dump.Columns, "id")
			stmt, err := tx.PrepareContext(ctx,
				`INSERT INTO `+t.name+` (`+quoteCols(cols)+`) VALUES (?`+repeatComma(len(cols)-1)+`)`)
			if err != nil {
				return fmt.Errorf("store: import %s: %w", t.name, err)
			}
			for _, row := range dump.Rows {
				args := make([]any, len(use))
				drop := false
				for n, i := range use {
					v := normalizeBundleValue(row[i])
					if ref, isRef := t.refs[dump.Columns[i]]; isRef {
						v = remapID(ids, ref, v)
						if asInt64(v) == 0 && contains(t.required, dump.Columns[i]) {
							drop = true
						}
					}
					if t.name == "missions" && dump.Columns[i] == "name" && opts.Name != "" {
						v = opts.Name
					}
					args[n] = v
				}
				if drop {
					if res.DroppedRows == nil {
						res.DroppedRows = map[string]int{}
					}
					res.DroppedRows[t.name]++
					continue
				}
				out, err := stmt.ExecContext(ctx, args...)
				if err != nil {
					stmt.Close()
					return fmt.Errorf("store: import %s: %w", t.name, err)
				}
				if t.referenced && idAt >= 0 {
					newID, err := out.LastInsertId()
					if err != nil {
						stmt.Close()
						return fmt.Errorf("store: import %s: %w", t.name, err)
					}
					m, ok := ids[t.name]
					if !ok {
						m = map[int64]int64{}
						ids[t.name] = m
					}
					m[asInt64(normalizeBundleValue(row[idAt]))] = newID
				}
				res.Counts[t.name]++
			}
			stmt.Close()
		}

		for _, id := range ids["missions"] {
			res.MissionID = id
		}
		if res.MissionID == 0 {
			return fmt.Errorf("store: import: the mission was not written")
		}
		if err := tx.QueryRowContext(ctx,
			`SELECT name FROM missions WHERE id = ?`, res.MissionID).Scan(&res.Name); err != nil {
			return fmt.Errorf("store: import: %w", err)
		}
		// Whoever restored it has to be able to open it, even when not one of the
		// original members exists on this installation.
		if opts.OwnerID > 0 {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO mission_users (mission_id, user_id) VALUES (?, ?)
				 ON CONFLICT DO NOTHING`, res.MissionID, opts.OwnerID); err != nil {
				return fmt.Errorf("store: import: mission member: %w", err)
			}
		}
		res.SkippedColumns = sortedKeys(skipped)
		return nil
	})
	if err != nil {
		return ImportResult{}, err
	}
	return res, nil
}

// resolveBundleUsers matches the bundle's accounts to this installation's by username,
// which is the only name a person keeps across two databases.
func resolveBundleUsers(ctx context.Context, tx *sql.Tx, users []BundleUser, create bool) (map[int64]int64, []string, []string, error) {
	out := map[int64]int64{}
	var created, unmatched []string
	for _, u := range users {
		if strings.TrimSpace(u.Username) == "" {
			continue
		}
		var id int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM users WHERE username = ? COLLATE NOCASE`, u.Username).Scan(&id)
		switch {
		case err == nil:
			out[u.ID] = id
			continue
		case err != sql.ErrNoRows:
			return nil, nil, nil, fmt.Errorf("store: import: user %q: %w", u.Username, err)
		}
		if !create {
			unmatched = append(unmatched, u.Username)
			continue
		}
		// Disabled, and with a password hash that cannot be produced by any password, so
		// recreating the account restores the attribution without creating a way in.
		role := u.Role
		if role == "" {
			role = string(model.RoleOperator)
		}
		r, err := tx.ExecContext(ctx, `
			INSERT INTO users (username, display_name, role, password_hash, disabled, created_at)
			VALUES (?, ?, ?, '', 1, ?)`,
			u.Username, u.DisplayName, role, time.Now().UTC().UnixMilli())
		if err != nil {
			return nil, nil, nil, fmt.Errorf("store: import: create user %q: %w", u.Username, err)
		}
		if id, err = r.LastInsertId(); err != nil {
			return nil, nil, nil, fmt.Errorf("store: import: create user %q: %w", u.Username, err)
		}
		out[u.ID] = id
		created = append(created, u.Username)
	}
	return out, created, unmatched, nil
}

// remapID turns an id as the bundle numbered it into the id it has here. An id with no
// mapping becomes 0, which every one of these columns treats as "none" rather than as a
// dangling reference.
func remapID(ids map[string]map[int64]int64, table string, v any) any {
	old := asInt64(v)
	if old == 0 {
		return int64(0)
	}
	if m, ok := ids[table]; ok {
		if n, ok := m[old]; ok {
			return n
		}
	}
	return int64(0)
}

// normalizeBundleValue turns what JSON decoding produced back into something the driver
// can bind. Numbers arrive as json.Number so a millisecond timestamp or a large id
// survives the trip exactly.
func normalizeBundleValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, err := t.Float64()
		if err != nil {
			return t.String()
		}
		return f
	case float64:
		if t == float64(int64(t)) {
			return int64(t)
		}
		return t
	case bool:
		if t {
			return int64(1)
		}
		return int64(0)
	case []byte:
		return string(t)
	default:
		return v
	}
}

func asInt64(v any) int64 {
	switch t := normalizeBundleValue(v).(type) {
	case int64:
		return t
	case float64:
		return int64(t)
	case string:
		var n int64
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n
		}
	}
	return 0
}

// tableColumnList returns a table's columns in their declared order, or an empty slice
// when this build has no such table.
func (s *Store) tableColumnList(ctx context.Context, table string) ([]string, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return nil, fmt.Errorf("store: columns of %s: %w", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store: columns of %s: %w", table, err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func txTableColumns(ctx context.Context, tx *sql.Tx, table string) (map[string]bool, error) {
	cols, err := tableColumns(ctx, tx, table)
	if err != nil {
		return nil, fmt.Errorf("store: columns of %s: %w", table, err)
	}
	return cols, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func columnIndex(cols []string, want string) int {
	for i, c := range cols {
		if c == want {
			return i
		}
	}
	return -1
}

func quoteCols(cols []string) string {
	var sb strings.Builder
	for i, c := range cols {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(`"`)
		sb.WriteString(strings.ReplaceAll(c, `"`, `""`))
		sb.WriteString(`"`)
	}
	return sb.String()
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// bundleChecksum covers everything that describes the mission, so a truncated or edited
// file is refused instead of being restored as a partial engagement. The checksum field
// itself is left out of what it covers.
func bundleChecksum(b MissionBundle) string {
	b.Checksum = ""
	h := sha256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(b); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
