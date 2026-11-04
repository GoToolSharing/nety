package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// Assets are the long-lived identities that survive IP changes between scan
// days. The correlator (internal/identity) decides what matches what; this
// file only stores and loads the result.

const assetCols = `id, mission_id, label, hostname, domain, os, kind, tags, notes,
	first_seen, last_seen`

func scanAssetRow(sc interface{ Scan(...any) error }) (model.Asset, error) {
	var (
		a           model.Asset
		tags        string
		first, last int64
	)
	err := sc.Scan(&a.ID, &a.MissionID, &a.Label, &a.Hostname, &a.Domain, &a.OS,
		&a.Kind, &tags, &a.Notes, &first, &last)
	if err != nil {
		return model.Asset{}, err
	}
	jsonDec(tags, &a.Tags)
	a.FirstSeen, a.LastSeen = toTime(first), toTime(last)
	return a, nil
}

// SaveAsset inserts a new asset (ID == 0) or updates an existing one, together
// with its keys and IPs. Keys and IPs are merged, never truncated: an asset
// accumulates evidence across scans.
func (s *Store) SaveAsset(ctx context.Context, a model.Asset) (model.Asset, error) {
	now := time.Now().UTC()
	if a.FirstSeen.IsZero() {
		a.FirstSeen = now
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = now
	}
	if a.Kind == "" {
		a.Kind = model.AssetUnknown
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if a.ID == 0 {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO assets (mission_id, label, hostname, domain, os, kind, tags,
				                    notes, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				a.MissionID, a.Label, a.Hostname, a.Domain, a.OS, string(a.Kind),
				jsonList(a.Tags), a.Notes, ms(a.FirstSeen), ms(a.LastSeen))
			if err != nil {
				return err
			}
			if a.ID, err = res.LastInsertId(); err != nil {
				return err
			}
		} else {
			if _, err := tx.ExecContext(ctx, `
				UPDATE assets SET label = ?, hostname = ?, domain = ?, os = ?, kind = ?,
				    tags = ?, notes = ?, last_seen = ?
				WHERE id = ?`,
				a.Label, a.Hostname, a.Domain, a.OS, string(a.Kind), jsonList(a.Tags),
				a.Notes, ms(a.LastSeen), a.ID); err != nil {
				return err
			}
		}

		keyStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO asset_keys (asset_id, mission_id, kind, value, source, confidence,
			                        first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (asset_id, kind, value) DO UPDATE SET
			    source = excluded.source,
			    confidence = MAX(asset_keys.confidence, excluded.confidence),
			    last_seen = excluded.last_seen`)
		if err != nil {
			return err
		}
		defer keyStmt.Close()
		for _, k := range a.Keys {
			if k.Value == "" {
				continue
			}
			first, last := k.FirstSeen, k.LastSeen
			if first.IsZero() {
				first = now
			}
			if last.IsZero() {
				last = now
			}
			if _, err := keyStmt.ExecContext(ctx, a.ID, a.MissionID, string(k.Kind), k.Value,
				k.Source, k.Confidence, ms(first), ms(last)); err != nil {
				return err
			}
		}

		ipStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO asset_ips (asset_id, mission_id, network_id, ip, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (asset_id, network_id, ip) DO UPDATE SET last_seen = excluded.last_seen`)
		if err != nil {
			return err
		}
		defer ipStmt.Close()
		for _, ip := range a.IPs {
			if ip.IP == "" {
				continue
			}
			first, last := ip.FirstSeen, ip.LastSeen
			if first.IsZero() {
				first = now
			}
			if last.IsZero() {
				last = now
			}
			if _, err := ipStmt.ExecContext(ctx, a.ID, a.MissionID, ip.NetworkID, ip.IP,
				ms(first), ms(last)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return model.Asset{}, fmt.Errorf("store: save asset: %w", err)
	}
	return a, nil
}

// Asset loads one asset with its keys and IPs.
func (s *Store) Asset(ctx context.Context, id int64) (model.Asset, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+assetCols+` FROM assets WHERE id = ?`, id)
	a, err := scanAssetRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Asset{}, ErrNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("store: asset: %w", err)
	}
	if err := s.loadAssetDetails(ctx, []*model.Asset{&a}); err != nil {
		return model.Asset{}, err
	}
	return a, nil
}

// ListAssets returns every asset of a mission with keys and IPs attached.
// The correlator needs this full list to resolve an observation.
func (s *Store) ListAssets(ctx context.Context, missionID int64) ([]model.Asset, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+assetCols+` FROM assets WHERE mission_id = ? ORDER BY label, id`, missionID)
	if err != nil {
		return nil, fmt.Errorf("store: list assets: %w", err)
	}
	defer rows.Close()
	var out []model.Asset
	for rows.Next() {
		a, err := scanAssetRow(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list assets: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ptrs := make([]*model.Asset, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	if err := s.loadAssetDetails(ctx, ptrs); err != nil {
		return nil, err
	}
	return out, nil
}

// loadAssetDetails fills Keys and IPs for the given assets in two queries.
func (s *Store) loadAssetDetails(ctx context.Context, assets []*model.Asset) error {
	if len(assets) == 0 {
		return nil
	}
	byID := make(map[int64]*model.Asset, len(assets))
	ids := make([]any, 0, len(assets))
	for _, a := range assets {
		byID[a.ID] = a
		ids = append(ids, a.ID)
	}
	placeholders := `?` + repeatComma(len(ids)-1)

	keyRows, err := s.r.QueryContext(ctx,
		`SELECT asset_id, kind, value, source, confidence, first_seen, last_seen
		 FROM asset_keys WHERE asset_id IN (`+placeholders+`) ORDER BY confidence DESC, kind`, ids...)
	if err != nil {
		return fmt.Errorf("store: asset keys: %w", err)
	}
	for keyRows.Next() {
		var (
			assetID     int64
			k           model.AssetKey
			first, last int64
		)
		if err := keyRows.Scan(&assetID, &k.Kind, &k.Value, &k.Source, &k.Confidence, &first, &last); err != nil {
			keyRows.Close()
			return fmt.Errorf("store: asset keys: %w", err)
		}
		k.FirstSeen, k.LastSeen = toTime(first), toTime(last)
		if a := byID[assetID]; a != nil {
			a.Keys = append(a.Keys, k)
		}
	}
	keyRows.Close()
	if err := keyRows.Err(); err != nil {
		return err
	}

	ipRows, err := s.r.QueryContext(ctx,
		`SELECT asset_id, network_id, ip, first_seen, last_seen
		 FROM asset_ips WHERE asset_id IN (`+placeholders+`) ORDER BY network_id, ip`, ids...)
	if err != nil {
		return fmt.Errorf("store: asset ips: %w", err)
	}
	defer ipRows.Close()
	for ipRows.Next() {
		var (
			assetID     int64
			ip          model.AssetIP
			first, last int64
		)
		if err := ipRows.Scan(&assetID, &ip.NetworkID, &ip.IP, &first, &last); err != nil {
			return fmt.Errorf("store: asset ips: %w", err)
		}
		ip.FirstSeen, ip.LastSeen = toTime(first), toTime(last)
		if a := byID[assetID]; a != nil {
			a.IPs = append(a.IPs, ip)
		}
	}
	return ipRows.Err()
}

// AssetByKey finds the asset holding a given identity key, if any. Used as a
// fast path by the correlator for very strong keys.
func (s *Store) AssetByKey(ctx context.Context, missionID int64, kind model.EvidenceKind, value string) (model.Asset, error) {
	var id int64
	err := s.r.QueryRowContext(ctx,
		`SELECT asset_id FROM asset_keys WHERE mission_id = ? AND kind = ? AND value = ?
		 ORDER BY confidence DESC LIMIT 1`, missionID, string(kind), value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Asset{}, ErrNotFound
	}
	if err != nil {
		return model.Asset{}, fmt.Errorf("store: asset by key: %w", err)
	}
	return s.Asset(ctx, id)
}

// DeleteAsset removes an asset and unlinks its hosts.
func (s *Store) DeleteAsset(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET asset_id = 0 WHERE asset_id = ?`, id); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete asset: %w", err)
		}
		return affected(res)
	})
}

// MergeAssets folds src into dst (keys, IPs, hosts) and deletes src.
func (s *Store) MergeAssets(ctx context.Context, dstID, srcID int64) error {
	if dstID == srcID {
		return nil
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_keys (asset_id, mission_id, kind, value, source, confidence, first_seen, last_seen)
			SELECT ?, mission_id, kind, value, source, confidence, first_seen, last_seen
			FROM asset_keys WHERE asset_id = ?
			ON CONFLICT (asset_id, kind, value) DO UPDATE SET
			    confidence = MAX(asset_keys.confidence, excluded.confidence),
			    last_seen = MAX(asset_keys.last_seen, excluded.last_seen)`,
			dstID, srcID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO asset_ips (asset_id, mission_id, network_id, ip, first_seen, last_seen)
			SELECT ?, mission_id, network_id, ip, first_seen, last_seen
			FROM asset_ips WHERE asset_id = ?
			ON CONFLICT (asset_id, network_id, ip) DO UPDATE SET
			    last_seen = MAX(asset_ips.last_seen, excluded.last_seen)`,
			dstID, srcID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET asset_id = ? WHERE asset_id = ?`, dstID, srcID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE assets SET first_seen = MIN(first_seen, (SELECT first_seen FROM assets WHERE id = ?)),
			                  last_seen  = MAX(last_seen,  (SELECT last_seen  FROM assets WHERE id = ?))
			WHERE id = ?`, srcID, srcID, dstID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM assets WHERE id = ?`, srcID)
		return err
	})
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

// Audit records an action for traceability (who ran what against which client).
func (s *Store) Audit(ctx context.Context, userID int64, username string, missionID int64, action, detail, remote string) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO audit_log (ts, user_id, username, mission_id, action, detail, remote)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			time.Now().UnixMilli(), userID, username, missionID, action,
			truncate(detail, 2000), remote)
		return err
	})
	if err != nil {
		s.log.Warn("audit log write failed", "action", action, "error", err)
	}
}

// AuditEntry is one audit row.
type AuditEntry struct {
	ID        int64     `json:"id"`
	Time      time.Time `json:"time"`
	UserID    int64     `json:"user_id"`
	Username  string    `json:"username"`
	MissionID int64     `json:"mission_id"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	Remote    string    `json:"remote"`
}

// AuditLog returns the most recent audit entries.
func (s *Store) AuditLog(ctx context.Context, missionID int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := `SELECT id, ts, user_id, username, mission_id, action, detail, remote FROM audit_log`
	args := []any{}
	if missionID != 0 {
		q += ` WHERE mission_id = ?`
		args = append(args, missionID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: audit log: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.UserID, &e.Username, &e.MissionID,
			&e.Action, &e.Detail, &e.Remote); err != nil {
			return nil, err
		}
		e.Time = toTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

// Setting reads a key/value setting ("" when absent).
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.r.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: setting: %w", err)
	}
	return v, nil
}

// SetSetting stores a key/value setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO settings (key, value) VALUES (?, ?)
			 ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, value)
		return err
	})
}

// MissionData loads everything needed by the exporters in one go.
func (s *Store) MissionData(ctx context.Context, missionID, networkID int64) (model.MissionData, error) {
	var d model.MissionData
	var err error
	if d.Mission, err = s.Mission(ctx, missionID); err != nil {
		return d, err
	}
	if d.Networks, err = s.ListNetworks(ctx, missionID); err != nil {
		return d, err
	}
	if d.Scans, err = s.ListScans(ctx, missionID, 0); err != nil {
		return d, err
	}
	if d.Hosts, err = s.ListHosts(ctx, missionID, networkID); err != nil {
		return d, err
	}
	if d.Services, err = s.ListServices(ctx, ServiceFilter{MissionID: missionID, NetworkID: networkID}); err != nil {
		return d, err
	}
	if d.Assets, err = s.ListAssets(ctx, missionID); err != nil {
		return d, err
	}
	if d.Findings, err = s.ListFindings(ctx, missionID, networkID); err != nil {
		return d, err
	}
	if d.Reach, err = s.ListReach(ctx, missionID, 0); err != nil {
		return d, err
	}
	if d.Matrix, err = s.Matrix(ctx, missionID); err != nil {
		return d, err
	}
	if networkID != 0 {
		filtered := d.Networks[:0]
		for _, n := range d.Networks {
			if n.ID == networkID {
				filtered = append(filtered, n)
			}
		}
		d.Networks = filtered
	}
	d.ExportedAt = time.Now().UTC()
	return d, nil
}
