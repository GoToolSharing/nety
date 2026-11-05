package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

const missionCols = `id, name, client, description, scope_cidrs, exclude_cidrs,
	archived, created_by, created_at, updated_at`

func scanMission(sc interface{ Scan(...any) error }) (model.Mission, error) {
	var (
		m                model.Mission
		scope, exclude   string
		archived         int
		created, updated int64
	)
	err := sc.Scan(&m.ID, &m.Name, &m.Client, &m.Description, &scope, &exclude,
		&archived, &m.CreatedBy, &created, &updated)
	if err != nil {
		return model.Mission{}, err
	}
	jsonDec(scope, &m.ScopeCIDRs)
	jsonDec(exclude, &m.ExcludeCIDRs)
	m.Archived = archived != 0
	m.CreatedAt, m.UpdatedAt = toTime(created), toTime(updated)
	return m, nil
}

// CreateMission inserts a mission and attaches its creator to it.
func (s *Store) CreateMission(ctx context.Context, m model.Mission) (model.Mission, error) {
	now := time.Now().UTC()
	m.CreatedAt, m.UpdatedAt = now, now
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO missions (name, client, description, scope_cidrs, exclude_cidrs,
			                      archived, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			m.Name, m.Client, m.Description, jsonList(m.ScopeCIDRs), jsonList(m.ExcludeCIDRs),
			boolInt(m.Archived), m.CreatedBy, ms(m.CreatedAt), ms(m.UpdatedAt))
		if err != nil {
			return err
		}
		if m.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		if m.CreatedBy != 0 {
			_, err = tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO mission_users (mission_id, user_id) VALUES (?, ?)`,
				m.ID, m.CreatedBy)
		}
		return err
	})
	if err != nil {
		return model.Mission{}, fmt.Errorf("store: create mission: %w", err)
	}
	return m, nil
}

// Mission loads one mission.
func (s *Store) Mission(ctx context.Context, id int64) (model.Mission, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+missionCols+` FROM missions WHERE id = ?`, id)
	m, err := scanMission(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Mission{}, ErrNotFound
	}
	if err != nil {
		return model.Mission{}, fmt.Errorf("store: mission: %w", err)
	}
	return m, nil
}

// ListMissions returns every mission; when userID is non-zero and the user is not an
// admin, only the missions they are a member of.
func (s *Store) ListMissions(ctx context.Context, userID int64, all bool) ([]model.Mission, error) {
	q := `SELECT ` + missionCols + ` FROM missions ORDER BY archived, updated_at DESC`
	args := []any{}
	if !all {
		q = `SELECT m.id, m.name, m.client, m.description, m.scope_cidrs, m.exclude_cidrs,
		            m.archived, m.created_by, m.created_at, m.updated_at
		     FROM missions m
		     JOIN mission_users mu ON mu.mission_id = m.id AND mu.user_id = ?
		     ORDER BY m.archived, m.updated_at DESC`
		args = append(args, userID)
	}
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list missions: %w", err)
	}
	defer rows.Close()
	var out []model.Mission
	for rows.Next() {
		m, err := scanMission(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list missions: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UpdateMission saves the editable fields.
func (s *Store) UpdateMission(ctx context.Context, m model.Mission) error {
	m.UpdatedAt = time.Now().UTC()
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE missions SET name = ?, client = ?, description = ?, scope_cidrs = ?,
			                    exclude_cidrs = ?, archived = ?, updated_at = ?
			WHERE id = ?`,
			m.Name, m.Client, m.Description, jsonList(m.ScopeCIDRs), jsonList(m.ExcludeCIDRs),
			boolInt(m.Archived), ms(m.UpdatedAt), m.ID)
		if err != nil {
			return fmt.Errorf("store: update mission: %w", err)
		}
		return affected(res)
	})
}

// TouchMission bumps updated_at, so the mission list sorts by activity.
func (s *Store) TouchMission(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE missions SET updated_at = ? WHERE id = ?`,
			time.Now().UnixMilli(), id)
		return err
	})
}

// DeleteMission removes a mission and everything attached to it.
func (s *Store) DeleteMission(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM missions WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete mission: %w", err)
		}
		return affected(res)
	})
}

// SetMissionMembers replaces the member list of a mission.
func (s *Store) SetMissionMembers(ctx context.Context, missionID int64, userIDs []int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM mission_users WHERE mission_id = ?`, missionID); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx,
			`INSERT OR IGNORE INTO mission_users (mission_id, user_id) VALUES (?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, uid := range userIDs {
			if _, err := stmt.ExecContext(ctx, missionID, uid); err != nil {
				return err
			}
		}
		return nil
	})
}

// MissionMembers lists the user ids attached to a mission.
func (s *Store) MissionMembers(ctx context.Context, missionID int64) ([]int64, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT user_id FROM mission_users WHERE mission_id = ? ORDER BY user_id`, missionID)
	if err != nil {
		return nil, fmt.Errorf("store: mission members: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// IsMissionMember reports whether a user is attached to a mission.
func (s *Store) IsMissionMember(ctx context.Context, missionID, userID int64) (bool, error) {
	var n int
	err := s.r.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mission_users WHERE mission_id = ? AND user_id = ?`,
		missionID, userID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: is member: %w", err)
	}
	return n > 0, nil
}

// --------------------------------------------------------------------------- Networks
// ---------------------------------------------------------------------------

const networkCols = `id, mission_id, name, vlan_id, description, iface, local_ip,
	local_mac, prefixes, gateway, dns_servers, domain_search, dhcp_server, l2,
	created_at, updated_at`

func scanNetwork(sc interface{ Scan(...any) error }) (model.Network, error) {
	var (
		n                                    model.Network
		prefixes, dnsServers, search, l2, gw string
		created, updated                     int64
	)
	err := sc.Scan(&n.ID, &n.MissionID, &n.Name, &n.VLANID, &n.Description, &n.Interface,
		&n.LocalIP, &n.LocalMAC, &prefixes, &gw, &dnsServers, &search, &n.DHCPServer,
		&l2, &created, &updated)
	if err != nil {
		return model.Network{}, err
	}
	n.Gateway = gw
	jsonDec(prefixes, &n.Prefixes)
	jsonDec(dnsServers, &n.DNSServers)
	jsonDec(search, &n.DomainSearch)
	jsonDec(l2, &n.L2)
	n.CreatedAt, n.UpdatedAt = toTime(created), toTime(updated)
	return n, nil
}

// CreateNetwork inserts a network (VLAN attachment point).
func (s *Store) CreateNetwork(ctx context.Context, n model.Network) (model.Network, error) {
	now := time.Now().UTC()
	n.CreatedAt, n.UpdatedAt = now, now
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO networks (mission_id, name, vlan_id, description, iface, local_ip,
			                      local_mac, prefixes, gateway, dns_servers, domain_search,
			                      dhcp_server, l2, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			n.MissionID, n.Name, n.VLANID, n.Description, n.Interface, n.LocalIP,
			n.LocalMAC, jsonList(n.Prefixes), n.Gateway, jsonList(n.DNSServers),
			jsonList(n.DomainSearch), n.DHCPServer, jsonEnc(n.L2), ms(n.CreatedAt), ms(n.UpdatedAt))
		if err != nil {
			return err
		}
		n.ID, err = res.LastInsertId()
		return err
	})
	if isUnique(err) {
		return model.Network{}, fmt.Errorf("network %q: %w", n.Name, ErrConflict)
	}
	if err != nil {
		return model.Network{}, fmt.Errorf("store: create network: %w", err)
	}
	return n, nil
}

// Network loads one network.
func (s *Store) Network(ctx context.Context, id int64) (model.Network, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+networkCols+` FROM networks WHERE id = ?`, id)
	n, err := scanNetwork(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Network{}, ErrNotFound
	}
	if err != nil {
		return model.Network{}, fmt.Errorf("store: network: %w", err)
	}
	return n, nil
}

// ListNetworks returns the networks of a mission, oldest first.
func (s *Store) ListNetworks(ctx context.Context, missionID int64) ([]model.Network, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+networkCols+` FROM networks WHERE mission_id = ? ORDER BY id`, missionID)
	if err != nil {
		return nil, fmt.Errorf("store: list networks: %w", err)
	}
	defer rows.Close()
	var out []model.Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list networks: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// UpdateNetwork saves a network.
func (s *Store) UpdateNetwork(ctx context.Context, n model.Network) error {
	n.UpdatedAt = time.Now().UTC()
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE networks SET name = ?, vlan_id = ?, description = ?, iface = ?,
			    local_ip = ?, local_mac = ?, prefixes = ?, gateway = ?, dns_servers = ?,
			    domain_search = ?, dhcp_server = ?, l2 = ?, updated_at = ?
			WHERE id = ?`,
			n.Name, n.VLANID, n.Description, n.Interface, n.LocalIP, n.LocalMAC,
			jsonList(n.Prefixes), n.Gateway, jsonList(n.DNSServers), jsonList(n.DomainSearch),
			n.DHCPServer, jsonEnc(n.L2), ms(n.UpdatedAt), n.ID)
		if err != nil {
			return fmt.Errorf("store: update network: %w", err)
		}
		return affected(res)
	})
}

// DeleteNetwork removes a network. Hosts/services keep their network_id but become
// orphaned; callers should delete them explicitly when that matters.
func (s *Store) DeleteNetwork(ctx context.Context, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM networks WHERE id = ?`, id)
		if err != nil {
			return fmt.Errorf("store: delete network: %w", err)
		}
		return affected(res)
	})
}

// ResetCounts says what a reset removed, so the operator sees the size of what they just
// discarded rather than a bare confirmation.
type ResetCounts struct {
	Scans    int64 `json:"scans"`
	Hosts    int64 `json:"hosts"`
	Services int64 `json:"services"`
	Findings int64 `json:"findings"`
	Assets   int64 `json:"assets"`
	Reach    int64 `json:"reach"`
}

// ResetMissionData empties a mission of everything a scan produced and keeps everything
// the operator configured.
//
// What goes: the scans with their work units and their logs, the hosts, the services, the
// findings, the assets with their identity evidence, the segmentation results, and the
// layer-2 panel of each network, which is itself the output of a probe.
//
// What stays: the mission, its scope and exclusions, its team, and its networks with
// their interface, VLAN and addressing. Starting a mission over should not mean setting
// up the VLANs again.
func (s *Store) ResetMissionData(ctx context.Context, missionID int64) (ResetCounts, error) {
	var c ResetCounts
	err := s.tx(ctx, func(tx *sql.Tx) error {
		// scan_work and scan_logs hang off scans, and asset_keys and asset_ips off
		// assets, both with ON DELETE CASCADE, so deleting the parent row is enough and
		// keeps this list short.
		for _, step := range []struct {
			table string
			into  *int64
		}{
			{"service_changes", nil},
			{"reach_results", &c.Reach},
			{"findings", &c.Findings},
			{"services", &c.Services},
			{"hosts", &c.Hosts},
			{"assets", &c.Assets},
			{"scans", &c.Scans},
		} {
			res, err := tx.ExecContext(ctx,
				`DELETE FROM `+step.table+` WHERE mission_id = ?`, missionID)
			if err != nil {
				return fmt.Errorf("store: reset %s: %w", step.table, err)
			}
			if step.into == nil {
				continue
			}
			n, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("store: reset %s: %w", step.table, err)
			}
			*step.into = n
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE networks SET l2 = '{}' WHERE mission_id = ?`, missionID); err != nil {
			return fmt.Errorf("store: reset network l2: %w", err)
		}
		return nil
	})
	return c, err
}
