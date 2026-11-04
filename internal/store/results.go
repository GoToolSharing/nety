package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vaadata/nety/internal/model"
)

// This file holds the hot write paths. Results are written the moment they are
// discovered (requirement R1), so every upsert is a single statement keyed on
// the natural identity of the row and merges rather than replaces: a later
// scan must enrich a host, not blank the fields it did not look at.

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

const hostCols = `id, mission_id, network_id, asset_id, ip, mac, vendor, hostname,
	hostnames, domain, os, ttl, discovered_by, first_seen, last_seen, last_scan_id`

func scanHost(sc interface{ Scan(...any) error }) (model.Host, error) {
	var (
		h                     model.Host
		hostnames, discovered string
		first, last           int64
	)
	err := sc.Scan(&h.ID, &h.MissionID, &h.NetworkID, &h.AssetID, &h.IP, &h.MAC,
		&h.Vendor, &h.Hostname, &hostnames, &h.Domain, &h.OS, &h.TTL,
		&discovered, &first, &last, &h.LastScanID)
	if err != nil {
		return model.Host{}, err
	}
	jsonDec(hostnames, &h.Hostnames)
	jsonDec(discovered, &h.DiscoveredBy)
	h.FirstSeen, h.LastSeen = toTime(first), toTime(last)
	return h, nil
}

// UpsertHost inserts or merges a host and returns it with its id. Empty
// fields in h never overwrite a value already stored; lists are unioned.
func (s *Store) UpsertHost(ctx context.Context, h model.Host) (model.Host, error) {
	now := time.Now().UTC()
	if h.FirstSeen.IsZero() {
		h.FirstSeen = now
	}
	if h.LastSeen.IsZero() {
		h.LastSeen = now
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		existing, err := hostByKeyTx(ctx, tx, h.MissionID, h.NetworkID, h.IP)
		switch {
		case errors.Is(err, ErrNotFound):
			res, err := tx.ExecContext(ctx, `
				INSERT INTO hosts (mission_id, network_id, asset_id, ip, mac, vendor,
				    hostname, hostnames, domain, os, ttl, discovered_by,
				    first_seen, last_seen, last_scan_id)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				h.MissionID, h.NetworkID, h.AssetID, h.IP, h.MAC, h.Vendor,
				h.Hostname, jsonList(h.Hostnames), h.Domain, h.OS, h.TTL,
				jsonList(h.DiscoveredBy), ms(h.FirstSeen), ms(h.LastSeen), h.LastScanID)
			if err != nil {
				return err
			}
			h.ID, err = res.LastInsertId()
			return err
		case err != nil:
			return err
		}
		merged := mergeHost(existing, h)
		if _, err := tx.ExecContext(ctx, `
			UPDATE hosts SET asset_id = ?, mac = ?, vendor = ?, hostname = ?, hostnames = ?,
			    domain = ?, os = ?, ttl = ?, discovered_by = ?, last_seen = ?, last_scan_id = ?
			WHERE id = ?`,
			merged.AssetID, merged.MAC, merged.Vendor, merged.Hostname, jsonList(merged.Hostnames),
			merged.Domain, merged.OS, merged.TTL, jsonList(merged.DiscoveredBy),
			ms(merged.LastSeen), merged.LastScanID, merged.ID); err != nil {
			return err
		}
		h = merged
		return nil
	})
	if err != nil {
		return model.Host{}, fmt.Errorf("store: upsert host %s: %w", h.IP, err)
	}
	return h, nil
}

func mergeHost(old, new model.Host) model.Host {
	out := old
	if new.AssetID != 0 {
		out.AssetID = new.AssetID
	}
	out.MAC = firstNonEmpty(new.MAC, old.MAC)
	out.Vendor = firstNonEmpty(new.Vendor, old.Vendor)
	out.Hostname = firstNonEmpty(new.Hostname, old.Hostname)
	out.Domain = firstNonEmpty(new.Domain, old.Domain)
	out.OS = firstNonEmpty(new.OS, old.OS)
	if new.TTL != 0 {
		out.TTL = new.TTL
	}
	out.Hostnames = unionStrings(old.Hostnames, new.Hostnames)
	out.DiscoveredBy = unionStrings(old.DiscoveredBy, new.DiscoveredBy)
	if new.LastSeen.After(out.LastSeen) {
		out.LastSeen = new.LastSeen
	}
	if new.LastScanID != 0 {
		out.LastScanID = new.LastScanID
	}
	return out
}

func hostByKeyTx(ctx context.Context, tx *sql.Tx, missionID, networkID int64, ip string) (model.Host, error) {
	row := tx.QueryRowContext(ctx,
		`SELECT `+hostCols+` FROM hosts WHERE mission_id = ? AND network_id = ? AND ip = ?`,
		missionID, networkID, ip)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, ErrNotFound
	}
	return h, err
}

// Host loads one host.
func (s *Store) Host(ctx context.Context, id int64) (model.Host, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id = ?`, id)
	h, err := scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Host{}, ErrNotFound
	}
	if err != nil {
		return model.Host{}, fmt.Errorf("store: host: %w", err)
	}
	return h, nil
}

// SetHostAsset links a host to an asset.
func (s *Store) SetHostAsset(ctx context.Context, hostID, assetID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE hosts SET asset_id = ? WHERE id = ?`, assetID, hostID)
		return err
	})
}

// ListHosts returns the hosts of a mission, optionally restricted to one
// network (networkID 0 = all).
func (s *Store) ListHosts(ctx context.Context, missionID, networkID int64) ([]model.Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts WHERE mission_id = ?`
	args := []any{missionID}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	q += ` ORDER BY network_id, id`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list hosts: %w", err)
	}
	defer rows.Close()
	var out []model.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list hosts: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Services
// ---------------------------------------------------------------------------

const serviceCols = `id, mission_id, network_id, host_id, ip, port, protocol, state,
	reason, name, product, version, extra_info, os_type, cpes, tunnel, banner,
	tls, http, ssh, extra, confidence, method, first_seen, last_seen, last_scan_id`

func scanService(sc interface{ Scan(...any) error }) (model.Service, error) {
	var (
		sv                      model.Service
		cpes, extra             string
		tlsRaw, httpRaw, sshRaw sql.NullString
		first, last             int64
	)
	err := sc.Scan(&sv.ID, &sv.MissionID, &sv.NetworkID, &sv.HostID, &sv.IP, &sv.Port,
		&sv.Protocol, &sv.State, &sv.Reason, &sv.Name, &sv.Product, &sv.Version,
		&sv.ExtraInfo, &sv.OSType, &cpes, &sv.Tunnel, &sv.Banner,
		&tlsRaw, &httpRaw, &sshRaw, &extra, &sv.Confidence, &sv.Method,
		&first, &last, &sv.LastScanID)
	if err != nil {
		return model.Service{}, err
	}
	jsonDec(cpes, &sv.CPEs)
	jsonDec(extra, &sv.Extra)
	sv.TLS = jsonDecPtr[model.TLSInfo](tlsRaw)
	sv.HTTP = jsonDecPtr[model.HTTPInfo](httpRaw)
	sv.SSH = jsonDecPtr[model.SSHInfo](sshRaw)
	sv.FirstSeen, sv.LastSeen = toTime(first), toTime(last)
	return sv, nil
}

// UpsertService inserts or merges a service. Called on every open port the
// moment it is found, then again once it has been fingerprinted.
func (s *Store) UpsertService(ctx context.Context, sv model.Service) (model.Service, error) {
	now := time.Now().UTC()
	if sv.FirstSeen.IsZero() {
		sv.FirstSeen = now
	}
	if sv.LastSeen.IsZero() {
		sv.LastSeen = now
	}
	if sv.State == "" {
		sv.State = model.PortOpen
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+serviceCols+` FROM services
			WHERE mission_id = ? AND network_id = ? AND ip = ? AND port = ? AND protocol = ?`,
			sv.MissionID, sv.NetworkID, sv.IP, sv.Port, string(sv.Protocol))
		existing, err := scanService(row)
		if errors.Is(err, sql.ErrNoRows) {
			res, err := tx.ExecContext(ctx, `
				INSERT INTO services (mission_id, network_id, host_id, ip, port, protocol,
				    state, reason, name, product, version, extra_info, os_type, cpes,
				    tunnel, banner, tls, http, ssh, extra, confidence, method,
				    first_seen, last_seen, last_scan_id)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				sv.MissionID, sv.NetworkID, sv.HostID, sv.IP, sv.Port, string(sv.Protocol),
				string(sv.State), sv.Reason, sv.Name, sv.Product, sv.Version, sv.ExtraInfo,
				sv.OSType, jsonList(sv.CPEs), sv.Tunnel, sv.Banner,
				jsonEncPtr(sv.TLS, sv.TLS == nil), jsonEncPtr(sv.HTTP, sv.HTTP == nil),
				jsonEncPtr(sv.SSH, sv.SSH == nil), jsonMap(sv.Extra), sv.Confidence, sv.Method,
				ms(sv.FirstSeen), ms(sv.LastSeen), sv.LastScanID)
			if err != nil {
				return err
			}
			sv.ID, err = res.LastInsertId()
			return err
		}
		if err != nil {
			return err
		}
		merged := mergeService(existing, sv)
		if _, err := tx.ExecContext(ctx, `
			UPDATE services SET host_id = ?, state = ?, reason = ?, name = ?, product = ?,
			    version = ?, extra_info = ?, os_type = ?, cpes = ?, tunnel = ?, banner = ?,
			    tls = ?, http = ?, ssh = ?, extra = ?, confidence = ?, method = ?,
			    last_seen = ?, last_scan_id = ?
			WHERE id = ?`,
			merged.HostID, string(merged.State), merged.Reason, merged.Name, merged.Product,
			merged.Version, merged.ExtraInfo, merged.OSType, jsonList(merged.CPEs),
			merged.Tunnel, merged.Banner,
			jsonEncPtr(merged.TLS, merged.TLS == nil), jsonEncPtr(merged.HTTP, merged.HTTP == nil),
			jsonEncPtr(merged.SSH, merged.SSH == nil), jsonMap(merged.Extra),
			merged.Confidence, merged.Method, ms(merged.LastSeen), merged.LastScanID,
			merged.ID); err != nil {
			return err
		}
		sv = merged
		return nil
	})
	if err != nil {
		return model.Service{}, fmt.Errorf("store: upsert service %s:%d: %w", sv.IP, sv.Port, err)
	}
	return sv, nil
}

// mergeService keeps the richer of the two descriptions: a fingerprint result
// (high confidence) wins over a bare open-port record, but a later low
// confidence pass never erases a good identification.
func mergeService(old, new model.Service) model.Service {
	out := old
	if new.HostID != 0 {
		out.HostID = new.HostID
	}
	if new.State != "" {
		out.State = new.State
	}
	out.Reason = firstNonEmpty(new.Reason, old.Reason)
	if new.Confidence >= old.Confidence {
		out.Name = firstNonEmpty(new.Name, old.Name)
		out.Product = firstNonEmpty(new.Product, old.Product)
		out.Version = firstNonEmpty(new.Version, old.Version)
		out.ExtraInfo = firstNonEmpty(new.ExtraInfo, old.ExtraInfo)
		out.OSType = firstNonEmpty(new.OSType, old.OSType)
		out.Method = firstNonEmpty(new.Method, old.Method)
		out.Confidence = new.Confidence
	}
	out.CPEs = unionStrings(old.CPEs, new.CPEs)
	out.Tunnel = firstNonEmpty(new.Tunnel, old.Tunnel)
	out.Banner = firstNonEmpty(new.Banner, old.Banner)
	if new.TLS != nil {
		out.TLS = new.TLS
	}
	if new.HTTP != nil {
		out.HTTP = new.HTTP
	}
	if new.SSH != nil {
		out.SSH = new.SSH
	}
	out.Extra = mergeMaps(old.Extra, new.Extra)
	if new.LastSeen.After(out.LastSeen) {
		out.LastSeen = new.LastSeen
	}
	if new.LastScanID != 0 {
		out.LastScanID = new.LastScanID
	}
	return out
}

// Service loads one service.
func (s *Store) Service(ctx context.Context, id int64) (model.Service, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+serviceCols+` FROM services WHERE id = ?`, id)
	sv, err := scanService(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Service{}, ErrNotFound
	}
	if err != nil {
		return model.Service{}, fmt.Errorf("store: service: %w", err)
	}
	return sv, nil
}

// ServiceFilter narrows a service listing.
type ServiceFilter struct {
	MissionID  int64
	NetworkID  int64 // 0 = all
	HostID     int64 // 0 = all
	Port       int   // 0 = all
	Protocol   model.Protocol
	Search     string // substring over ip, name, product, version, banner, hostname
	OnlyWithID bool   // only services already fingerprinted
	Limit      int
	Offset     int
}

// ListServices returns services matching the filter.
func (s *Store) ListServices(ctx context.Context, f ServiceFilter) ([]model.Service, error) {
	var sb strings.Builder
	sb.WriteString(`SELECT ` + serviceCols + ` FROM services WHERE mission_id = ?`)
	args := []any{f.MissionID}
	if f.NetworkID != 0 {
		sb.WriteString(` AND network_id = ?`)
		args = append(args, f.NetworkID)
	}
	if f.HostID != 0 {
		sb.WriteString(` AND host_id = ?`)
		args = append(args, f.HostID)
	}
	if f.Port != 0 {
		sb.WriteString(` AND port = ?`)
		args = append(args, f.Port)
	}
	if f.Protocol != "" {
		sb.WriteString(` AND protocol = ?`)
		args = append(args, string(f.Protocol))
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		sb.WriteString(` AND (ip LIKE ? OR name LIKE ? OR product LIKE ? OR version LIKE ? OR banner LIKE ?)`)
		like := "%" + q + "%"
		args = append(args, like, like, like, like, like)
	}
	if f.OnlyWithID {
		sb.WriteString(` AND name <> ''`)
	}
	sb.WriteString(` ORDER BY network_id, ip, port`)
	if f.Limit > 0 {
		sb.WriteString(` LIMIT ?`)
		args = append(args, f.Limit)
		if f.Offset > 0 {
			sb.WriteString(` OFFSET ?`)
			args = append(args, f.Offset)
		}
	}
	rows, err := s.r.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("store: list services: %w", err)
	}
	defer rows.Close()
	var out []model.Service
	for rows.Next() {
		sv, err := scanService(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list services: %w", err)
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

// ServicesForHost lists the services of one host.
func (s *Store) ServicesForHost(ctx context.Context, hostID int64) ([]model.Service, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT `+serviceCols+` FROM services WHERE host_id = ? ORDER BY protocol, port`, hostID)
	if err != nil {
		return nil, fmt.Errorf("store: services for host: %w", err)
	}
	defer rows.Close()
	var out []model.Service
	for rows.Next() {
		sv, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sv)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const findingCols = `id, mission_id, network_id, host_id, service_id, ip, port,
	protocol, check_id, title, severity, description, evidence, remediation, refs,
	first_seen, last_seen, last_scan_id`

func scanFinding(sc interface{ Scan(...any) error }) (model.Finding, error) {
	var (
		f           model.Finding
		refs        string
		first, last int64
	)
	err := sc.Scan(&f.ID, &f.MissionID, &f.NetworkID, &f.HostID, &f.ServiceID, &f.IP,
		&f.Port, &f.Protocol, &f.CheckID, &f.Title, &f.Severity, &f.Description,
		&f.Evidence, &f.Remediation, &refs, &first, &last, &f.LastScanID)
	if err != nil {
		return model.Finding{}, err
	}
	jsonDec(refs, &f.References)
	f.FirstSeen, f.LastSeen = toTime(first), toTime(last)
	return f, nil
}

// UpsertFinding inserts a finding or refreshes an existing one.
func (s *Store) UpsertFinding(ctx context.Context, f model.Finding) (model.Finding, error) {
	now := time.Now().UTC()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO findings (mission_id, network_id, host_id, service_id, ip, port,
			    protocol, check_id, title, severity, description, evidence, remediation,
			    refs, first_seen, last_seen, last_scan_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (mission_id, network_id, ip, port, protocol, check_id) DO UPDATE SET
			    host_id = excluded.host_id,
			    service_id = excluded.service_id,
			    title = excluded.title,
			    severity = excluded.severity,
			    description = excluded.description,
			    evidence = excluded.evidence,
			    remediation = excluded.remediation,
			    refs = excluded.refs,
			    last_seen = excluded.last_seen,
			    last_scan_id = excluded.last_scan_id`,
			f.MissionID, f.NetworkID, f.HostID, f.ServiceID, f.IP, f.Port,
			string(f.Protocol), f.CheckID, f.Title, string(f.Severity), f.Description,
			f.Evidence, f.Remediation, jsonList(f.References),
			ms(f.FirstSeen), ms(f.LastSeen), f.LastScanID)
		if err != nil {
			return err
		}
		if id, err := res.LastInsertId(); err == nil && id != 0 {
			f.ID = id
			return nil
		}
		return tx.QueryRowContext(ctx, `SELECT id FROM findings
			WHERE mission_id = ? AND network_id = ? AND ip = ? AND port = ? AND protocol = ? AND check_id = ?`,
			f.MissionID, f.NetworkID, f.IP, f.Port, string(f.Protocol), f.CheckID).Scan(&f.ID)
	})
	if err != nil {
		return model.Finding{}, fmt.Errorf("store: upsert finding: %w", err)
	}
	return f, nil
}

// ListFindings returns the findings of a mission (networkID 0 = all).
func (s *Store) ListFindings(ctx context.Context, missionID, networkID int64) ([]model.Finding, error) {
	q := `SELECT ` + findingCols + ` FROM findings WHERE mission_id = ?`
	args := []any{missionID}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	// Severity is stored as text; order it by weight for the UI.
	q += ` ORDER BY CASE severity
	           WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
	           WHEN 'low' THEN 3 ELSE 4 END, ip, port`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list findings: %w", err)
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list findings: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Reachability results
// ---------------------------------------------------------------------------

const reachCols = `id, mission_id, scan_id, source_network_id, target_network_id,
	target_host_id, target_service_id, ip, port, protocol, technique, vlan_id,
	status, detail, rtt_ms, tested_at`

func scanReach(sc interface{ Scan(...any) error }) (model.ReachResult, error) {
	var (
		r      model.ReachResult
		tested int64
	)
	err := sc.Scan(&r.ID, &r.MissionID, &r.ScanID, &r.SourceNetworkID, &r.TargetNetworkID,
		&r.TargetHostID, &r.TargetServiceID, &r.IP, &r.Port, &r.Protocol, &r.Technique,
		&r.VLANID, &r.Status, &r.Detail, &r.RTTMs, &tested)
	if err != nil {
		return model.ReachResult{}, err
	}
	r.TestedAt = toTime(tested)
	return r, nil
}

// UpsertReach records one reachability test result, replacing the previous
// result for the same (source, target service, technique, vlan) tuple.
func (s *Store) UpsertReach(ctx context.Context, r model.ReachResult) (model.ReachResult, error) {
	if r.TestedAt.IsZero() {
		r.TestedAt = time.Now().UTC()
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			INSERT INTO reach_results (mission_id, scan_id, source_network_id, target_network_id,
			    target_host_id, target_service_id, ip, port, protocol, technique, vlan_id,
			    status, detail, rtt_ms, tested_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (mission_id, source_network_id, ip, port, protocol, technique, vlan_id)
			DO UPDATE SET scan_id = excluded.scan_id,
			    target_network_id = excluded.target_network_id,
			    target_host_id = excluded.target_host_id,
			    target_service_id = excluded.target_service_id,
			    status = excluded.status,
			    detail = excluded.detail,
			    rtt_ms = excluded.rtt_ms,
			    tested_at = excluded.tested_at`,
			r.MissionID, r.ScanID, r.SourceNetworkID, r.TargetNetworkID, r.TargetHostID,
			r.TargetServiceID, r.IP, r.Port, string(r.Protocol), r.Technique, r.VLANID,
			string(r.Status), truncate(r.Detail, 1000), r.RTTMs, ms(r.TestedAt))
		if err != nil {
			return err
		}
		if id, err := res.LastInsertId(); err == nil && id != 0 {
			r.ID = id
		}
		return nil
	})
	if err != nil {
		return model.ReachResult{}, fmt.Errorf("store: upsert reach: %w", err)
	}
	return r, nil
}

// ListReach returns reachability results of a mission, optionally restricted
// to one source network.
func (s *Store) ListReach(ctx context.Context, missionID, sourceNetworkID int64) ([]model.ReachResult, error) {
	q := `SELECT ` + reachCols + ` FROM reach_results WHERE mission_id = ?`
	args := []any{missionID}
	if sourceNetworkID != 0 {
		q += ` AND source_network_id = ?`
		args = append(args, sourceNetworkID)
	}
	q += ` ORDER BY source_network_id, target_network_id, ip, port, technique`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list reach: %w", err)
	}
	defer rows.Close()
	var out []model.ReachResult
	for rows.Next() {
		r, err := scanReach(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list reach: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Matrix aggregates reachability results into source→target cells.
func (s *Store) Matrix(ctx context.Context, missionID int64) ([]model.MatrixCell, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT source_network_id, target_network_id, technique, status, COUNT(*), MAX(tested_at)
		FROM reach_results WHERE mission_id = ?
		GROUP BY source_network_id, target_network_id, technique, status`, missionID)
	if err != nil {
		return nil, fmt.Errorf("store: matrix: %w", err)
	}
	defer rows.Close()

	type key struct{ src, dst int64 }
	cells := map[key]*model.MatrixCell{}
	for rows.Next() {
		var (
			src, dst, n, tested int64
			technique, status   string
		)
		if err := rows.Scan(&src, &dst, &technique, &status, &n, &tested); err != nil {
			return nil, err
		}
		k := key{src, dst}
		c := cells[k]
		if c == nil {
			c = &model.MatrixCell{
				SourceNetworkID: src,
				TargetNetworkID: dst,
				ByTechnique:     map[string]int{},
			}
			cells[k] = c
		}
		c.Tested += int(n)
		switch model.ReachStatus(status) {
		case model.ReachOpen:
			c.Reachable += int(n)
			c.ByTechnique[technique] += int(n)
		case model.ReachClosed:
			c.Closed += int(n)
		case model.ReachFiltered, model.ReachUnreachable:
			c.Filtered += int(n)
		}
		if t := toTime(tested); !t.IsZero() && (c.LastTestedAt == nil || t.After(*c.LastTestedAt)) {
			tt := t
			c.LastTestedAt = &tt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]model.MatrixCell, 0, len(cells))
	for _, c := range cells {
		out = append(out, *c)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func unionStrings(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, v := range list {
			if v == "" {
				continue
			}
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeMaps(old, new map[string]string) map[string]string {
	if len(new) == 0 {
		return old
	}
	out := make(map[string]string, len(old)+len(new))
	for k, v := range old {
		out[k] = v
	}
	for k, v := range new {
		out[k] = v
	}
	return out
}
