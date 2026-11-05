package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// This file holds the hot write paths. Results are written the moment they are
// discovered (requirement R1), so every upsert is a single statement keyed on
// the natural identity of the row and merges rather than replaces: a later
// scan must enrich a host, not blank the fields it did not look at.

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

const hostCols = `id, mission_id, network_id, asset_id, ip, mac, vendor, hostname,
	hostnames, domain, os, ttl, discovered_by,
	triage_status, triage_note, triage_by, triage_at,
	first_seen, last_seen, last_scan_id`

func scanHost(sc interface{ Scan(...any) error }) (model.Host, error) {
	var (
		h                     model.Host
		hostnames, discovered string
		first, last           int64
		triageAt              sql.NullInt64
	)
	err := sc.Scan(&h.ID, &h.MissionID, &h.NetworkID, &h.AssetID, &h.IP, &h.MAC,
		&h.Vendor, &h.Hostname, &hostnames, &h.Domain, &h.OS, &h.TTL, &discovered,
		&h.Triage.Status, &h.Triage.Note, &h.Triage.UpdatedBy, &triageAt,
		&first, &last, &h.LastScanID)
	if err != nil {
		return model.Host{}, err
	}
	jsonDec(hostnames, &h.Hostnames)
	jsonDec(discovered, &h.DiscoveredBy)
	h.Triage.UpdatedAt = toTimePtr(triageAt)
	if h.Triage.Status == "" {
		h.Triage.Status = model.TriageTodo
	}
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
			if h.ID, err = res.LastInsertId(); err != nil {
				return err
			}
			// The row carries the column default; mirror it on the value we
			// hand back so callers never see an empty status.
			h.Triage = model.Triage{Status: model.TriageTodo}
			if h.AssetID != 0 {
				if err := inheritAssetTriageTx(ctx, tx, &h); err != nil {
					return err
				}
			}
			return nil
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
		if merged.AssetID != 0 && merged.AssetID != existing.AssetID {
			if err := inheritAssetTriageTx(ctx, tx, &merged); err != nil {
				return err
			}
		}
		h = merged
		return nil
	})
	if err != nil {
		return model.Host{}, fmt.Errorf("store: upsert host %s: %w", h.IP, err)
	}
	return h, nil
}

// mergeHost keeps everything already known about a host and lets the new
// observation fill the gaps.
//
// Triage is deliberately not merged: it belongs to the operator, the UPDATE
// above does not write its columns, and a value passed in here is ignored.
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

// SetHostAsset links a host to an asset. This is what the identity phase calls
// once the correlator has decided which machine an address belongs to.
func (s *Store) SetHostAsset(ctx context.Context, hostID, assetID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var previous int64
		err := tx.QueryRowContext(ctx, `SELECT asset_id FROM hosts WHERE id = ?`, hostID).Scan(&previous)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET asset_id = ? WHERE id = ?`, assetID, hostID); err != nil {
			return err
		}
		if assetID == 0 || assetID == previous {
			return nil
		}
		h := model.Host{ID: hostID, AssetID: assetID}
		return inheritAssetTriageTx(ctx, tx, &h)
	})
}

// inheritAssetTriageTx gives a host the status of the asset it has just been
// attached to, when that status is "skipped".
//
// A machine that changes IP mid-engagement comes back as a brand new host, and
// without this it would walk straight back into the working views as an
// untriaged address of a machine the client asked us not to touch. Only a new
// attachment triggers it: re-running the identity phase on a host that is
// already on this asset must not undo an operator who deliberately put one
// address of it back in scope.
func inheritAssetTriageTx(ctx context.Context, tx *sql.Tx, h *model.Host) error {
	var (
		status string
		by     int64
	)
	err := tx.QueryRowContext(ctx,
		`SELECT triage_status, triage_by FROM assets WHERE id = ?`, h.AssetID).Scan(&status, &by)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if model.TriageStatus(status) != model.TriageSkipped {
		return nil
	}
	now := time.Now().UnixMilli()
	if _, err := tx.ExecContext(ctx,
		`UPDATE hosts SET triage_status = ?, triage_by = ?, triage_at = ? WHERE id = ?`,
		string(model.TriageSkipped), by, now, h.ID); err != nil {
		return err
	}
	at := toTime(now)
	h.Triage.Status = model.TriageSkipped
	h.Triage.UpdatedBy = by
	h.Triage.UpdatedAt = &at
	return nil
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
	tls, http, ssh, extra, confidence, method,
	triage_status, triage_note, triage_by, triage_at,
	first_seen, last_seen, last_scan_id`

func scanService(sc interface{ Scan(...any) error }) (model.Service, error) {
	var (
		sv                      model.Service
		cpes, extra             string
		tlsRaw, httpRaw, sshRaw sql.NullString
		first, last             int64
	)
	var triageAt sql.NullInt64
	err := sc.Scan(&sv.ID, &sv.MissionID, &sv.NetworkID, &sv.HostID, &sv.IP, &sv.Port,
		&sv.Protocol, &sv.State, &sv.Reason, &sv.Name, &sv.Product, &sv.Version,
		&sv.ExtraInfo, &sv.OSType, &cpes, &sv.Tunnel, &sv.Banner,
		&tlsRaw, &httpRaw, &sshRaw, &extra, &sv.Confidence, &sv.Method,
		&sv.Triage.Status, &sv.Triage.Note, &sv.Triage.UpdatedBy, &triageAt,
		&first, &last, &sv.LastScanID)
	if err != nil {
		return model.Service{}, err
	}
	jsonDec(cpes, &sv.CPEs)
	jsonDec(extra, &sv.Extra)
	sv.TLS = jsonDecPtr[model.TLSInfo](tlsRaw)
	sv.HTTP = jsonDecPtr[model.HTTPInfo](httpRaw)
	sv.SSH = jsonDecPtr[model.SSHInfo](sshRaw)
	sv.Triage.UpdatedAt = toTimePtr(triageAt)
	if sv.Triage.Status == "" {
		sv.Triage.Status = model.TriageTodo
	}
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
			if sv.ID, err = res.LastInsertId(); err != nil {
				return err
			}
			// The row carries the column default; mirror it on the value we
			// hand back so callers never see an empty status.
			sv.Triage = model.Triage{Status: model.TriageTodo}
			return nil
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
//
// Triage is deliberately not merged: it belongs to the operator, the UPDATE
// below does not write its columns, and a value passed in here is ignored.
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
	// Triage narrows to one or more triage statuses, which is how the
	// services screen shows "what is left to look at".
	Triage []model.TriageStatus
	// IncludeSkippedHosts brings back the services of hosts the operator has
	// skipped. They are left out by default: skipping a host is how a machine
	// that is out of scope gets parked, and it should stop appearing in the
	// work queue. The rows are hidden, never touched, so un-skipping the host
	// brings them back exactly as they were.
	IncludeSkippedHosts bool
	Limit               int
	Offset              int
}

// notOnASkippedHost is the SQL that keeps the rows of a skipped host out of a
// listing. column is the host reference of the table being listed, written by
// us and never by a caller.
//
// A row with no host (column = 0) matches no host row, so it is never hidden:
// there is nothing to say it belongs to a machine that was parked.
func notOnASkippedHost(column string) string {
	return ` AND NOT EXISTS (SELECT 1 FROM hosts WHERE hosts.id = ` + column +
		` AND hosts.triage_status = '` + string(model.TriageSkipped) + `')`
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
	if len(f.Triage) > 0 {
		sb.WriteString(` AND triage_status IN (?` + repeatComma(len(f.Triage)-1) + `)`)
		for _, t := range f.Triage {
			args = append(args, string(t))
		}
	}
	if !f.IncludeSkippedHosts {
		sb.WriteString(notOnASkippedHost("services.host_id"))
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
	triage_status, triage_note, triage_by, triage_at,
	first_seen, last_seen, last_scan_id`

func scanFinding(sc interface{ Scan(...any) error }) (model.Finding, error) {
	var (
		f           model.Finding
		refs        string
		first, last int64
	)
	var triageAt sql.NullInt64
	err := sc.Scan(&f.ID, &f.MissionID, &f.NetworkID, &f.HostID, &f.ServiceID, &f.IP,
		&f.Port, &f.Protocol, &f.CheckID, &f.Title, &f.Severity, &f.Description,
		&f.Evidence, &f.Remediation, &refs,
		&f.Triage.Status, &f.Triage.Note, &f.Triage.UpdatedBy, &triageAt,
		&first, &last, &f.LastScanID)
	if err != nil {
		return model.Finding{}, err
	}
	jsonDec(refs, &f.References)
	f.Triage.UpdatedAt = toTimePtr(triageAt)
	if f.Triage.Status == "" {
		f.Triage.Status = model.TriageTodo
	}
	f.FirstSeen, f.LastSeen = toTime(first), toTime(last)
	return f, nil
}

// UpsertFinding inserts a finding or refreshes an existing one.
//
// The triage columns are absent from the DO UPDATE below on purpose: they
// belong to the operator, so re-running the checks refreshes the evidence and
// leaves the verdict written on top of it intact.
func (s *Store) UpsertFinding(ctx context.Context, f model.Finding) (model.Finding, error) {
	now := time.Now().UTC()
	if f.FirstSeen.IsZero() {
		f.FirstSeen = now
	}
	if f.LastSeen.IsZero() {
		f.LastSeen = now
	}
	err := s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
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
		// Read the triage back rather than echoing what the caller passed in,
		// which is blank on a scan: the row it gets must say what the operator
		// has already recorded against this finding.
		var triageAt sql.NullInt64
		return tx.QueryRowContext(ctx, `SELECT id, triage_status, triage_note, triage_by, triage_at
			FROM findings
			WHERE mission_id = ? AND network_id = ? AND ip = ? AND port = ? AND protocol = ? AND check_id = ?`,
			f.MissionID, f.NetworkID, f.IP, f.Port, string(f.Protocol), f.CheckID).
			Scan(&f.ID, &f.Triage.Status, &f.Triage.Note, &f.Triage.UpdatedBy, &triageAt)
	})
	if err != nil {
		return model.Finding{}, fmt.Errorf("store: upsert finding: %w", err)
	}
	if f.Triage.Status == "" {
		f.Triage.Status = model.TriageTodo
	}
	return f, nil
}

// Finding loads one finding.
func (s *Store) Finding(ctx context.Context, id int64) (model.Finding, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE id = ?`, id)
	f, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, ErrNotFound
	}
	if err != nil {
		return model.Finding{}, fmt.Errorf("store: finding: %w", err)
	}
	return f, nil
}

// FindingFilter narrows a finding listing.
type FindingFilter struct {
	MissionID int64
	NetworkID int64 // 0 = all
	HostID    int64 // 0 = all
	// Triage narrows to one or more triage statuses, which is how the findings
	// screen shows "what is left to decide on".
	Triage []model.TriageStatus
	// IncludeSkippedHosts brings back the findings of hosts the operator has
	// skipped, which are left out by default for the same reason as the
	// services: a parked machine should not keep filling the work queue. The
	// rows are hidden, never touched.
	IncludeSkippedHosts bool
}

// ListFindings returns the findings matching the filter.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, error) {
	q := `SELECT ` + findingCols + ` FROM findings WHERE mission_id = ?`
	args := []any{f.MissionID}
	if f.NetworkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, f.NetworkID)
	}
	if f.HostID != 0 {
		q += ` AND host_id = ?`
		args = append(args, f.HostID)
	}
	if len(f.Triage) > 0 {
		q += ` AND triage_status IN (?` + repeatComma(len(f.Triage)-1) + `)`
		for _, t := range f.Triage {
			args = append(args, string(t))
		}
	}
	if !f.IncludeSkippedHosts {
		q += notOnASkippedHost("findings.host_id")
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
		fd, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("store: list findings: %w", err)
		}
		out = append(out, fd)
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

// ReachFilter narrows a reachability listing.
type ReachFilter struct {
	MissionID       int64
	SourceNetworkID int64 // 0 = all
	// IncludeSkippedHosts brings back the tests aimed at a host the operator
	// has skipped. They are left out by default: a segmentation result against
	// a machine that is out of scope is not something the operator is working
	// on, and the matrix counts are filtered the same way so the two agree.
	IncludeSkippedHosts bool
}

// ListReach returns reachability results of a mission, optionally restricted
// to one source network.
func (s *Store) ListReach(ctx context.Context, f ReachFilter) ([]model.ReachResult, error) {
	q := `SELECT ` + reachCols + ` FROM reach_results WHERE mission_id = ?`
	args := []any{f.MissionID}
	if f.SourceNetworkID != 0 {
		q += ` AND source_network_id = ?`
		args = append(args, f.SourceNetworkID)
	}
	if !f.IncludeSkippedHosts {
		q += notOnASkippedHost("reach_results.target_host_id")
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

// Matrix aggregates reachability results into source→target cells. It counts
// exactly the rows ListReach returns for the same value of includeSkippedHosts,
// so a cell never claims more tests than the drill-down behind it shows.
func (s *Store) Matrix(ctx context.Context, missionID int64, includeSkippedHosts bool) ([]model.MatrixCell, error) {
	q := `
		SELECT source_network_id, target_network_id, technique, status, COUNT(*), MAX(tested_at)
		FROM reach_results WHERE mission_id = ?`
	if !includeSkippedHosts {
		q += notOnASkippedHost("reach_results.target_host_id")
	}
	q += ` GROUP BY source_network_id, target_network_id, technique, status`
	rows, err := s.r.QueryContext(ctx, q, missionID)
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

// ---------------------------------------------------------------------------
// Service triage
// ---------------------------------------------------------------------------

// SetServiceTriage records the operator's pass over a service. Passing a nil
// status or note leaves that field alone, so the UI can update one without
// clearing the other.
//
// Triage lives in the services table but is never written by UpsertService:
// re-scanning a network refreshes what was observed and leaves the manual work
// on top of it intact.
func (s *Store) SetServiceTriage(ctx context.Context, serviceID int64, status *model.TriageStatus, note *string, userID int64) (model.Service, error) {
	var out model.Service
	err := s.tx(ctx, func(tx *sql.Tx) error {
		sets := []string{"triage_by = ?", "triage_at = ?"}
		args := []any{userID, time.Now().UnixMilli()}
		if status != nil {
			sets = append([]string{"triage_status = ?"}, sets...)
			args = append([]any{string(*status)}, args...)
		}
		if note != nil {
			sets = append(sets, "triage_note = ?")
			args = append(args, truncate(*note, 4000))
		}
		args = append(args, serviceID)
		res, err := tx.ExecContext(ctx,
			`UPDATE services SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return err
		}
		row := tx.QueryRowContext(ctx, `SELECT `+serviceCols+` FROM services WHERE id = ?`, serviceID)
		out, err = scanService(row)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return model.Service{}, ErrNotFound
		}
		return model.Service{}, fmt.Errorf("store: set service triage: %w", err)
	}
	return out, nil
}

// BulkSetServiceTriage applies one status to many services at once, which is
// how an operator clears a batch of uninteresting ports in a single gesture.
// Only services of the given mission are touched, so an id from another
// mission cannot be slipped in.
func (s *Store) BulkSetServiceTriage(ctx context.Context, missionID int64, ids []int64, status model.TriageStatus, userID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`UPDATE services SET triage_status = ?, triage_by = ?, triage_at = ?
			 WHERE id = ? AND mission_id = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		now := time.Now().UnixMilli()
		for _, id := range ids {
			res, err := stmt.ExecContext(ctx, string(status), userID, now, id, missionID)
			if err != nil {
				return err
			}
			if k, _ := res.RowsAffected(); k > 0 {
				n += k
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: bulk triage: %w", err)
	}
	return n, nil
}

// TriageCounts reports how many services sit in each status, for the progress
// readout on the services screen. It counts the same rows the listing shows,
// so the bar above the table and the table under it never disagree.
func (s *Store) TriageCounts(ctx context.Context, missionID, networkID int64, includeSkippedHosts bool) (map[model.TriageStatus]int, error) {
	q := `SELECT triage_status, COUNT(*) FROM services WHERE mission_id = ?`
	args := []any{missionID}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	if !includeSkippedHosts {
		q += notOnASkippedHost("services.host_id")
	}
	q += ` GROUP BY triage_status`

	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: triage counts: %w", err)
	}
	defer rows.Close()
	out := map[model.TriageStatus]int{}
	for _, st := range model.AllTriageStatuses {
		out[st] = 0
	}
	for rows.Next() {
		var (
			status string
			n      int
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		if status == "" {
			status = string(model.TriageTodo)
		}
		out[model.TriageStatus(status)] += n
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Finding triage
// ---------------------------------------------------------------------------

// SetFindingTriage records the operator's verdict on a finding. Passing a nil
// status or note leaves that field alone, so the UI can update one without
// clearing the other.
//
// Like service triage, this lives in the findings table but is never written
// by UpsertFinding: re-running the checks refreshes what they saw and leaves
// the decision made about it intact.
func (s *Store) SetFindingTriage(ctx context.Context, findingID int64, status *model.TriageStatus, note *string, userID int64) (model.Finding, error) {
	var out model.Finding
	err := s.tx(ctx, func(tx *sql.Tx) error {
		sets := []string{"triage_by = ?", "triage_at = ?"}
		args := []any{userID, time.Now().UnixMilli()}
		if status != nil {
			sets = append([]string{"triage_status = ?"}, sets...)
			args = append([]any{string(*status)}, args...)
		}
		if note != nil {
			sets = append(sets, "triage_note = ?")
			args = append(args, truncate(*note, 4000))
		}
		args = append(args, findingID)
		res, err := tx.ExecContext(ctx,
			`UPDATE findings SET `+strings.Join(sets, ", ")+` WHERE id = ?`, args...)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return err
		}
		row := tx.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings WHERE id = ?`, findingID)
		out, err = scanFinding(row)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return model.Finding{}, ErrNotFound
		}
		return model.Finding{}, fmt.Errorf("store: set finding triage: %w", err)
	}
	return out, nil
}

// BulkSetFindingTriage applies one status to many findings at once, which is
// how an operator clears a wave of informational checks in a single gesture.
// Only findings of the given mission are touched, so an id from another
// mission cannot be slipped in.
func (s *Store) BulkSetFindingTriage(ctx context.Context, missionID int64, ids []int64, status model.TriageStatus, userID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`UPDATE findings SET triage_status = ?, triage_by = ?, triage_at = ?
			 WHERE id = ? AND mission_id = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		now := time.Now().UnixMilli()
		for _, id := range ids {
			res, err := stmt.ExecContext(ctx, string(status), userID, now, id, missionID)
			if err != nil {
				return err
			}
			if k, _ := res.RowsAffected(); k > 0 {
				n += k
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: bulk finding triage: %w", err)
	}
	return n, nil
}

// FindingTriageCounts reports how many findings sit in each status, for the
// progress readout on the findings screen. Like the service counts, it counts
// exactly what the listing shows.
func (s *Store) FindingTriageCounts(ctx context.Context, missionID, networkID int64, includeSkippedHosts bool) (map[model.TriageStatus]int, error) {
	q := `SELECT triage_status, COUNT(*) FROM findings WHERE mission_id = ?`
	args := []any{missionID}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	if !includeSkippedHosts {
		q += notOnASkippedHost("findings.host_id")
	}
	q += ` GROUP BY triage_status`

	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: finding triage counts: %w", err)
	}
	defer rows.Close()
	out := map[model.TriageStatus]int{}
	for _, st := range model.AllTriageStatuses {
		out[st] = 0
	}
	for rows.Next() {
		var (
			status string
			n      int
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		if status == "" {
			status = string(model.TriageTodo)
		}
		out[model.TriageStatus(status)] += n
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Host triage
// ---------------------------------------------------------------------------

// SetHostTriage records the operator's pass over one address. Passing a nil
// status or note leaves that field alone, as on a service.
//
// Skipping a host is the one status with consequences beyond its own row: the
// services, findings and segmentation results that belong to it drop out of
// the default listings. Nothing is written to them, so whatever the operator
// had already recorded against each one is still there when the host comes
// back.
func (s *Store) SetHostTriage(ctx context.Context, hostID int64, status *model.TriageStatus, note *string, userID int64) (model.Host, error) {
	var out model.Host
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE hosts SET `+strings.Join(triageSets(status, note), ", ")+` WHERE id = ?`,
			append(triageArgs(status, note, userID), hostID)...)
		if err != nil {
			return err
		}
		if err := affected(res); err != nil {
			return err
		}
		row := tx.QueryRowContext(ctx, `SELECT `+hostCols+` FROM hosts WHERE id = ?`, hostID)
		out, err = scanHost(row)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return model.Host{}, ErrNotFound
		}
		return model.Host{}, fmt.Errorf("store: set host triage: %w", err)
	}
	return out, nil
}

// BulkSetHostTriage applies one status to many hosts at once. Only hosts of
// the given mission are touched, so an id from another mission cannot be
// slipped in.
func (s *Store) BulkSetHostTriage(ctx context.Context, missionID int64, ids []int64, status model.TriageStatus, userID int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx,
			`UPDATE hosts SET triage_status = ?, triage_by = ?, triage_at = ?
			 WHERE id = ? AND mission_id = ?`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		now := time.Now().UnixMilli()
		for _, id := range ids {
			res, err := stmt.ExecContext(ctx, string(status), userID, now, id, missionID)
			if err != nil {
				return err
			}
			if k, _ := res.RowsAffected(); k > 0 {
				n += k
			}
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: bulk host triage: %w", err)
	}
	return n, nil
}

// HostTriageCounts reports how many hosts sit in each status. Skipped hosts
// are counted here, unlike their services: the hosts screen is where they are
// shown and where they get put back in scope.
func (s *Store) HostTriageCounts(ctx context.Context, missionID, networkID int64) (map[model.TriageStatus]int, error) {
	q := `SELECT triage_status, COUNT(*) FROM hosts WHERE mission_id = ?`
	args := []any{missionID}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	q += ` GROUP BY triage_status`

	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: host triage counts: %w", err)
	}
	defer rows.Close()
	out := map[model.TriageStatus]int{}
	for _, st := range model.AllTriageStatuses {
		out[st] = 0
	}
	for rows.Next() {
		var (
			status string
			n      int
		)
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		if status == "" {
			status = string(model.TriageTodo)
		}
		out[model.TriageStatus(status)] += n
	}
	return out, rows.Err()
}

// SkippedHostCounts says what the default listings are leaving out, so the UI
// can put one quiet line above a table instead of silently showing fewer rows
// than the database holds.
type SkippedHostCounts struct {
	Hosts int `json:"hosts"`
	// Labels names the skipped hosts, best name first, capped: the banner says
	// which machine is parked, not all of them when a whole subnet is.
	Labels   []string `json:"host_labels"`
	Services int      `json:"services"`
	Findings int      `json:"findings"`
	Reach    int      `json:"reach"`
}

// maxSkippedLabels is how many host names the banner can carry before it stops
// being one line.
const maxSkippedLabels = 4

// SkippedHostCounts counts the rows hidden by the skipped hosts of a mission,
// optionally restricted to one network.
func (s *Store) SkippedHostCounts(ctx context.Context, missionID, networkID int64) (SkippedHostCounts, error) {
	var out SkippedHostCounts
	q := `SELECT id, ip, hostname FROM hosts WHERE mission_id = ? AND triage_status = ?`
	args := []any{missionID, string(model.TriageSkipped)}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	q += ` ORDER BY id`
	rows, err := s.r.QueryContext(ctx, q, args...)
	if err != nil {
		return out, fmt.Errorf("store: skipped hosts: %w", err)
	}
	defer rows.Close()
	var ids []any
	for rows.Next() {
		var (
			id           int64
			ip, hostname string
		)
		if err := rows.Scan(&id, &ip, &hostname); err != nil {
			return out, fmt.Errorf("store: skipped hosts: %w", err)
		}
		ids = append(ids, id)
		out.Hosts++
		if len(out.Labels) < maxSkippedLabels {
			out.Labels = append(out.Labels, firstNonEmpty(hostname, ip))
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(ids) == 0 {
		return out, nil
	}
	in := `?` + repeatComma(len(ids)-1)
	for _, c := range []struct {
		table  string
		column string
		into   *int
	}{
		{"services", "host_id", &out.Services},
		{"findings", "host_id", &out.Findings},
		{"reach_results", "target_host_id", &out.Reach},
	} {
		if err := s.r.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+c.table+` WHERE `+c.column+` IN (`+in+`)`, ids...).
			Scan(c.into); err != nil {
			return out, fmt.Errorf("store: skipped host %s: %w", c.table, err)
		}
	}
	return out, nil
}

// triageSets and triageArgs build the partial UPDATE shared by every triage
// setter: a field the caller left out keeps the value already in the row.
func triageSets(status *model.TriageStatus, note *string) []string {
	sets := []string{"triage_by = ?", "triage_at = ?"}
	if status != nil {
		sets = append([]string{"triage_status = ?"}, sets...)
	}
	if note != nil {
		sets = append(sets, "triage_note = ?")
	}
	return sets
}

func triageArgs(status *model.TriageStatus, note *string, userID int64) []any {
	args := []any{userID, time.Now().UnixMilli()}
	if status != nil {
		args = append([]any{string(*status)}, args...)
	}
	if note != nil {
		args = append(args, truncate(*note, 4000))
	}
	return args
}
