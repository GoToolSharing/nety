package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// This file answers "what changed between these two scans".
//
// There is no per-scan copy of a result row. A re-scan merges into the row
// that is already there and stamps last_scan_id with its own id, so the only
// thing the database remembers about a row's history is which scan touched it
// last, plus when it was first and last seen. Everything below is built on
// that, and seenBy is where the reasoning lives.

// ---------------------------------------------------------------------------
// Which scan saw what
// ---------------------------------------------------------------------------

// scanEnd is the moment a scan stopped writing results.
//
// A scan that is still running, or that was abandoned without a finish stamp,
// is still the most recent thing to have touched its rows, so it ends now
// rather than at some point in the past that would make its own rows look
// stale.
func scanEnd(finished *time.Time, now time.Time) time.Time {
	if finished != nil {
		return *finished
	}
	return now
}

// scanEnds reads the end time of every scan of a mission, keyed by id, so the
// rule below can be applied to a row from the id it carries.
func (s *Store) scanEnds(ctx context.Context, missionID int64) (map[int64]time.Time, error) {
	rows, err := s.r.QueryContext(ctx,
		`SELECT id, finished_at FROM scans WHERE mission_id = ?`, missionID)
	if err != nil {
		return nil, fmt.Errorf("store: scan ends: %w", err)
	}
	defer rows.Close()
	now := time.Now().UTC()
	out := map[int64]time.Time{}
	for rows.Next() {
		var (
			id       int64
			finished sql.NullInt64
		)
		if err := rows.Scan(&id, &finished); err != nil {
			return nil, fmt.Errorf("store: scan ends: %w", err)
		}
		out[id] = scanEnd(toTimePtr(finished), now)
	}
	return out, rows.Err()
}

// seenBy answers whether a result row was part of what the scan ending at
// `at` found.
//
// last_scan_id alone is not enough. It names the scan that touched the row
// last, which settles the question for the most recent scan and for a row
// nothing has touched since, but it says nothing about a row that two scans
// both saw: the second overwrites the first. So the stamp is read together
// with first_seen, and with the end time of the scan it names:
//
//   - the row already existed when this scan ran (first_seen <= at), and
//   - the scan that last touched it is this one or one that ran after it
//     (end of last_scan_id >= at), so nothing says the row had already
//     stopped answering by then.
//
// A row last touched before `at` is one this scan did not see, and a row born
// after it never existed for it.
//
// This leans on a scan of a network covering the whole network, which is what
// a discovery scan does. A host that happened to be down for the ten minutes
// a scan was looking at it, and that a later scan found again, reads here as
// if the first scan had seen it. A row no scan has stamped at all cannot be
// attributed to either side and is left out of both.
func seenBy(firstSeen time.Time, lastScanID int64, ends map[int64]time.Time, at time.Time) bool {
	last, ok := ends[lastScanID]
	if !ok {
		return false
	}
	return !firstSeen.After(at) && !last.Before(at)
}

// ---------------------------------------------------------------------------
// Picking the scan to compare against
// ---------------------------------------------------------------------------

// PreviousScan returns the most recent completed scan of the same network that
// ran before sc, which is what the diff compares against when the caller does
// not name one. It answers ErrNotFound when sc is the first scan of its
// network.
func (s *Store) PreviousScan(ctx context.Context, sc model.Scan) (model.Scan, error) {
	row := s.r.QueryRowContext(ctx, `SELECT `+scanCols+` FROM scans
		WHERE mission_id = ? AND network_id = ? AND id <> ? AND status = ?
		  AND COALESCE(finished_at, created_at) <= ?
		ORDER BY COALESCE(finished_at, created_at) DESC, id DESC LIMIT 1`,
		sc.MissionID, sc.NetworkID, sc.ID, string(model.ScanCompleted),
		ms(scanEnd(sc.FinishedAt, time.Now().UTC())))
	out, err := scanScan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: previous scan: %w", err)
	}
	return out, nil
}

// LatestCompletedScan returns the last completed scan of a mission, optionally
// restricted to one network. The exports use it to decide which pair of scans
// the diff sheet is about when the caller did not say.
func (s *Store) LatestCompletedScan(ctx context.Context, missionID, networkID int64) (model.Scan, error) {
	q := `SELECT ` + scanCols + ` FROM scans WHERE mission_id = ? AND status = ?`
	args := []any{missionID, string(model.ScanCompleted)}
	if networkID != 0 {
		q += ` AND network_id = ?`
		args = append(args, networkID)
	}
	q += ` ORDER BY COALESCE(finished_at, created_at) DESC, id DESC LIMIT 1`
	out, err := scanScan(s.r.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Scan{}, ErrNotFound
	}
	if err != nil {
		return model.Scan{}, fmt.Errorf("store: latest completed scan: %w", err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The diff itself
// ---------------------------------------------------------------------------

// ScanDiff compares two scans of the same network. The two may be given in
// either order; the earlier one is always the baseline the later one is read
// against.
func (s *Store) ScanDiff(ctx context.Context, from, to model.Scan) (model.ScanDiff, error) {
	now := time.Now().UTC()
	if scanEnd(from.FinishedAt, now).After(scanEnd(to.FinishedAt, now)) {
		from, to = to, from
	}
	ref := model.ScanRefOf(from)
	out := model.ScanDiff{
		MissionID: to.MissionID,
		NetworkID: to.NetworkID,
		From:      &ref,
		To:        model.ScanRefOf(to),
	}
	ends, err := s.scanEnds(ctx, to.MissionID)
	if err != nil {
		return out, err
	}
	// Both ends of the comparison are read from the live tables, so take the
	// end times from the same map the rows are judged against.
	atA, atB := ends[from.ID], ends[to.ID]
	if atA.IsZero() || atB.IsZero() {
		return out, fmt.Errorf("store: scan diff: scan %d or %d does not belong to mission %d",
			from.ID, to.ID, to.MissionID)
	}

	// Skipped hosts are included on purpose. The diff answers what the network
	// did between two dates; a machine the operator parked is still part of
	// that answer, and the rows carry their own triage status for a reader who
	// wants to tell them apart.
	hosts, err := s.ListHosts(ctx, to.MissionID, to.NetworkID)
	if err != nil {
		return out, err
	}
	services, err := s.ListServices(ctx, ServiceFilter{
		MissionID: to.MissionID, NetworkID: to.NetworkID, IncludeSkippedHosts: true,
	})
	if err != nil {
		return out, err
	}
	findings, err := s.ListFindings(ctx, FindingFilter{
		MissionID: to.MissionID, NetworkID: to.NetworkID, IncludeSkippedHosts: true,
	})
	if err != nil {
		return out, err
	}
	assets, err := s.ListAssets(ctx, to.MissionID)
	if err != nil {
		return out, err
	}
	labels := make(map[int64]string, len(assets))
	for _, a := range assets {
		labels[a.ID] = a.Label
	}

	d := differ{ends: ends, atA: atA, atB: atB, labels: labels}
	d.hosts(hosts, &out)
	d.services(services, &out)
	d.findings(findings, &out)
	out.Changed = out.Counts.Total() > 0
	out.Caveats = d.caveats(out)
	if !out.Changed {
		out.Message = fmt.Sprintf(
			"scan #%d found exactly what scan #%d found: no host, port or finding changed",
			to.ID, from.ID)
	}
	return out, nil
}

// differ carries the state the three passes share.
type differ struct {
	ends   map[int64]time.Time
	atA    time.Time // end of the earlier scan
	atB    time.Time // end of the later scan
	labels map[int64]string

	// machines maps a host id to a key that survives a change of address, and
	// hostnames to the best name for that host, both filled by the host pass
	// and read by the service and finding passes.
	machines  map[int64]string
	hostnames map[int64]string
	assetOf   map[int64]int64
	// unstamped records that at least one row carries no last_scan_id, which
	// is a row neither side of the diff can account for.
	unstamped bool
	// sameAddress records that at least one machine was seen at the same
	// address by both scans, which is the case where an in-place update hides
	// a version change.
	sameAddress bool
}

// machineKey is what makes a machine the same machine across two scans. The
// asset is used where the correlator has found one, so an address change reads
// as one machine moving; without an asset there is nothing but the address.
func machineKey(assetID int64, ip string) string {
	if assetID != 0 {
		return "asset:" + strconv.FormatInt(assetID, 10)
	}
	return "ip:" + ip
}

func (d *differ) hosts(hosts []model.Host, out *model.ScanDiff) {
	d.machines = make(map[int64]string, len(hosts))
	d.hostnames = make(map[int64]string, len(hosts))
	d.assetOf = make(map[int64]int64, len(hosts))

	var both, onlyA, onlyB []model.Host
	for _, h := range hosts {
		d.machines[h.ID] = machineKey(h.AssetID, h.IP)
		d.hostnames[h.ID] = h.Hostname
		d.assetOf[h.ID] = h.AssetID
		if h.LastScanID == 0 {
			d.unstamped = true
			continue
		}
		inA := seenBy(h.FirstSeen, h.LastScanID, d.ends, d.atA)
		inB := seenBy(h.FirstSeen, h.LastScanID, d.ends, d.atB)
		switch {
		case inA && inB:
			both = append(both, h)
		case inA:
			onlyA = append(onlyA, h)
		case inB:
			onlyB = append(onlyB, h)
		}
	}
	if len(both) > 0 {
		d.sameAddress = true
	}

	// A machine that changed address shows up as one row the earlier scan saw
	// and another the later one saw. The asset is what ties the two together,
	// so a move reads as a move instead of a disappearance and an arrival.
	paired := make([]bool, len(onlyB))
	byAsset := map[int64][]int{}
	for i, h := range onlyB {
		if h.AssetID != 0 {
			byAsset[h.AssetID] = append(byAsset[h.AssetID], i)
		}
	}
	for _, gone := range onlyA {
		moved := -1
		if gone.AssetID != 0 {
			for _, i := range byAsset[gone.AssetID] {
				if !paired[i] {
					paired[i] = true
					moved = i
					break
				}
			}
		}
		if moved < 0 {
			out.Hosts = append(out.Hosts, d.hostRow(model.DiffRemoved, gone))
			out.Counts.HostsRemoved++
			continue
		}
		row := d.hostRow(model.DiffMoved, onlyB[moved])
		row.PreviousIP = gone.IP
		row.PreviousHostID = gone.ID
		out.Hosts = append(out.Hosts, row)
		out.Counts.HostsMoved++
		out.Counts.HostsSame++
	}
	for i, h := range onlyB {
		if paired[i] {
			continue
		}
		out.Hosts = append(out.Hosts, d.hostRow(model.DiffAdded, h))
		out.Counts.HostsAdded++
	}
	for _, h := range both {
		out.Hosts = append(out.Hosts, d.hostRow(model.DiffSame, h))
		out.Counts.HostsSame++
	}
	sort.SliceStable(out.Hosts, func(i, j int) bool {
		a, b := out.Hosts[i], out.Hosts[j]
		if a.Change != b.Change {
			return changeRank(a.Change) < changeRank(b.Change)
		}
		return ipLess(a.IP, b.IP)
	})
}

func (d *differ) hostRow(change model.DiffChange, h model.Host) model.ScanDiffHost {
	return model.ScanDiffHost{
		Change: change, HostID: h.ID, IP: h.IP, Hostname: h.Hostname,
		MAC: h.MAC, OS: h.OS, AssetID: h.AssetID, AssetLabel: d.labels[h.AssetID],
	}
}

// serviceKey identifies a port on a machine rather than on an address, so the
// ports of a machine that moved line up with the ones it had before.
func (d *differ) serviceKey(sv model.Service) string {
	m, ok := d.machines[sv.HostID]
	if !ok {
		m = "ip:" + sv.IP
	}
	return m + "|" + strconv.Itoa(sv.Port) + "/" + string(sv.Protocol)
}

func (d *differ) services(services []model.Service, out *model.ScanDiff) {
	sideA := map[string]model.Service{}
	sideB := map[string]model.Service{}
	for _, sv := range services {
		if sv.LastScanID == 0 {
			d.unstamped = true
			continue
		}
		key := d.serviceKey(sv)
		// First row wins a key, so a machine answering at two addresses at
		// once gives the same answer on every run rather than whichever row
		// the map happened to hand back last.
		if _, dup := sideA[key]; !dup && seenBy(sv.FirstSeen, sv.LastScanID, d.ends, d.atA) {
			sideA[key] = sv
		}
		if _, dup := sideB[key]; !dup && seenBy(sv.FirstSeen, sv.LastScanID, d.ends, d.atB) {
			sideB[key] = sv
		}
	}
	for key, sv := range sideB {
		before, had := sideA[key]
		if !had {
			out.Services = append(out.Services, d.serviceRow(model.DiffAdded, sv))
			out.Counts.PortsOpened++
			continue
		}
		// An unchanged port is not news, so only a different product or
		// version string earns a row. When the machine did not move, before
		// and sv are the same database row and this can never fire: see the
		// caveat built below.
		if before.Product == sv.Product && before.Version == sv.Version {
			continue
		}
		row := d.serviceRow(model.DiffChanged, sv)
		row.PreviousProduct = before.Product
		row.PreviousVersion = before.Version
		if before.IP != sv.IP {
			row.PreviousIP = before.IP
		}
		out.Services = append(out.Services, row)
		out.Counts.ServicesChanged++
	}
	for key, sv := range sideA {
		if _, still := sideB[key]; still {
			continue
		}
		out.Services = append(out.Services, d.serviceRow(model.DiffRemoved, sv))
		out.Counts.PortsClosed++
	}
	sort.SliceStable(out.Services, func(i, j int) bool {
		a, b := out.Services[i], out.Services[j]
		if a.Change != b.Change {
			return changeRank(a.Change) < changeRank(b.Change)
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Port < b.Port
	})
}

func (d *differ) serviceRow(change model.DiffChange, sv model.Service) model.ScanDiffService {
	asset := d.assetOf[sv.HostID]
	return model.ScanDiffService{
		Change: change, ServiceID: sv.ID, IP: sv.IP, Hostname: d.hostnames[sv.HostID],
		Port: sv.Port, Protocol: sv.Protocol, Name: sv.Name,
		Product: sv.Product, Version: sv.Version,
		AssetID: asset, AssetLabel: d.labels[asset],
	}
}

func (d *differ) findings(findings []model.Finding, out *model.ScanDiff) {
	key := func(f model.Finding) string {
		m, ok := d.machines[f.HostID]
		if !ok {
			m = "ip:" + f.IP
		}
		return m + "|" + strconv.Itoa(f.Port) + "/" + string(f.Protocol) + "|" + f.CheckID
	}
	sideA := map[string]model.Finding{}
	sideB := map[string]model.Finding{}
	for _, f := range findings {
		if f.LastScanID == 0 {
			d.unstamped = true
			continue
		}
		k := key(f)
		if _, dup := sideA[k]; !dup && seenBy(f.FirstSeen, f.LastScanID, d.ends, d.atA) {
			sideA[k] = f
		}
		if _, dup := sideB[k]; !dup && seenBy(f.FirstSeen, f.LastScanID, d.ends, d.atB) {
			sideB[k] = f
		}
	}
	for k, f := range sideB {
		if _, had := sideA[k]; had {
			continue
		}
		out.Findings = append(out.Findings, d.findingRow(model.DiffAdded, f))
		out.Counts.FindingsRaised++
	}
	for k, f := range sideA {
		if _, still := sideB[k]; still {
			continue
		}
		out.Findings = append(out.Findings, d.findingRow(model.DiffRemoved, f))
		out.Counts.FindingsCleared++
	}
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.Change != b.Change {
			return changeRank(a.Change) < changeRank(b.Change)
		}
		if a.Severity != b.Severity {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		if a.IP != b.IP {
			return ipLess(a.IP, b.IP)
		}
		return a.Port < b.Port
	})
}

func (d *differ) findingRow(change model.DiffChange, f model.Finding) model.ScanDiffFinding {
	asset := d.assetOf[f.HostID]
	return model.ScanDiffFinding{
		Change: change, FindingID: f.ID, IP: f.IP, Hostname: d.hostnames[f.HostID],
		Port: f.Port, Protocol: f.Protocol, CheckID: f.CheckID, Title: f.Title,
		Severity: f.Severity, AssetID: asset, AssetLabel: d.labels[asset],
	}
}

// caveats says in plain words what this comparison cannot see, so a reader
// does not take an empty group for a guarantee.
func (d *differ) caveats(out model.ScanDiff) []string {
	var c []string
	if d.sameAddress {
		c = append(c, "A re-scan updates each result in place rather than storing a second copy, "+
			"so a product or version that changed on a machine which kept its address cannot be "+
			"recovered after the fact. The version group only shows machines that also moved.")
	}
	if d.unstamped {
		c = append(c, "Some rows carry no scan stamp, from an import or a version of NETY that "+
			"predates it. They are left out of both sides rather than guessed at.")
	}
	if out.From != nil && out.From.Status != model.ScanCompleted {
		c = append(c, fmt.Sprintf("Scan #%d did not complete, so what it did not reach reads here "+
			"as something that was not there.", out.From.ID))
	}
	return c
}

// changeRank orders the groups the way they are read: what appeared, what went
// away, then what changed, then the rest.
func changeRank(c model.DiffChange) int {
	switch c {
	case model.DiffAdded:
		return 0
	case model.DiffRemoved:
		return 1
	case model.DiffChanged:
		return 2
	case model.DiffMoved:
		return 3
	default:
		return 4
	}
}

func severityRank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 0
	case model.SevHigh:
		return 1
	case model.SevMedium:
		return 2
	case model.SevLow:
		return 3
	default:
		return 4
	}
}

// ipLess orders IPv4 numerically and leaves anything else lexicographic, so a
// diff reads in address order and never panics on a malformed value.
func ipLess(a, b string) bool {
	ka, oka := ipSortKey(a)
	kb, okb := ipSortKey(b)
	if oka && okb {
		return ka < kb
	}
	return a < b
}

func ipSortKey(s string) (uint32, bool) {
	var (
		v     uint32
		octet int
		n     int
		digit bool
	)
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if !digit || n > 255 {
				return 0, false
			}
			v = v<<8 | uint32(n)
			octet++
			n, digit = 0, false
			continue
		}
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
		digit = true
		if n > 255 {
			return 0, false
		}
	}
	return v, octet == 4
}
