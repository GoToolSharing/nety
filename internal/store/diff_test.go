package store

import (
	"context"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// completedScan creates a scan of one network and backdates it, so a test can lay out two
// passes over the same VLAN at known moments instead of racing the clock.
func completedScan(t *testing.T, s *Store, missionID, networkID int64, finished time.Time) model.Scan {
	t.Helper()
	ctx := context.Background()
	sc, err := s.CreateScan(ctx, model.Scan{
		MissionID: missionID, NetworkID: networkID, Kind: model.ScanDiscovery,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if _, err := s.w.ExecContext(ctx,
		`UPDATE scans SET status = ?, started_at = ?, finished_at = ? WHERE id = ?`,
		string(model.ScanCompleted), ms(finished.Add(-10*time.Minute)), ms(finished), sc.ID); err != nil {
		t.Fatalf("backdate scan: %v", err)
	}
	out, err := s.Scan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("reload scan: %v", err)
	}
	return out
}

// diffFixture lays out the situation the diff exists for: a VLAN scanned on Monday and
// again on Wednesday, with a host that appeared, a host that went away, a machine that
// kept its identity across a change of address, a port that opened, a port that closed, a
// version that moved and a finding that is no longer raised.
type diffFixture struct {
	store     *Store
	mission   model.Mission
	monday    model.Scan
	wednesday model.Scan
}

func newDiffFixture(t *testing.T) diffFixture {
	t.Helper()
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	const netID = 1

	tA := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Millisecond)
	tB := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	inA, inB := tA.Add(-time.Minute), tB.Add(-time.Minute)

	laptop, err := s.SaveAsset(ctx, model.Asset{
		MissionID: m.ID, Label: "WKS-042", Hostname: "wks-042", Kind: model.AssetWorkstation,
	})
	if err != nil {
		t.Fatalf("save asset: %v", err)
	}

	monday := completedScan(t, s, m.ID, netID, tA)

	host := func(ip string, assetID int64, scan model.Scan, at time.Time) model.Host {
		t.Helper()
		h, err := s.UpsertHost(ctx, model.Host{
			MissionID: m.ID, NetworkID: netID, IP: ip, AssetID: assetID,
			DiscoveredBy: []string{"arp"}, FirstSeen: at, LastSeen: at, LastScanID: scan.ID,
		})
		if err != nil {
			t.Fatalf("upsert host %s: %v", ip, err)
		}
		return h
	}
	service := func(h model.Host, port int, product, version string, scan model.Scan, at time.Time) {
		t.Helper()
		if _, err := s.UpsertService(ctx, model.Service{
			MissionID: m.ID, NetworkID: netID, HostID: h.ID, IP: h.IP,
			Port: port, Protocol: model.TCP, State: model.PortOpen,
			Name: "ssh", Product: product, Version: version, Confidence: 90,
			FirstSeen: at, LastSeen: at, LastScanID: scan.ID,
		}); err != nil {
			t.Fatalf("upsert service %s:%d: %v", h.IP, port, err)
		}
	}
	finding := func(h model.Host, checkID string, scan model.Scan, at time.Time) {
		t.Helper()
		if _, err := s.UpsertFinding(ctx, model.Finding{
			MissionID: m.ID, NetworkID: netID, HostID: h.ID, IP: h.IP, Port: 445,
			Protocol: model.TCP, CheckID: checkID, Title: checkID, Severity: model.SevHigh,
			FirstSeen: at, LastSeen: at, LastScanID: scan.ID,
		}); err != nil {
			t.Fatalf("upsert finding %s: %v", checkID, err)
		}
	}

	// Monday.
	stable := host("10.0.0.1", 0, monday, inA)
	host("10.0.0.2", 0, monday, inA)
	old := host("10.0.0.10", laptop.ID, monday, inA)
	service(stable, 80, "nginx", "1.24.0", monday, inA)
	service(stable, 23, "telnetd", "", monday, inA)
	service(old, 22, "OpenSSH", "8.4p1", monday, inA)
	finding(stable, "smb-signing-disabled", monday, inA)

	wednesday := completedScan(t, s, m.ID, netID, tB)

	// Wednesday. The stable host answers again, 10.0.0.2 is silent, 10.0.0.3 is new, and
	// the workstation came back on a different lease.
	stable = host("10.0.0.1", 0, wednesday, inB)
	host("10.0.0.3", 0, wednesday, inB)
	moved := host("10.0.0.11", laptop.ID, wednesday, inB)
	service(stable, 80, "nginx", "1.24.0", wednesday, inB)
	service(stable, 445, "Windows SMB", "3.1.1", wednesday, inB)
	service(moved, 22, "OpenSSH", "9.6p1", wednesday, inB)
	finding(stable, "tls-expired-certificate", wednesday, inB)

	return diffFixture{store: s, mission: m, monday: monday, wednesday: wednesday}
}

func TestScanDiffHostsServicesAndFindings(t *testing.T) {
	ctx := context.Background()
	f := newDiffFixture(t)

	diff, err := f.store.ScanDiff(ctx, f.monday, f.wednesday)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if !diff.Changed {
		t.Fatal("two different scans should read as changed")
	}
	if diff.From == nil || diff.From.ID != f.monday.ID || diff.To.ID != f.wednesday.ID {
		t.Fatalf("the earlier scan should be the baseline, got from=%v to=%d", diff.From, diff.To.ID)
	}

	hosts := map[string]model.ScanDiffHost{}
	for _, h := range diff.Hosts {
		hosts[h.IP] = h
	}
	if got := hosts["10.0.0.3"].Change; got != model.DiffAdded {
		t.Errorf("10.0.0.3 appeared on Wednesday, got %q", got)
	}
	if got := hosts["10.0.0.2"].Change; got != model.DiffRemoved {
		t.Errorf("10.0.0.2 went away, got %q", got)
	}
	if got := hosts["10.0.0.1"].Change; got != model.DiffSame {
		t.Errorf("10.0.0.1 answered both times, got %q", got)
	}
	moved := hosts["10.0.0.11"]
	if moved.Change != model.DiffMoved {
		t.Errorf("the workstation changed address, got %q", moved.Change)
	}
	if moved.PreviousIP != "10.0.0.10" {
		t.Errorf("the move should carry the old address, got %q", moved.PreviousIP)
	}
	if moved.AssetLabel != "WKS-042" {
		t.Errorf("the move should name the machine, got %q", moved.AssetLabel)
	}
	if _, listed := hosts["10.0.0.10"]; listed {
		t.Error("the old address must not also read as a host that went away")
	}
	if diff.Counts.HostsAdded != 1 || diff.Counts.HostsRemoved != 1 ||
		diff.Counts.HostsMoved != 1 || diff.Counts.HostsSame != 2 {
		t.Errorf("unexpected host counts: %+v", diff.Counts)
	}

	type portKey struct {
		ip   string
		port int
	}
	services := map[portKey]model.ScanDiffService{}
	for _, sv := range diff.Services {
		services[portKey{sv.IP, sv.Port}] = sv
	}
	if got := services[portKey{"10.0.0.1", 445}].Change; got != model.DiffAdded {
		t.Errorf("445 opened on Wednesday, got %q", got)
	}
	if got := services[portKey{"10.0.0.1", 23}].Change; got != model.DiffRemoved {
		t.Errorf("23 closed, got %q", got)
	}
	if _, listed := services[portKey{"10.0.0.1", 80}]; listed {
		t.Error("an unchanged port has no business in the diff")
	}
	ssh := services[portKey{"10.0.0.11", 22}]
	if ssh.Change != model.DiffChanged {
		t.Errorf("the SSH version moved, got %q", ssh.Change)
	}
	if ssh.PreviousVersion != "8.4p1" || ssh.Version != "9.6p1" {
		t.Errorf("the version change should carry both strings, got %q -> %q",
			ssh.PreviousVersion, ssh.Version)
	}
	if ssh.PreviousIP != "10.0.0.10" {
		t.Errorf("the changed service followed the machine, got previous ip %q", ssh.PreviousIP)
	}
	if diff.Counts.PortsOpened != 1 || diff.Counts.PortsClosed != 1 || diff.Counts.ServicesChanged != 1 {
		t.Errorf("unexpected service counts: %+v", diff.Counts)
	}

	findings := map[string]model.ScanDiffFinding{}
	for _, fd := range diff.Findings {
		findings[fd.CheckID] = fd
	}
	if got := findings["tls-expired-certificate"].Change; got != model.DiffAdded {
		t.Errorf("the TLS finding is new, got %q", got)
	}
	if got := findings["smb-signing-disabled"].Change; got != model.DiffRemoved {
		t.Errorf("the SMB finding is no longer raised, got %q", got)
	}
	if diff.Counts.FindingsRaised != 1 || diff.Counts.FindingsCleared != 1 {
		t.Errorf("unexpected finding counts: %+v", diff.Counts)
	}

	// The order of the two scans is the caller's convenience, not part of the answer:
	// asking the other way round must give the same comparison.
	reversed, err := f.store.ScanDiff(ctx, f.wednesday, f.monday)
	if err != nil {
		t.Fatalf("reversed diff: %v", err)
	}
	if reversed.Counts != diff.Counts {
		t.Errorf("the diff should not depend on the order of its arguments:\n%+v\n%+v",
			reversed.Counts, diff.Counts)
	}
}

// TestScanDiffUnchangedScan is the case the UI has to say plainly rather than show three
// empty tables.
func TestScanDiffUnchangedScan(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	const netID = 2

	tA := time.Now().UTC().Add(-48 * time.Hour)
	tB := time.Now().UTC().Add(-2 * time.Hour)

	first := completedScan(t, s, m.ID, netID, tA)
	h, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: netID, IP: "10.1.0.5",
		FirstSeen: tA.Add(-time.Minute), LastSeen: tA.Add(-time.Minute), LastScanID: first.ID,
	})
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}
	if _, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: netID, HostID: h.ID, IP: h.IP, Port: 22,
		Protocol: model.TCP, State: model.PortOpen, Name: "ssh", Product: "OpenSSH",
		Version: "9.6p1", Confidence: 90,
		FirstSeen: tA.Add(-time.Minute), LastSeen: tA.Add(-time.Minute), LastScanID: first.ID,
	}); err != nil {
		t.Fatalf("upsert service: %v", err)
	}

	second := completedScan(t, s, m.ID, netID, tB)
	if _, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: netID, IP: "10.1.0.5",
		LastSeen: tB.Add(-time.Minute), LastScanID: second.ID,
	}); err != nil {
		t.Fatalf("re-upsert host: %v", err)
	}
	if _, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: netID, HostID: h.ID, IP: h.IP, Port: 22,
		Protocol: model.TCP, State: model.PortOpen, Name: "ssh", Product: "OpenSSH",
		Version: "9.6p1", Confidence: 90,
		LastSeen: tB.Add(-time.Minute), LastScanID: second.ID,
	}); err != nil {
		t.Fatalf("re-upsert service: %v", err)
	}

	diff, err := s.ScanDiff(ctx, first, second)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Changed || diff.Counts.Total() != 0 {
		t.Fatalf("nothing moved between the two scans: %+v", diff.Counts)
	}
	if diff.Message == "" {
		t.Error("an unchanged diff must say so in words")
	}
	if diff.Counts.HostsSame != 1 {
		t.Errorf("the host was there both times, got %+v", diff.Counts)
	}
	// These two scans predate the change history, so the diff has to say it cannot vouch
	// for a version change on an address that did not move.
	if len(diff.Caveats) == 0 {
		t.Error("expected the diff to say its history does not reach back this far")
	}
}

// TestPreviousScanPicksTheLastOneOnThisNetwork covers the default the API falls back on
// when the caller does not name a scan to compare against.
func TestPreviousScanPicksTheLastOneOnThisNetwork(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	now := time.Now().UTC()
	oldest := completedScan(t, s, m.ID, 1, now.Add(-72*time.Hour))
	previous := completedScan(t, s, m.ID, 1, now.Add(-48*time.Hour))
	completedScan(t, s, m.ID, 2, now.Add(-3*time.Hour)) // another VLAN, not comparable
	latest := completedScan(t, s, m.ID, 1, now.Add(-2*time.Hour))

	got, err := s.PreviousScan(ctx, latest)
	if err != nil {
		t.Fatalf("previous scan: %v", err)
	}
	if got.ID != previous.ID {
		t.Fatalf("expected scan #%d, got #%d", previous.ID, got.ID)
	}
	if _, err := s.PreviousScan(ctx, oldest); err == nil {
		t.Fatal("the first scan of a network has nothing to compare against")
	}

	newest, err := s.LatestCompletedScan(ctx, m.ID, 1)
	if err != nil {
		t.Fatalf("latest scan: %v", err)
	}
	if newest.ID != latest.ID {
		t.Fatalf("expected scan #%d, got #%d", latest.ID, newest.ID)
	}
}
