package store

import (
	"context"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// Skipping is the triage status with consequences beyond its own row: an operator parks a
// machine that is out of scope, and everything belonging to it has to leave the working
// views without anything being deleted.

// parked seeds one host with a service, a finding and a segmentation result attached to
// it, which is the shape of everything these tests check.
func parked(t *testing.T, s *Store, missionID int64, ip string) (model.Host, model.Service, model.Finding, model.ReachResult) {
	t.Helper()
	ctx := context.Background()
	h, err := s.UpsertHost(ctx, model.Host{MissionID: missionID, NetworkID: 1, IP: ip})
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	sv, err := s.UpsertService(ctx, model.Service{
		MissionID: missionID, NetworkID: 1, HostID: h.ID, IP: ip, Port: 445,
		Protocol: model.TCP, Name: "microsoft-ds",
	})
	if err != nil {
		t.Fatalf("seed service: %v", err)
	}
	f, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: missionID, NetworkID: 1, HostID: h.ID, ServiceID: sv.ID, IP: ip,
		Port: 445, Protocol: model.TCP, CheckID: "smb-signing-not-required",
		Title: "SMB signing not required", Severity: model.SevMedium,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	r, err := s.UpsertReach(ctx, model.ReachResult{
		MissionID: missionID, SourceNetworkID: 2, TargetNetworkID: 1,
		TargetHostID: h.ID, TargetServiceID: sv.ID, IP: ip, Port: 445,
		Protocol: model.TCP, Technique: model.TechDirect, Status: model.ReachOpen,
	})
	if err != nil {
		t.Fatalf("seed reach: %v", err)
	}
	return h, sv, f, r
}

func skip(t *testing.T, s *Store, hostID int64) {
	t.Helper()
	status := model.TriageSkipped
	if _, err := s.SetHostTriage(context.Background(), hostID, &status, nil, 1); err != nil {
		t.Fatalf("skip host: %v", err)
	}
}

// TestSkippingAHostHidesItsRows is the whole point of the feature: one gesture takes a
// machine out of the way, everywhere it shows up.
func TestSkippingAHostHidesItsRows(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.5")

	services, _ := s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	findings, _ := s.ListFindings(ctx, FindingFilter{MissionID: m.ID})
	reach, _ := s.ListReach(ctx, ReachFilter{MissionID: m.ID})
	if len(services) != 1 || len(findings) != 1 || len(reach) != 1 {
		t.Fatalf("expected the seeded rows, got %d services, %d findings, %d reach",
			len(services), len(findings), len(reach))
	}

	skip(t, s, h.ID)

	services, _ = s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	findings, _ = s.ListFindings(ctx, FindingFilter{MissionID: m.ID})
	reach, _ = s.ListReach(ctx, ReachFilter{MissionID: m.ID})
	if len(services) != 0 || len(findings) != 0 || len(reach) != 0 {
		t.Fatalf("a skipped host should hide its rows, got %d services, %d findings, %d reach",
			len(services), len(findings), len(reach))
	}

	cells, err := s.Matrix(ctx, m.ID, false)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	if len(cells) != 0 {
		t.Fatalf("the matrix must count what the listing shows, got %+v", cells)
	}
	cells, _ = s.Matrix(ctx, m.ID, true)
	if len(cells) != 1 || cells[0].Tested != 1 {
		t.Fatalf("include_skipped must bring the cell back, got %+v", cells)
	}

	// The counts above the tables have to agree with the tables.
	counts, _ := s.TriageCounts(ctx, m.ID, 0, false)
	if total, _ := countTotal(counts); total != 0 {
		t.Fatalf("service counts should drop the hidden rows: %+v", counts)
	}
	fCounts, _ := s.FindingTriageCounts(ctx, m.ID, 0, false)
	if total, _ := countTotal(fCounts); total != 0 {
		t.Fatalf("finding counts should drop the hidden rows: %+v", fCounts)
	}

	// And the host is still there: that is where it gets put back in scope.
	hosts, _ := s.ListHosts(ctx, m.ID, 0)
	if len(hosts) != 1 || hosts[0].Triage.Status != model.TriageSkipped {
		t.Fatalf("the host itself must stay visible and skipped: %+v", hosts)
	}
}

func countTotal(counts map[model.TriageStatus]int) (int, int) {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total, total - counts[model.TriageTodo]
}

// TestSkippingAHostNeverWritesToItsRows is the rule that makes un-skipping safe: the
// operator may already have gone through some of those services by hand, and that work
// must still be there afterwards.
func TestSkippingAHostNeverWritesToItsRows(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, sv, f, _ := parked(t, s, m.ID, "10.0.0.6")

	flagged := model.TriageFlagged
	note := "relais SMB confirme"
	if _, err := s.SetServiceTriage(ctx, sv.ID, &flagged, &note, 7); err != nil {
		t.Fatalf("triage service: %v", err)
	}
	if _, err := s.SetFindingTriage(ctx, f.ID, &flagged, &note, 7); err != nil {
		t.Fatalf("triage finding: %v", err)
	}

	skip(t, s, h.ID)

	hidden, _ := s.ListServices(ctx, ServiceFilter{MissionID: m.ID, IncludeSkippedHosts: true})
	if len(hidden) != 1 || hidden[0].Triage.Status != model.TriageFlagged || hidden[0].Triage.Note != note {
		t.Fatalf("skipping the host rewrote its service: %+v", hidden)
	}
	hiddenF, _ := s.ListFindings(ctx, FindingFilter{MissionID: m.ID, IncludeSkippedHosts: true})
	if len(hiddenF) != 1 || hiddenF[0].Triage.Status != model.TriageFlagged {
		t.Fatalf("skipping the host rewrote its finding: %+v", hiddenF)
	}

	// Back in scope, and nothing was lost on the way.
	todo := model.TriageTodo
	if _, err := s.SetHostTriage(ctx, h.ID, &todo, nil, 1); err != nil {
		t.Fatalf("un-skip: %v", err)
	}
	back, _ := s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	if len(back) != 1 || back[0].Triage.Status != model.TriageFlagged || back[0].Triage.Note != note {
		t.Fatalf("un-skipping must bring the service back untouched: %+v", back)
	}
}

// TestRowsWithoutAHostAreNeverHidden: a finding recorded against a network rather than an
// address belongs to nobody, so no host can park it.
func TestRowsWithoutAHostAreNeverHidden(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.7")
	if _, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.254", CheckID: "dhcp-rogue",
		Title: "Rogue DHCP server", Severity: model.SevHigh,
	}); err != nil {
		t.Fatalf("seed orphan finding: %v", err)
	}
	skip(t, s, h.ID)

	findings, _ := s.ListFindings(ctx, FindingFilter{MissionID: m.ID})
	if len(findings) != 1 || findings[0].CheckID != "dhcp-rogue" {
		t.Fatalf("a finding with no host must stay: %+v", findings)
	}
}

// TestHostTriageSurvivesRescan: the next morning's scan sees the same address again and
// must not undo the decision made about it.
func TestHostTriageSurvivesRescan(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, err := s.UpsertHost(ctx, model.Host{MissionID: m.ID, NetworkID: 1, IP: "10.0.0.8"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if h.Triage.Status != model.TriageTodo {
		t.Fatalf("a new host should start as todo, got %q", h.Triage.Status)
	}
	status := model.TriageSkipped
	note := "poste de travail du client, hors perimetre"
	if _, err := s.SetHostTriage(ctx, h.ID, &status, &note, 7); err != nil {
		t.Fatalf("triage: %v", err)
	}

	rescanned, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.8", Hostname: "ws-042",
		OS: "Windows 11", LastScanID: 42,
	})
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescanned.Hostname != "ws-042" {
		t.Fatalf("the rescan should have enriched the host: %+v", rescanned)
	}
	if rescanned.Triage.Status != model.TriageSkipped || rescanned.Triage.Note != note {
		t.Fatalf("the rescan erased the triage: %+v", rescanned.Triage)
	}
}

// --------------------------------------------------------------------------- Assets
// ---------------------------------------------------------------------------

// TestSkippingAMachineSkipsEveryAddress: the operator is parking a machine, not one of
// the addresses it happens to answer on today.
func TestSkippingAMachineSkipsEveryAddress(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	asset, err := s.SaveAsset(ctx, model.Asset{MissionID: m.ID, Label: "ws-042"})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if asset.Triage.Status != model.TriageTodo {
		t.Fatalf("a new asset should start as todo, got %q", asset.Triage.Status)
	}
	var hostIDs []int64
	for _, ip := range []string{"10.0.0.9", "10.0.1.9"} {
		h, _, _, _ := parked(t, s, m.ID, ip)
		if err := s.SetHostAsset(ctx, h.ID, asset.ID); err != nil {
			t.Fatalf("attach: %v", err)
		}
		hostIDs = append(hostIDs, h.ID)
	}

	status := model.TriageSkipped
	note := "laptop du pentester"
	updated, hosts, err := s.SetAssetTriage(ctx, asset.ID, &status, &note, 3)
	if err != nil {
		t.Fatalf("triage asset: %v", err)
	}
	if updated.Triage.Status != model.TriageSkipped || updated.Triage.Note != note {
		t.Fatalf("asset triage not stored: %+v", updated.Triage)
	}
	if hosts != 2 {
		t.Fatalf("expected both addresses to follow, got %d", hosts)
	}
	for _, id := range hostIDs {
		h, _ := s.Host(ctx, id)
		if h.Triage.Status != model.TriageSkipped {
			t.Fatalf("address %s did not follow the machine: %+v", h.IP, h.Triage)
		}
		// The note stays on the machine, where it was written.
		if h.Triage.Note != "" {
			t.Fatalf("the machine's note should not be copied onto its addresses: %q", h.Triage.Note)
		}
	}
	services, _ := s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	if len(services) != 0 {
		t.Fatalf("the machine's services should be hidden, got %d", len(services))
	}
}

// TestANewAddressOfASkippedMachineIsSkipped is the IP change mid-engagement: a machine
// that is out of scope must not walk back in as a fresh host.
func TestANewAddressOfASkippedMachineIsSkipped(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	asset, err := s.SaveAsset(ctx, model.Asset{MissionID: m.ID, Label: "ws-042"})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	status := model.TriageSkipped
	if _, _, err := s.SetAssetTriage(ctx, asset.ID, &status, nil, 3); err != nil {
		t.Fatalf("triage asset: %v", err)
	}

	// The next day the same machine answers on another address, and the correlator
	// recognises it.
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.77")
	if h.Triage.Status != model.TriageTodo {
		t.Fatalf("a brand new host starts as todo, got %q", h.Triage.Status)
	}
	if err := s.SetHostAsset(ctx, h.ID, asset.ID); err != nil {
		t.Fatalf("attach: %v", err)
	}
	again, _ := s.Host(ctx, h.ID)
	if again.Triage.Status != model.TriageSkipped {
		t.Fatalf("the new address of a skipped machine must be skipped too: %+v", again.Triage)
	}
	services, _ := s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	if len(services) != 0 {
		t.Fatalf("and its services hidden with it, got %d", len(services))
	}

	// Putting that one address back in scope by hand must stick: re-running the identity
	// phase attaches it to the same asset and changes nothing.
	todo := model.TriageTodo
	if _, err := s.SetHostTriage(ctx, h.ID, &todo, nil, 1); err != nil {
		t.Fatalf("un-skip: %v", err)
	}
	if err := s.SetHostAsset(ctx, h.ID, asset.ID); err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	again, _ = s.Host(ctx, h.ID)
	if again.Triage.Status != model.TriageTodo {
		t.Fatalf("re-attaching to the same machine must not re-skip the address: %+v", again.Triage)
	}
}

func TestBulkHostAndAssetTriageAreScopedToTheMission(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	mine := testMission(t, s)
	theirs, err := s.CreateMission(ctx, model.Mission{Name: "someone else"})
	if err != nil {
		t.Fatal(err)
	}

	var ids []int64
	for _, ip := range []string{"10.0.0.10", "10.0.0.11"} {
		h, _, _, _ := parked(t, s, mine.ID, ip)
		ids = append(ids, h.ID)
	}
	foreign, _, _, _ := parked(t, s, theirs.ID, "10.9.9.9")

	n, err := s.BulkSetHostTriage(ctx, mine.ID, append(ids, foreign.ID), model.TriageSkipped, 3)
	if err != nil {
		t.Fatalf("bulk hosts: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 hosts updated, got %d", n)
	}
	if other, _ := s.Host(ctx, foreign.ID); other.Triage.Status != model.TriageTodo {
		t.Fatalf("a host from another mission was modified: %+v", other.Triage)
	}

	ours, err := s.SaveAsset(ctx, model.Asset{MissionID: mine.ID, Label: "ours"})
	if err != nil {
		t.Fatal(err)
	}
	notOurs, err := s.SaveAsset(ctx, model.Asset{MissionID: theirs.ID, Label: "theirs"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetHostAsset(ctx, foreign.ID, notOurs.ID); err != nil {
		t.Fatal(err)
	}
	n, err = s.BulkSetAssetTriage(ctx, mine.ID, []int64{ours.ID, notOurs.ID}, model.TriageSkipped, 3)
	if err != nil {
		t.Fatalf("bulk assets: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 machine updated, got %d", n)
	}
	if other, _ := s.Asset(ctx, notOurs.ID); other.Triage.Status != model.TriageTodo {
		t.Fatalf("a machine from another mission was modified: %+v", other.Triage)
	}
	if other, _ := s.Host(ctx, foreign.ID); other.Triage.Status != model.TriageTodo {
		t.Fatalf("a host of another mission's machine was modified: %+v", other.Triage)
	}
}

// TestExportsKeepTheSkippedRows: asked for the whole record, an export must not quietly
// lose a machine because it was parked on screen. This is the handover case, the one an
// incoming tester needs; the deliverable case, where those rows are deliberately left
// out, is in export_scope_test.go.
func TestExportsKeepTheSkippedRows(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.12")
	skip(t, s, h.ID)

	d, err := s.MissionData(ctx, m.ID, ExportScope{IncludeDismissed: true, IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("mission data: %v", err)
	}
	if len(d.Hosts) != 1 || len(d.Services) != 1 || len(d.Findings) != 1 || len(d.Reach) != 1 {
		t.Fatalf("an export must carry everything: %d hosts, %d services, %d findings, %d reach",
			len(d.Hosts), len(d.Services), len(d.Findings), len(d.Reach))
	}
	if len(d.Matrix) != 1 {
		t.Fatalf("an export must carry the matrix cell too: %+v", d.Matrix)
	}
	if d.Hosts[0].Triage.Status != model.TriageSkipped {
		t.Fatalf("and say which rows were out of scope: %+v", d.Hosts[0].Triage)
	}
}

// TestSkippedHostCounts feeds the banner that tells the operator a table is showing less
// than it holds.
func TestSkippedHostCounts(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.13")
	parked(t, s, m.ID, "10.0.0.14")

	empty, err := s.SkippedHostCounts(ctx, m.ID, 0)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if empty.Hosts != 0 || empty.Services != 0 {
		t.Fatalf("nothing is skipped yet: %+v", empty)
	}

	skip(t, s, h.ID)
	got, err := s.SkippedHostCounts(ctx, m.ID, 0)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if got.Hosts != 1 || got.Services != 1 || got.Findings != 1 || got.Reach != 1 {
		t.Fatalf("unexpected counts: %+v", got)
	}
	if len(got.Labels) != 1 || got.Labels[0] != "10.0.0.13" {
		t.Fatalf("the banner needs to name the host: %+v", got.Labels)
	}
}
