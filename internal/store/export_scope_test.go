package store

import (
	"context"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// An export is usually a deliverable. What the operator decided against has no
// business in it, and what it leaves out it has to be able to name: a
// spreadsheet that is quietly shorter than the mission is how a client ends up
// asking about a finding nobody meant to send.

func TestExportLeavesOutWhatWasSetAside(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	// One machine that stays, one that gets skipped with everything on it.
	keep, keepService, _, _ := parked(t, s, m.ID, "10.0.0.5")
	gone, _, _, _ := parked(t, s, m.ID, "10.0.0.6")
	skip(t, s, gone.ID)

	// And, on the machine that stays, one finding called a false positive and
	// one service skipped on its own.
	fp, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: m.ID, NetworkID: 1, HostID: keep.ID, IP: keep.IP,
		CheckID: "tls-weak-cipher", Title: "Weak TLS cipher", Severity: model.SevLow,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	fpStatus := model.TriageFalsePositive
	if _, err := s.SetFindingTriage(ctx, fp.ID, &fpStatus, nil, 1); err != nil {
		t.Fatalf("mark false positive: %v", err)
	}
	skippedStatus := model.TriageSkipped
	if _, err := s.SetServiceTriage(ctx, keepService.ID, &skippedStatus, nil, 1); err != nil {
		t.Fatalf("skip service: %v", err)
	}

	// The whole record: nothing held back, and nothing claimed to be.
	full, err := s.MissionData(ctx, m.ID, ExportScope{IncludeDismissed: true, IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("full export: %v", err)
	}
	if len(full.Hosts) != 2 || len(full.Services) != 2 || len(full.Findings) != 3 {
		t.Fatalf("the full export must carry everything, got %d hosts, %d services, %d findings",
			len(full.Hosts), len(full.Services), len(full.Findings))
	}
	if full.Omitted.Any() {
		t.Fatalf("the full export must not claim to have left anything out: %+v", full.Omitted)
	}

	// The deliverable.
	out, err := s.MissionData(ctx, m.ID, ExportScope{IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(out.Hosts) != 1 || out.Hosts[0].ID != keep.ID {
		t.Fatalf("the skipped host should be gone, got %+v", out.Hosts)
	}
	if len(out.Services) != 0 {
		t.Fatalf("one service was on a skipped host and the other was skipped itself, got %+v",
			out.Services)
	}
	for _, f := range out.Findings {
		if f.ID == fp.ID {
			t.Fatal("a finding called a false positive must not reach the deliverable")
		}
		if f.HostID == gone.ID {
			t.Fatal("a finding on a skipped host must not reach the deliverable")
		}
	}
	if len(out.Findings) != 1 {
		t.Fatalf("only the untouched finding should survive, got %d", len(out.Findings))
	}
	if len(out.Reach) != 1 {
		t.Fatalf("only the segmentation result of the host that stays, got %d", len(out.Reach))
	}

	// And it says so, exactly.
	if out.Omitted == nil {
		t.Fatal("an export that holds rows back has to record it")
	}
	if out.Omitted.SetAside.Hosts != 1 {
		t.Fatalf("hosts omitted: got %d, want 1", out.Omitted.SetAside.Hosts)
	}
	if out.Omitted.SetAside.Services != 2 {
		t.Fatalf("services omitted: got %d, want 2", out.Omitted.SetAside.Services)
	}
	if out.Omitted.SetAside.Findings != 2 {
		t.Fatalf("findings omitted: got %d, want 2", out.Omitted.SetAside.Findings)
	}
	if out.Omitted.SetAside.Reach != 1 {
		t.Fatalf("segmentation results omitted: got %d, want 1", out.Omitted.SetAside.Reach)
	}
}

// A mission with nothing set aside must not grow a disclaimer it does not
// need, in either direction.
func TestExportSaysNothingWhenNothingWasSetAside(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	parked(t, s, m.ID, "10.0.0.5")

	out, err := s.MissionData(ctx, m.ID, ExportScope{IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if out.Omitted.Any() {
		t.Fatalf("nothing was set aside, so nothing should be reported: %+v", out.Omitted)
	}
	if len(out.Hosts) != 1 || len(out.Services) != 1 || len(out.Findings) != 1 {
		t.Fatalf("an untriaged mission must export whole, got %d hosts, %d services, %d findings",
			len(out.Hosts), len(out.Services), len(out.Findings))
	}
}

// Skipping the machine, rather than the address, has to reach the export the
// same way: the skip cascades onto its hosts, and the export follows.
func TestExportFollowsASkippedMachine(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	h, _, _, _ := parked(t, s, m.ID, "10.0.0.7")

	asset, err := s.SaveAsset(ctx, model.Asset{MissionID: m.ID, Label: "fileserver"})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	h.AssetID = asset.ID
	if _, err := s.UpsertHost(ctx, h); err != nil {
		t.Fatalf("attach host to asset: %v", err)
	}
	status := model.TriageSkipped
	if _, _, err := s.SetAssetTriage(ctx, asset.ID, &status, nil, 1); err != nil {
		t.Fatalf("skip asset: %v", err)
	}

	out, err := s.MissionData(ctx, m.ID, ExportScope{IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(out.Assets) != 0 {
		t.Fatalf("the skipped machine should be gone, got %+v", out.Assets)
	}
	if len(out.Hosts) != 0 || len(out.Services) != 0 || len(out.Findings) != 0 {
		t.Fatalf("skipping the machine takes its address and its rows with it, got %d hosts, %d services, %d findings",
			len(out.Hosts), len(out.Services), len(out.Findings))
	}
	if out.Omitted.SetAside.Assets != 1 {
		t.Fatalf("machines omitted: got %d, want 1", out.Omitted.SetAside.Assets)
	}
}

// The second switch. A finding still at "to do" is a check result nobody has
// read, which is not a verdict to put in front of a client. A service is
// inventory and goes in whatever its status: the deliverable's list of open
// ports has to be the whole list.
func TestExportLeavesOutUnreviewedFindingsButNeverServices(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	host, service, finding, _ := parked(t, s, m.ID, "10.0.0.8")

	reviewed, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: m.ID, NetworkID: 1, HostID: host.ID, IP: host.IP,
		CheckID: "ldap.signing", Title: "LDAP signing not enforced", Severity: model.SevHigh,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	flagged := model.TriageFlagged
	if _, err := s.SetFindingTriage(ctx, reviewed.ID, &flagged, nil, 1); err != nil {
		t.Fatalf("flag finding: %v", err)
	}

	out, err := s.MissionData(ctx, m.ID, ExportScope{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(out.Findings) != 1 || out.Findings[0].ID != reviewed.ID {
		t.Fatalf("only the reviewed finding belongs in the deliverable, got %+v", out.Findings)
	}
	if out.Omitted.Unreviewed.Findings != 1 {
		t.Fatalf("unreviewed findings: got %d, want 1", out.Omitted.Unreviewed.Findings)
	}

	// The service was never triaged, and it is still there. This is the whole
	// point of keeping the two switches apart.
	if len(out.Services) != 1 || out.Services[0].ID != service.ID {
		t.Fatalf("a service is inventory and must not be filtered on its status, got %+v",
			out.Services)
	}
	if out.Omitted.Unreviewed.Services != 0 {
		t.Fatalf("services are never held back as unreviewed, got %d",
			out.Omitted.Unreviewed.Services)
	}
	if len(out.Hosts) != 1 {
		t.Fatalf("a host uses \"to do\" to mean in scope, so it stays: got %+v", out.Hosts)
	}

	// Asked for, they come back.
	whole, err := s.MissionData(ctx, m.ID, ExportScope{IncludeUnreviewed: true})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(whole.Findings) != 2 {
		t.Fatalf("both findings should be back, got %+v", whole.Findings)
	}
	if whole.Omitted.Any() {
		t.Fatalf("nothing was held back, so nothing should be claimed: %+v", whole.Omitted)
	}
	_ = finding
}

// The two reasons are counted apart, because they do not mean the same thing
// to whoever opens the file: one is a decision, the other is its absence.
func TestExportCountsTheTwoReasonsApart(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	host, _, _, _ := parked(t, s, m.ID, "10.0.0.9")

	dropped, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: m.ID, NetworkID: 1, HostID: host.ID, IP: host.IP,
		CheckID: "http.banner", Title: "Server banner", Severity: model.SevInfo,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	skipped := model.TriageSkipped
	if _, err := s.SetFindingTriage(ctx, dropped.ID, &skipped, nil, 1); err != nil {
		t.Fatalf("skip finding: %v", err)
	}

	out, err := s.MissionData(ctx, m.ID, ExportScope{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if out.Omitted.SetAside.Findings != 1 {
		t.Fatalf("set aside: got %d, want 1", out.Omitted.SetAside.Findings)
	}
	if out.Omitted.Unreviewed.Findings != 1 {
		t.Fatalf("unreviewed: got %d, want 1", out.Omitted.Unreviewed.Findings)
	}
	if out.Omitted.Total() != 2 {
		t.Fatalf("one of each, counted once each: got %d", out.Omitted.Total())
	}
	if len(out.Findings) != 0 {
		t.Fatalf("neither belongs in the deliverable, got %+v", out.Findings)
	}
}
