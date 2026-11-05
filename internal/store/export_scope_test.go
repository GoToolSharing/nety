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
	full, err := s.MissionData(ctx, m.ID, ExportScope{IncludeDismissed: true})
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
	out, err := s.MissionData(ctx, m.ID, ExportScope{})
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
	if out.Omitted.Hosts != 1 {
		t.Fatalf("hosts omitted: got %d, want 1", out.Omitted.Hosts)
	}
	if out.Omitted.Services != 2 {
		t.Fatalf("services omitted: got %d, want 2", out.Omitted.Services)
	}
	if out.Omitted.Findings != 2 {
		t.Fatalf("findings omitted: got %d, want 2", out.Omitted.Findings)
	}
	if out.Omitted.Reach != 1 {
		t.Fatalf("segmentation results omitted: got %d, want 1", out.Omitted.Reach)
	}
}

// A mission with nothing set aside must not grow a disclaimer it does not
// need, in either direction.
func TestExportSaysNothingWhenNothingWasSetAside(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	parked(t, s, m.ID, "10.0.0.5")

	out, err := s.MissionData(ctx, m.ID, ExportScope{})
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

	out, err := s.MissionData(ctx, m.ID, ExportScope{})
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
	if out.Omitted.Assets != 1 {
		t.Fatalf("machines omitted: got %d, want 1", out.Omitted.Assets)
	}
}
