package store

import (
	"context"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// TestTriageSurvivesRescan is the property that makes triage worth having: an
// operator spends a day going through services by hand, re-runs the scan the
// next morning, and must not lose any of it.
func TestTriageSurvivesRescan(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	sv, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5", Port: 445, Protocol: model.TCP,
		Name: "microsoft-ds", Confidence: 20,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if sv.Triage.Status != model.TriageTodo {
		t.Fatalf("a new service should start as todo, got %q", sv.Triage.Status)
	}

	status := model.TriageFlagged
	note := "signature SMB non requise, relais possible depuis le VLAN bureaux"
	updated, err := s.SetServiceTriage(ctx, sv.ID, &status, &note, 7)
	if err != nil {
		t.Fatalf("set triage: %v", err)
	}
	if updated.Triage.Status != model.TriageFlagged || updated.Triage.Note != note {
		t.Fatalf("triage not stored: %+v", updated.Triage)
	}
	if updated.Triage.UpdatedBy != 7 || updated.Triage.UpdatedAt == nil {
		t.Fatalf("authorship not recorded: %+v", updated.Triage)
	}

	// The next day's scan finds the same service and fingerprints it properly.
	rescanned, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5", Port: 445, Protocol: model.TCP,
		Name: "microsoft-ds", Product: "Windows SMB", Version: "3.1.1",
		Confidence: 90, Method: "probe-match", LastScanID: 42,
	})
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescanned.Product != "Windows SMB" {
		t.Fatalf("the rescan should have enriched the service: %+v", rescanned)
	}
	if rescanned.Triage.Status != model.TriageFlagged {
		t.Fatalf("the rescan erased the status: %+v", rescanned.Triage)
	}
	if rescanned.Triage.Note != note {
		t.Fatalf("the rescan erased the note: %q", rescanned.Triage.Note)
	}
	if rescanned.Triage.UpdatedBy != 7 {
		t.Fatalf("the rescan erased the authorship: %+v", rescanned.Triage)
	}
}

func TestTriagePartialUpdates(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	sv, _ := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.6", Port: 22, Protocol: model.TCP,
	})

	note := "en cours, credentials par defaut a tester"
	if _, err := s.SetServiceTriage(ctx, sv.ID, nil, &note, 1); err != nil {
		t.Fatalf("note only: %v", err)
	}
	got, _ := s.Service(ctx, sv.ID)
	if got.Triage.Note != note || got.Triage.Status != model.TriageTodo {
		t.Fatalf("a note-only update must not change the status: %+v", got.Triage)
	}

	status := model.TriageDone
	if _, err := s.SetServiceTriage(ctx, sv.ID, &status, nil, 1); err != nil {
		t.Fatalf("status only: %v", err)
	}
	got, _ = s.Service(ctx, sv.ID)
	if got.Triage.Status != model.TriageDone || got.Triage.Note != note {
		t.Fatalf("a status-only update must not clear the note: %+v", got.Triage)
	}
}

func TestBulkTriageIsScopedToTheMission(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	mine := testMission(t, s)
	theirs, err := s.CreateMission(ctx, model.Mission{Name: "someone else"})
	if err != nil {
		t.Fatal(err)
	}

	var ids []int64
	for _, port := range []int{80, 443, 8080} {
		sv, _ := s.UpsertService(ctx, model.Service{
			MissionID: mine.ID, NetworkID: 1, IP: "10.0.0.7", Port: port, Protocol: model.TCP,
		})
		ids = append(ids, sv.ID)
	}
	foreign, _ := s.UpsertService(ctx, model.Service{
		MissionID: theirs.ID, NetworkID: 9, IP: "10.9.9.9", Port: 3389, Protocol: model.TCP,
	})

	n, err := s.BulkSetServiceTriage(ctx, mine.ID, append(ids, foreign.ID), model.TriageSkipped, 3)
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 services updated, got %d", n)
	}
	if other, _ := s.Service(ctx, foreign.ID); other.Triage.Status != model.TriageTodo {
		t.Fatalf("a service from another mission was modified: %+v", other.Triage)
	}

	counts, err := s.TriageCounts(ctx, mine.ID, 0)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts[model.TriageSkipped] != 3 || counts[model.TriageTodo] != 0 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
	// Every status is present even at zero, so the UI can render a stable bar.
	if len(counts) != len(model.AllTriageStatuses) {
		t.Fatalf("expected every status in the counts, got %+v", counts)
	}
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

func seedFinding(t *testing.T, s *Store, missionID int64, ip, checkID string) model.Finding {
	t.Helper()
	f, err := s.UpsertFinding(context.Background(), model.Finding{
		MissionID: missionID, NetworkID: 1, IP: ip, Port: 445, Protocol: model.TCP,
		CheckID: checkID, Title: "SMB signing not required",
		Severity: model.SevMedium, Evidence: "first pass",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return f
}

// TestFindingTriageSurvivesRescan is the same property as for services: a
// check firing again the next morning must not erase the verdict the operator
// already wrote against it.
func TestFindingTriageSurvivesRescan(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	f := seedFinding(t, s, m.ID, "10.0.0.5", "smb-signing-not-required")
	if f.Triage.Status != model.TriageTodo {
		t.Fatalf("a new finding should start as todo, got %q", f.Triage.Status)
	}

	status := model.TriageFlagged
	note := "confirme, relais reussi vers le serveur de fichiers"
	updated, err := s.SetFindingTriage(ctx, f.ID, &status, &note, 7)
	if err != nil {
		t.Fatalf("set triage: %v", err)
	}
	if updated.Triage.Status != model.TriageFlagged || updated.Triage.Note != note {
		t.Fatalf("triage not stored: %+v", updated.Triage)
	}
	if updated.Triage.UpdatedBy != 7 || updated.Triage.UpdatedAt == nil {
		t.Fatalf("authorship not recorded: %+v", updated.Triage)
	}

	// The next day's scan raises the same check with fresher evidence.
	rescanned, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5", Port: 445, Protocol: model.TCP,
		CheckID: "smb-signing-not-required", Title: "SMB signing not required",
		Severity: model.SevHigh, Evidence: "second pass", LastScanID: 42,
	})
	if err != nil {
		t.Fatalf("rescan: %v", err)
	}
	if rescanned.Evidence != "second pass" || rescanned.Severity != model.SevHigh {
		t.Fatalf("the rescan should have refreshed the finding: %+v", rescanned)
	}
	if rescanned.Triage.Status != model.TriageFlagged {
		t.Fatalf("the rescan erased the status: %+v", rescanned.Triage)
	}
	if rescanned.Triage.Note != note {
		t.Fatalf("the rescan erased the note: %q", rescanned.Triage.Note)
	}
	if rescanned.Triage.UpdatedBy != 7 {
		t.Fatalf("the rescan erased the authorship: %+v", rescanned.Triage)
	}

	// And the row on disk says the same thing, not just the value returned.
	stored, err := s.Finding(ctx, f.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Triage.Status != model.TriageFlagged || stored.Triage.Note != note {
		t.Fatalf("stored triage lost: %+v", stored.Triage)
	}
}

func TestFindingTriagePartialUpdates(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	f := seedFinding(t, s, m.ID, "10.0.0.6", "telnet-enabled")

	note := "a verifier avec le client, peut etre un equipement legacy"
	if _, err := s.SetFindingTriage(ctx, f.ID, nil, &note, 1); err != nil {
		t.Fatalf("note only: %v", err)
	}
	got, _ := s.Finding(ctx, f.ID)
	if got.Triage.Note != note || got.Triage.Status != model.TriageTodo {
		t.Fatalf("a note-only update must not change the status: %+v", got.Triage)
	}

	status := model.TriageDone
	if _, err := s.SetFindingTriage(ctx, f.ID, &status, nil, 1); err != nil {
		t.Fatalf("status only: %v", err)
	}
	got, _ = s.Finding(ctx, f.ID)
	if got.Triage.Status != model.TriageDone || got.Triage.Note != note {
		t.Fatalf("a status-only update must not clear the note: %+v", got.Triage)
	}
}

func TestBulkFindingTriageIsScopedToTheMission(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	mine := testMission(t, s)
	theirs, err := s.CreateMission(ctx, model.Mission{Name: "someone else"})
	if err != nil {
		t.Fatal(err)
	}

	var ids []int64
	for _, check := range []string{"telnet-enabled", "ftp-anonymous", "tls-expired"} {
		ids = append(ids, seedFinding(t, s, mine.ID, "10.0.0.7", check).ID)
	}
	foreign := seedFinding(t, s, theirs.ID, "10.9.9.9", "telnet-enabled")

	n, err := s.BulkSetFindingTriage(ctx, mine.ID, append(ids, foreign.ID), model.TriageSkipped, 3)
	if err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 findings updated, got %d", n)
	}
	if other, _ := s.Finding(ctx, foreign.ID); other.Triage.Status != model.TriageTodo {
		t.Fatalf("a finding from another mission was modified: %+v", other.Triage)
	}

	counts, err := s.FindingTriageCounts(ctx, mine.ID, 0)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts[model.TriageSkipped] != 3 || counts[model.TriageTodo] != 0 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
	// Every status is present even at zero, so the UI can render a stable bar.
	if len(counts) != len(model.AllTriageStatuses) {
		t.Fatalf("expected every status in the counts, got %+v", counts)
	}

	// Service and finding counts are kept apart: triaging one says nothing
	// about the other.
	svcCounts, err := s.TriageCounts(ctx, mine.ID, 0)
	if err != nil {
		t.Fatalf("service counts: %v", err)
	}
	if svcCounts[model.TriageSkipped] != 0 {
		t.Fatalf("finding triage leaked into the service counts: %+v", svcCounts)
	}
}

func TestListFindingsFiltersByTriage(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	kept := seedFinding(t, s, m.ID, "10.0.0.8", "telnet-enabled")
	seedFinding(t, s, m.ID, "10.0.0.9", "ftp-anonymous")

	status := model.TriageFlagged
	if _, err := s.SetFindingTriage(ctx, kept.ID, &status, nil, 1); err != nil {
		t.Fatalf("triage: %v", err)
	}

	flagged, err := s.ListFindings(ctx, FindingFilter{
		MissionID: m.ID, Triage: []model.TriageStatus{model.TriageFlagged},
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(flagged) != 1 || flagged[0].ID != kept.ID {
		t.Fatalf("expected only the flagged finding, got %+v", flagged)
	}
	todo, _ := s.ListFindings(ctx, FindingFilter{
		MissionID: m.ID, Triage: []model.TriageStatus{model.TriageTodo},
	})
	if len(todo) != 1 {
		t.Fatalf("expected one finding left to do, got %d", len(todo))
	}
}
