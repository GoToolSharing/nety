package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testMission(t *testing.T, s *Store) model.Mission {
	t.Helper()
	m, err := s.CreateMission(context.Background(), model.Mission{Name: "audit", Client: "acme"})
	if err != nil {
		t.Fatalf("create mission: %v", err)
	}
	return m
}

func TestUserLifecycle(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	u, err := s.CreateUser(ctx, model.User{Username: "alice", Role: model.RoleAdmin, PasswordHash: "h"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.ID == 0 {
		t.Fatal("expected an id")
	}
	if _, err := s.CreateUser(ctx, model.User{Username: "ALICE", PasswordHash: "h"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for a duplicate username, got %v", err)
	}
	got, err := s.UserByName(ctx, "Alice")
	if err != nil {
		t.Fatalf("by name: %v", err)
	}
	if got.ID != u.ID || got.Role != model.RoleAdmin {
		t.Fatalf("unexpected user %+v", got)
	}

	// Lockout counters.
	st, err := s.RecordLoginFailure(ctx, u.ID, 2, time.Minute)
	if err != nil || st.FailedAttempts != 1 || st.LockedUntil != nil {
		t.Fatalf("first failure: %+v err=%v", st, err)
	}
	st, err = s.RecordLoginFailure(ctx, u.ID, 2, time.Minute)
	if err != nil || st.LockedUntil == nil {
		t.Fatalf("expected a lockout after 2 failures: %+v err=%v", st, err)
	}
	if err := s.RecordLoginSuccess(ctx, u.ID); err != nil {
		t.Fatalf("success: %v", err)
	}
	if st, _ := s.LoginState(ctx, u.ID); st.FailedAttempts != 0 || st.LockedUntil != nil {
		t.Fatalf("counters should be cleared, got %+v", st)
	}
}

func TestHostAndServiceMerge(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	// First pass: discovery only knows the IP and the probe that answered.
	h, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5",
		DiscoveredBy: []string{"arp"}, MAC: "00:0c:29:11:22:33",
	})
	if err != nil {
		t.Fatalf("upsert host: %v", err)
	}

	// Second pass: identity collection adds a hostname but no MAC. The MAC
	// must survive and the discovery methods must be unioned.
	h2, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5",
		Hostname: "srv01", Domain: "corp.local", DiscoveredBy: []string{"tcp-syn:445"},
	})
	if err != nil {
		t.Fatalf("upsert host 2: %v", err)
	}
	if h2.ID != h.ID {
		t.Fatalf("expected the same host row, got %d then %d", h.ID, h2.ID)
	}
	if h2.MAC != "00:0c:29:11:22:33" {
		t.Fatalf("MAC was lost on merge: %q", h2.MAC)
	}
	if h2.Hostname != "srv01" || h2.Domain != "corp.local" {
		t.Fatalf("hostname not stored: %+v", h2)
	}
	if len(h2.DiscoveredBy) != 2 {
		t.Fatalf("discovery methods not unioned: %v", h2.DiscoveredBy)
	}

	// A port scan records a bare open port...
	sv, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, HostID: h.ID, IP: "10.0.0.5",
		Port: 443, Protocol: model.TCP, State: model.PortOpen, Reason: "syn-ack",
		Name: "https", Confidence: 20, Method: "port-table",
	})
	if err != nil {
		t.Fatalf("upsert service: %v", err)
	}
	// ...then the fingerprinter identifies it with higher confidence.
	sv2, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, HostID: h.ID, IP: "10.0.0.5",
		Port: 443, Protocol: model.TCP, Name: "http", Product: "nginx", Version: "1.24.0",
		Tunnel: "ssl", Confidence: 90, Method: "probe-match",
		TLS: &model.TLSInfo{SubjectCN: "srv01.corp.local", Version: "TLS1.3"},
	})
	if err != nil {
		t.Fatalf("upsert service 2: %v", err)
	}
	if sv2.ID != sv.ID {
		t.Fatalf("expected the same service row")
	}
	if sv2.Product != "nginx" || sv2.Version != "1.24.0" || sv2.TLS == nil {
		t.Fatalf("fingerprint not merged in: %+v", sv2)
	}
	if sv2.Reason != "syn-ack" {
		t.Fatalf("original reason lost: %q", sv2.Reason)
	}

	// A later low-confidence pass must not erase the identification.
	sv3, err := s.UpsertService(ctx, model.Service{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5", Port: 443, Protocol: model.TCP,
		Name: "https", Confidence: 20, Method: "port-table",
	})
	if err != nil {
		t.Fatalf("upsert service 3: %v", err)
	}
	if sv3.Product != "nginx" {
		t.Fatalf("low-confidence pass erased the product: %+v", sv3)
	}
}

// TestWorkUnitLifecycle covers requirement R2: a scan is a queue of persisted
// work units, so pausing, crashing and resuming never loses or repeats work.
func TestWorkUnitLifecycle(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	sc, err := s.CreateScan(ctx, model.Scan{MissionID: m.ID, NetworkID: 1, Kind: model.ScanDiscovery})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}

	payloads := make([]json.RawMessage, 5)
	for i := range payloads {
		payloads[i] = json.RawMessage(`{"chunk":` + string(rune('0'+i)) + `}`)
	}
	n, err := s.AddWork(ctx, sc.ID, model.PhasePortsTCP, payloads)
	if err != nil || n != 5 {
		t.Fatalf("add work: n=%d err=%v", n, err)
	}

	// Claim three units and finish one.
	claimed, err := s.ClaimWork(ctx, sc.ID, model.PhasePortsTCP, 3)
	if err != nil || len(claimed) != 3 {
		t.Fatalf("claim: %d err=%v", len(claimed), err)
	}
	if claimed[0].Attempts != 1 {
		t.Fatalf("attempts should be counted, got %d", claimed[0].Attempts)
	}
	if err := s.CompleteWork(ctx, claimed[0].ID); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Simulate a pause (or a crash): the two still-leased units go back to the
	// pending queue so no work is lost.
	released, err := s.ReleaseRunningWork(ctx, sc.ID)
	if err != nil || released != 2 {
		t.Fatalf("release: %d err=%v", released, err)
	}
	pending, err := s.PendingWorkCount(ctx, sc.ID)
	if err != nil || pending != 4 {
		t.Fatalf("expected 4 units left, got %d err=%v", pending, err)
	}

	// Resume: the completed unit is never handed out again.
	for range 10 {
		units, err := s.ClaimWork(ctx, sc.ID, model.PhasePortsTCP, 10)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if len(units) == 0 {
			break
		}
		for _, u := range units {
			if u.ID == claimed[0].ID {
				t.Fatal("a completed unit was handed out again")
			}
			if err := s.CompleteWork(ctx, u.ID); err != nil {
				t.Fatalf("complete: %v", err)
			}
		}
	}
	if pending, _ := s.PendingWorkCount(ctx, sc.ID); pending != 0 {
		t.Fatalf("expected the queue to be drained, %d left", pending)
	}

	progress, err := s.PhaseProgress(ctx, sc.ID)
	if err != nil || len(progress) != 1 {
		t.Fatalf("phase progress: %+v err=%v", progress, err)
	}
	if progress[0].Total != 5 || progress[0].Done != 5 {
		t.Fatalf("unexpected progress %+v", progress[0])
	}

	// AddWork is idempotent on seq, so regenerating after a resume is safe.
	again, err := s.AddWork(ctx, sc.ID, model.PhasePortsTCP, payloads)
	if err != nil {
		t.Fatalf("add work again: %v", err)
	}
	if again != 5 {
		t.Fatalf("expected 5 new units appended after the existing ones, got %d", again)
	}
}

func TestFailAndRetryWork(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	sc, _ := s.CreateScan(ctx, model.Scan{MissionID: m.ID, Kind: model.ScanDiscovery})

	if _, err := s.AddWork(ctx, sc.ID, model.PhaseChecks, []json.RawMessage{json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("add: %v", err)
	}
	units, _ := s.ClaimWork(ctx, sc.ID, model.PhaseChecks, 1)
	if err := s.FailWork(ctx, units[0].ID, "boom", false); err != nil {
		t.Fatalf("fail: %v", err)
	}
	if n, _ := s.PendingWorkCount(ctx, sc.ID); n != 0 {
		t.Fatalf("a failed unit should not be pending, got %d", n)
	}
	if n, err := s.RetryFailedWork(ctx, sc.ID); err != nil || n != 1 {
		t.Fatalf("retry: %d err=%v", n, err)
	}
	if n, _ := s.PendingWorkCount(ctx, sc.ID); n != 1 {
		t.Fatalf("retry should requeue the unit, got %d", n)
	}
}

func TestReachMatrix(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	add := func(src, dst int64, ip string, port int, tech string, st model.ReachStatus) {
		t.Helper()
		if _, err := s.UpsertReach(ctx, model.ReachResult{
			MissionID: m.ID, SourceNetworkID: src, TargetNetworkID: dst, IP: ip,
			Port: port, Protocol: model.TCP, Technique: tech, Status: st,
		}); err != nil {
			t.Fatalf("upsert reach: %v", err)
		}
	}
	add(1, 2, "10.0.2.5", 445, model.TechDirect, model.ReachOpen)
	add(1, 2, "10.0.2.5", 3389, model.TechDirect, model.ReachFiltered)
	add(1, 2, "10.0.2.6", 22, model.TechSrcPort53, model.ReachOpen)
	add(1, 3, "10.0.3.9", 80, model.TechDirect, model.ReachClosed)

	// Re-testing the same tuple replaces the previous verdict.
	add(1, 2, "10.0.2.5", 3389, model.TechDirect, model.ReachOpen)

	cells, err := s.Matrix(ctx, m.ID)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	var cell12, cell13 *model.MatrixCell
	for i := range cells {
		switch cells[i].TargetNetworkID {
		case 2:
			cell12 = &cells[i]
		case 3:
			cell13 = &cells[i]
		}
	}
	if cell12 == nil || cell13 == nil {
		t.Fatalf("expected cells for both targets, got %+v", cells)
	}
	if cell12.Tested != 3 || cell12.Reachable != 3 {
		t.Fatalf("unexpected 1->2 cell: %+v", cell12)
	}
	if cell12.ByTechnique[model.TechSrcPort53] != 1 {
		t.Fatalf("technique breakdown missing: %+v", cell12.ByTechnique)
	}
	if cell13.Closed != 1 || cell13.Reachable != 0 {
		t.Fatalf("unexpected 1->3 cell: %+v", cell13)
	}
}

func TestAssetKeysAndMerge(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	a1, err := s.SaveAsset(ctx, model.Asset{
		MissionID: m.ID, Label: "srv01.corp.local", Hostname: "srv01", Kind: model.AssetServer,
		Keys: []model.AssetKey{{Kind: model.EvSMBGUID, Value: "guid-1", Confidence: 95}},
		IPs:  []model.AssetIP{{IP: "10.0.0.5", NetworkID: 1}},
	})
	if err != nil {
		t.Fatalf("save asset: %v", err)
	}

	// The next day the same machine answers on another IP: same GUID.
	found, err := s.AssetByKey(ctx, m.ID, model.EvSMBGUID, "guid-1")
	if err != nil {
		t.Fatalf("by key: %v", err)
	}
	if found.ID != a1.ID {
		t.Fatalf("expected to find the asset by its SMB GUID")
	}
	found.IPs = append(found.IPs, model.AssetIP{IP: "10.0.0.77", NetworkID: 1})
	if _, err := s.SaveAsset(ctx, found); err != nil {
		t.Fatalf("resave: %v", err)
	}
	reloaded, _ := s.Asset(ctx, a1.ID)
	if len(reloaded.IPs) != 2 {
		t.Fatalf("expected both IPs on the asset, got %+v", reloaded.IPs)
	}

	a2, _ := s.SaveAsset(ctx, model.Asset{
		MissionID: m.ID, Label: "duplicate",
		Keys: []model.AssetKey{{Kind: model.EvSSHHostKey, Value: "SHA256:xyz", Confidence: 90}},
		IPs:  []model.AssetIP{{IP: "10.0.0.5", NetworkID: 2}},
	})
	if err := s.MergeAssets(ctx, a1.ID, a2.ID); err != nil {
		t.Fatalf("merge: %v", err)
	}
	merged, _ := s.Asset(ctx, a1.ID)
	if len(merged.Keys) != 2 || len(merged.IPs) != 3 {
		t.Fatalf("merge did not fold everything in: %d keys, %d ips", len(merged.Keys), len(merged.IPs))
	}
	if _, err := s.Asset(ctx, a2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("source asset should be gone, got %v", err)
	}
}

func TestFindingUpsertIsStable(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	f := model.Finding{
		MissionID: m.ID, NetworkID: 1, IP: "10.0.0.5", Port: 445, Protocol: model.TCP,
		CheckID: "smb-signing-not-required", Title: "SMB signing not required",
		Severity: model.SevMedium, Evidence: "first",
	}
	a, err := s.UpsertFinding(ctx, f)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	f.Evidence = "second"
	b, err := s.UpsertFinding(ctx, f)
	if err != nil {
		t.Fatalf("upsert again: %v", err)
	}
	if a.ID != b.ID {
		t.Fatalf("expected the same finding row, got %d and %d", a.ID, b.ID)
	}
	all, _ := s.ListFindings(ctx, m.ID, 0)
	if len(all) != 1 || all[0].Evidence != "second" {
		t.Fatalf("expected one refreshed finding, got %+v", all)
	}
}
