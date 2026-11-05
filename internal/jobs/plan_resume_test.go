package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

type stubInspector struct{}

func (stubInspector) Interfaces() ([]engine.InterfaceInfo, error) { return nil, nil }
func (stubInspector) Detect(context.Context, string) (engine.NetContext, error) {
	return engine.NetContext{}, nil
}
func (stubInspector) SniffL2(context.Context, string, time.Duration) (model.L2Info, error) {
	return model.L2Info{}, nil
}

// TestPlanningFinishesAfterACrashMidPlan reproduces a scan that came back from
// a crash and then reported itself completed having scanned nothing.
//
// Planning used to be all-or-nothing: it bailed out as soon as the scan had
// any phase at all. A process killed after writing the L2 unit but before the
// discovery ones left a scan whose plan was missing its main phase. Resuming
// ran the L2 recon, found no discovery work, and called that a success.
func TestPlanningFinishesAfterACrashMidPlan(t *testing.T) {
	h := newHarness(t, Engines{
		NetInspector: stubInspector{},
		Discoverer:   &fakeDiscoverer{perUnit: 2},
		PortScanner:  &fakePortScanner{openPorts: []uint16{80}},
	})
	ctx := context.Background()
	opts := defaultOptions()
	opts.ServiceDetection, opts.Checks = false, false
	sc := h.newScan(t, opts)

	// The state a crash during planning leaves behind: the L2 unit is on disk,
	// nothing else is.
	l2, err := json.Marshal(l2Payload{Interface: "eth0", Seconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.AddWork(ctx, sc.ID, model.PhaseL2, []json.RawMessage{l2}); err != nil {
		t.Fatalf("seed the half-written plan: %v", err)
	}
	phases, _ := h.st.PhaseProgress(ctx, sc.ID)
	if len(phases) != 1 || phases[0].Phase != model.PhaseL2 {
		t.Fatalf("expected only the L2 phase, got %+v", phases)
	}

	// Resuming must finish the plan, not take the half-written one as done.
	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 20*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("scan failed: %s", done.Error)
	}

	byPhase := map[model.WorkPhase]model.PhaseProgress{}
	for _, p := range done.Phases {
		byPhase[p.Phase] = p
	}
	if _, ok := byPhase[model.PhaseDiscovery]; !ok {
		t.Fatalf("the discovery phase was never planned: %+v", done.Phases)
	}
	if byPhase[model.PhaseL2].Total != 1 {
		t.Fatalf("the existing L2 unit should not have been duplicated: %+v", byPhase[model.PhaseL2])
	}
	hosts, _ := h.st.ListHosts(ctx, h.mis.ID, h.net.ID)
	if len(hosts) == 0 {
		t.Fatal("the resumed scan found nothing, which is the bug this covers")
	}
}

// Planning twice in a row must not duplicate anything.
func TestPlanIsIdempotentPerPhase(t *testing.T) {
	h := newHarness(t, Engines{
		NetInspector: stubInspector{},
		Discoverer:   &fakeDiscoverer{perUnit: 1},
		PortScanner:  &fakePortScanner{openPorts: []uint16{80}},
	})
	ctx := context.Background()
	sc := h.newScan(t, defaultOptions())

	for range 3 {
		if err := h.runner.plan(ctx, sc); err != nil {
			t.Fatalf("plan: %v", err)
		}
	}
	phases, _ := h.st.PhaseProgress(ctx, sc.ID)
	for _, p := range phases {
		switch p.Phase {
		case model.PhaseL2:
			if p.Total != 1 {
				t.Fatalf("L2 planned %d times", p.Total)
			}
		case model.PhaseDiscovery:
			if p.Total == 0 {
				t.Fatal("discovery was never planned")
			}
		}
	}
	before := phases
	if err := h.runner.plan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	after, _ := h.st.PhaseProgress(ctx, sc.ID)
	if len(after) != len(before) {
		t.Fatalf("a further plan changed the phases: %+v -> %+v", before, after)
	}
	for i := range after {
		if after[i].Total != before[i].Total {
			t.Fatalf("phase %s grew from %d to %d", after[i].Phase, before[i].Total, after[i].Total)
		}
	}
}

// A scan that completed without doing its work, because a crash cut the plan
// short, must be recoverable with Resume rather than having to be recreated.
func TestCompletedButUnplannedScanCanBeResumed(t *testing.T) {
	h := newHarness(t, Engines{
		NetInspector: stubInspector{},
		Discoverer:   &fakeDiscoverer{perUnit: 2},
		PortScanner:  &fakePortScanner{openPorts: []uint16{443}},
	})
	ctx := context.Background()
	opts := defaultOptions()
	opts.ServiceDetection, opts.Checks = false, false
	sc := h.newScan(t, opts)

	// A plan that only ever got as far as the L2 unit, then ran and
	// "completed" with nothing to do.
	l2, _ := json.Marshal(l2Payload{Interface: "eth0", Seconds: 1})
	if _, err := h.st.AddWork(ctx, sc.ID, model.PhaseL2, []json.RawMessage{l2}); err != nil {
		t.Fatal(err)
	}
	units, _ := h.st.ClaimWork(ctx, sc.ID, model.PhaseL2, 1)
	for _, u := range units {
		if err := h.st.CompleteWork(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.st.SetScanStatus(ctx, sc.ID, model.ScanCompleted, ""); err != nil {
		t.Fatal(err)
	}

	if err := h.runner.Start(ctx, sc.ID); err != nil {
		t.Fatalf("a scan whose plan is incomplete must be restartable: %v", err)
	}
	done := h.waitStatus(t, sc.ID, 20*time.Second, model.ScanCompleted, model.ScanFailed)
	if done.Status != model.ScanCompleted {
		t.Fatalf("failed: %s", done.Error)
	}
	if hosts, _ := h.st.ListHosts(ctx, h.mis.ID, h.net.ID); len(hosts) == 0 {
		t.Fatal("the restarted scan still found nothing")
	}

	// A genuinely finished scan still says so rather than looping.
	if err := h.runner.Start(ctx, sc.ID); err == nil {
		t.Fatal("a scan with a complete plan and no pending work should refuse to restart")
	}
}

// A host the operator marked skipped is out of scope. Its services are already
// left out by the service listing, so leaving it in the host-level ICMP row
// would put the machine back in the matrix through the back door.
func TestSegmentationLeavesSkippedHostsOut(t *testing.T) {
	h := newHarness(t, Engines{NetInspector: stubInspector{}})
	ctx := context.Background()

	other, err := h.st.CreateNetwork(ctx, model.Network{
		MissionID: h.mis.ID, Name: "VLAN20", VLANID: 20,
		Interface: "eth1", LocalIP: "10.0.20.2", Prefixes: []string{"10.0.20.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var kept, skipped model.Host
	for _, ip := range []string{"10.0.20.5", "10.0.20.6"} {
		got, err := h.st.UpsertHost(ctx, model.Host{
			MissionID: h.mis.ID, NetworkID: other.ID, IP: ip,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ip == "10.0.20.5" {
			kept = got
		} else {
			skipped = got
		}
	}
	status := model.TriageSkipped
	if _, err := h.st.SetHostTriage(ctx, skipped.ID, &status, nil, 0); err != nil {
		t.Fatal(err)
	}

	sc, err := h.st.CreateScan(ctx, model.Scan{
		MissionID: h.mis.ID, NetworkID: h.net.ID,
		Kind: model.ScanSegmentation, Options: defaultOptions(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.runner.plan(ctx, sc); err != nil {
		t.Fatalf("plan: %v", err)
	}

	units, err := h.st.ClaimWork(ctx, sc.ID, model.PhaseSegment, 100)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int64]bool{}
	for _, u := range units {
		var p segmentPayload
		if err := json.Unmarshal(u.Payload, &p); err != nil {
			t.Fatal(err)
		}
		for _, id := range p.HostIDs {
			seen[id] = true
		}
	}
	if !seen[kept.ID] {
		t.Fatal("the host that is in scope was not planned")
	}
	if seen[skipped.ID] {
		t.Fatal("a skipped host was still planned as a segmentation target")
	}
}
