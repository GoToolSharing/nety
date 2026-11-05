package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// A scan of a VLAN only means something next to the previous one, which is
// what this route answers. The seeding below walks the two passes in order so
// the finish stamps come out in the right order too.

// runScan records one pass over a network: a scan that completes, with the
// rows it found written against it.
func runScan(t *testing.T, e *testEnv, missionID, networkID int64, found func(scanID int64)) model.Scan {
	t.Helper()
	ctx := t.Context()
	sc, err := e.store.CreateScan(ctx, model.Scan{
		MissionID: missionID, NetworkID: networkID, Kind: model.ScanDiscovery,
	})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	found(sc.ID)
	if err := e.store.SetScanStatus(ctx, sc.ID, model.ScanCompleted, ""); err != nil {
		t.Fatalf("complete scan: %v", err)
	}
	// Finish stamps are milliseconds, and the diff reads them to tell the two
	// passes apart, so give the next one a moment of its own.
	time.Sleep(3 * time.Millisecond)
	out, err := e.store.Scan(ctx, sc.ID)
	if err != nil {
		t.Fatalf("reload scan: %v", err)
	}
	return out
}

func seedDiffHost(t *testing.T, e *testEnv, missionID, networkID, scanID int64, ip string) {
	t.Helper()
	if _, err := e.store.UpsertHost(t.Context(), model.Host{
		MissionID: missionID, NetworkID: networkID, IP: ip, LastScanID: scanID,
	}); err != nil {
		t.Fatalf("seed host %s: %v", ip, err)
	}
}

func TestScanDiffEndpoint(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	monday := runScan(t, e, m.ID, n.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.5")
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.6")
	})
	wednesday := runScan(t, e, m.ID, n.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.5")
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.7")
	})

	base := "/api/missions/" + itoa(m.ID) + "/scans/"

	// With no `against`, the server picks the previous completed scan and
	// says which one it was.
	var diff model.ScanDiff
	if st := alice.do("GET", base+itoa(wednesday.ID)+"/diff", nil, &diff); st != http.StatusOK {
		t.Fatalf("diff: status %d", st)
	}
	if diff.From == nil || diff.From.ID != monday.ID {
		t.Fatalf("expected the baseline to be scan #%d, got %+v", monday.ID, diff.From)
	}
	if !diff.FromPicked {
		t.Error("the response must say the baseline was picked by the server")
	}
	if !diff.Changed || diff.Counts.HostsAdded != 1 || diff.Counts.HostsRemoved != 1 ||
		diff.Counts.HostsSame != 1 {
		t.Fatalf("unexpected counts: %+v", diff.Counts)
	}

	// Naming it explicitly gives the same answer, and no longer claims the
	// server chose it.
	var explicit model.ScanDiff
	if st := alice.do("GET", base+itoa(wednesday.ID)+"/diff?against="+itoa(monday.ID),
		nil, &explicit); st != http.StatusOK {
		t.Fatalf("explicit diff: status %d", st)
	}
	if explicit.FromPicked || explicit.Counts != diff.Counts {
		t.Fatalf("explicit diff disagrees: picked=%v counts=%+v", explicit.FromPicked, explicit.Counts)
	}

	// The first scan of a network has nothing behind it, which is an answer,
	// not an error.
	var first model.ScanDiff
	if st := alice.do("GET", base+itoa(monday.ID)+"/diff", nil, &first); st != http.StatusOK {
		t.Fatalf("first scan diff: status %d", st)
	}
	if first.From != nil || first.Message == "" {
		t.Fatalf("the first scan should come back with no baseline and a reason: %+v", first)
	}

	if st := alice.do("GET", base+itoa(wednesday.ID)+"/diff?against="+itoa(wednesday.ID), nil, nil); st != http.StatusBadRequest {
		t.Errorf("comparing a scan with itself should be refused, got %d", st)
	}

	// Two scans of different networks have nothing in common to compare.
	other := alice.createNetwork(m.ID, "VLAN20")
	elsewhere := runScan(t, e, m.ID, other.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, other.ID, id, "10.1.0.5")
	})
	if st := alice.do("GET", base+itoa(wednesday.ID)+"/diff?against="+itoa(elsewhere.ID), nil, nil); st != http.StatusBadRequest {
		t.Errorf("a cross-network diff should be refused, got %d", st)
	}
}

// TestScanDiffIsMissionScoped keeps a diff from being a way round mission
// membership, and from confirming that another mission's scan exists.
func TestScanDiffIsMissionScoped(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	e.newUser("bob", model.RoleOperator)
	alice := e.login("alice")
	bob := e.login("bob")

	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	scan := runScan(t, e, m.ID, n.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.5")
	})

	if st := bob.do("GET", "/api/missions/"+itoa(m.ID)+"/scans/"+itoa(scan.ID)+"/diff", nil, nil); st != http.StatusNotFound {
		t.Fatalf("a non-member must not reach the diff, got %d", st)
	}

	// Bob's own mission cannot be used to read Alice's scan either.
	his := bob.createMission("OTHER")
	if st := bob.do("GET", "/api/missions/"+itoa(his.ID)+"/scans/"+itoa(scan.ID)+"/diff", nil, nil); st != http.StatusNotFound {
		t.Fatalf("a scan of another mission must not be reachable, got %d", st)
	}
}

// TestExportCarriesTheDiff checks the wiring rather than the rendering: an
// export asked for without naming a scan still works out which two it is
// about, and the diff travels in the file.
func TestExportCarriesTheDiff(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	runScan(t, e, m.ID, n.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.5")
	})
	runScan(t, e, m.ID, n.ID, func(id int64) {
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.5")
		seedDiffHost(t, e, m.ID, n.ID, id, "10.0.0.9")
	})

	status, body, _ := alice.raw("GET", "/api/missions/"+itoa(m.ID)+"/export?format=csv-diff")
	if status != http.StatusOK {
		t.Fatalf("export: status %d", status)
	}
	sheet := string(body)
	if !strings.Contains(sheet, "10.0.0.9") || !strings.Contains(sheet, "added") {
		t.Fatalf("the diff sheet should list the new host:\n%s", sheet)
	}

	var dump model.MissionData
	if st := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/export?format=json", nil, &dump); st != http.StatusOK {
		t.Fatalf("json export: status %d", st)
	}
	if dump.Diff == nil || dump.Diff.Counts.HostsAdded != 1 {
		t.Fatalf("the JSON dump should carry the diff, got %+v", dump.Diff)
	}
}
