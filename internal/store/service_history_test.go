package store

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// The case the diff could not see before: a machine that kept its address and whose
// service was upgraded between two scans. The service row holds one merged description,
// so the previous version only survives because the upsert writes it down as it replaces
// it.
func TestDiffSeesAVersionChangeOnAnAddressThatDidNotMove(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	const netID = 2

	tA := time.Now().UTC().Add(-48 * time.Hour)
	tB := time.Now().UTC().Add(-2 * time.Hour)

	// This database has been recording changes since before the first scan, which is what
	// any mission started after the upgrade looks like.
	if err := s.SetSetting(ctx, "service_changes_since",
		strconv.FormatInt(tA.Add(-24*time.Hour).UnixMilli(), 10)); err != nil {
		t.Fatal(err)
	}

	first := completedScan(t, s, m.ID, netID, tA)
	h, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: netID, IP: "10.1.0.5",
		FirstSeen: tA.Add(-time.Minute), LastSeen: tA.Add(-time.Minute), LastScanID: first.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	before := model.Service{
		MissionID: m.ID, NetworkID: netID, HostID: h.ID, IP: h.IP, Port: 22,
		Protocol: model.TCP, State: model.PortOpen, Name: "ssh", Product: "OpenSSH",
		Version: "8.4p1", Confidence: 90,
		FirstSeen: tA.Add(-time.Minute), LastSeen: tA.Add(-time.Minute), LastScanID: first.ID,
	}
	if _, err := s.UpsertService(ctx, before); err != nil {
		t.Fatal(err)
	}

	second := completedScan(t, s, m.ID, netID, tB)
	if _, err := s.UpsertHost(ctx, model.Host{
		MissionID: m.ID, NetworkID: netID, IP: "10.1.0.5",
		LastSeen: tB.Add(-time.Minute), LastScanID: second.ID,
	}); err != nil {
		t.Fatal(err)
	}
	after := before
	after.Version = "9.6p1"
	after.LastSeen = tB.Add(-time.Minute)
	after.LastScanID = second.ID
	if _, err := s.UpsertService(ctx, after); err != nil {
		t.Fatal(err)
	}

	diff, err := s.ScanDiff(ctx, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if diff.Counts.ServicesChanged != 1 {
		t.Fatalf("the version change was missed: %+v", diff.Counts)
	}
	var row *model.ScanDiffService
	for i := range diff.Services {
		if diff.Services[i].Change == model.DiffChanged {
			row = &diff.Services[i]
		}
	}
	if row == nil {
		t.Fatal("no changed service row")
	}
	if row.PreviousVersion != "8.4p1" || row.Version != "9.6p1" {
		t.Fatalf("wrong before and after: %q -> %q", row.PreviousVersion, row.Version)
	}
	if row.IP != "10.1.0.5" || row.PreviousIP != "" {
		t.Fatalf("the machine did not move, so no previous address: %+v", row)
	}
	for _, c := range diff.Caveats {
		if strings.Contains(c, "predates the recording") {
			t.Fatalf("the history covers this comparison, so no history caveat: %q", c)
		}
	}
}

// A re-scan that finds the same thing writes no history at all.
func TestAnUnchangedRescanRecordsNothing(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	sv := model.Service{
		MissionID: m.ID, NetworkID: 2, IP: "10.1.0.9", Port: 443,
		Protocol: model.TCP, State: model.PortOpen, Name: "https",
		Product: "nginx", Version: "1.24.0", Confidence: 90, LastScanID: 1,
	}
	if _, err := s.UpsertService(ctx, sv); err != nil {
		t.Fatal(err)
	}
	sv.LastScanID = 2
	if _, err := s.UpsertService(ctx, sv); err != nil {
		t.Fatal(err)
	}

	changes, err := s.serviceChangesBetween(ctx, m.ID,
		time.Now().UTC().Add(-time.Hour), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Fatalf("nothing changed, so nothing should have been written: %+v", changes)
	}
}
