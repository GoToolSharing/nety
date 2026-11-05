package store

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// seedMission fills a mission with one of everything that has to survive a round trip,
// including the parts no report ever shows: a paused scan's work units, its log, and an
// operator's note against a service.
func seedMission(t *testing.T, s *Store, name string) (model.Mission, model.User) {
	t.Helper()
	ctx := context.Background()

	op, err := s.CreateUser(ctx, model.User{
		Username: "operator", DisplayName: "The Operator", Role: model.RoleOperator,
	})
	if err != nil {
		t.Fatal(err)
	}
	mis, err := s.CreateMission(ctx, model.Mission{
		Name: name, Client: "ACME", Description: "internal",
		ScopeCIDRs: []string{"10.0.0.0/8"}, ExcludeCIDRs: []string{"10.0.0.1/32"},
		CreatedBy: op.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMissionMembers(ctx, mis.ID, []int64{op.ID}); err != nil {
		t.Fatal(err)
	}
	net, err := s.CreateNetwork(ctx, model.Network{
		MissionID: mis.ID, Name: "VLAN10", VLANID: 10, Interface: "eth0",
		LocalIP: "10.0.0.2", Prefixes: []string{"10.0.0.0/24"},
		L2: model.L2Info{NativeVLAN: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	sc, err := s.CreateScan(ctx, model.Scan{
		MissionID: mis.ID, NetworkID: net.ID, Kind: model.ScanDiscovery,
		CreatedBy: op.ID, Options: model.ScanOptions{Profile: "standard", TCPPorts: "top1000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	unit, _ := json.Marshal(map[string]any{"targets": []string{"10.0.0.5"}})
	if _, err := s.AddWork(ctx, sc.ID, model.PhaseDiscovery, []json.RawMessage{unit}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendScanLog(ctx, sc.ID, "info", "scope: 10.0.0.0/24"); err != nil {
		t.Fatal(err)
	}

	asset, err := s.SaveAsset(ctx, model.Asset{
		MissionID: mis.ID, Label: "srv-file", Hostname: "srv-file", Kind: "server",
	})
	if err != nil {
		t.Fatal(err)
	}
	host, err := s.UpsertHost(ctx, model.Host{
		MissionID: mis.ID, NetworkID: net.ID, AssetID: asset.ID, IP: "10.0.0.5",
		MAC: "aa:bb:cc:dd:ee:ff", Hostname: "srv-file", LastScanID: sc.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sv, err := s.UpsertService(ctx, model.Service{
		MissionID: mis.ID, NetworkID: net.ID, HostID: host.ID, IP: host.IP,
		Port: 445, Protocol: model.TCP, State: model.PortOpen, Name: "microsoft-ds",
		Product: "Samba", Version: "4.19.2", Confidence: 90, LastScanID: sc.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertFinding(ctx, model.Finding{
		MissionID: mis.ID, NetworkID: net.ID, HostID: host.ID, ServiceID: sv.ID,
		IP: host.IP, Port: 445, Protocol: model.TCP, CheckID: "smb-signing-not-required",
		Title: "SMB signing not required", Severity: model.SevMedium, LastScanID: sc.ID,
	}); err != nil {
		t.Fatal(err)
	}

	// The operator's own pass, which is the part a re-scan must not erase and a restore
	// must bring back with its author.
	note := "tested by hand, relay confirmed"
	status := model.TriageFlagged
	if _, err := s.SetServiceTriage(ctx, sv.ID, &status, &note, op.ID); err != nil {
		t.Fatal(err)
	}
	return mis, op
}

// A mission exported from one installation and restored on another has to come back
// whole, down to who wrote which note.
func TestMissionSurvivesAnExportAndImport(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, op := seedMission(t, src, "client A")

	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// Through the wire, so the test exercises what a file actually carries rather than
	// the in-memory values.
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(bundle); err != nil {
		t.Fatal(err)
	}
	var restored MissionBundle
	dec := json.NewDecoder(&buf)
	dec.UseNumber()
	if err := dec.Decode(&restored); err != nil {
		t.Fatal(err)
	}

	// A different installation: different ids, and the operator does not exist here.
	dst := testStore(t)
	admin, err := dst.CreateUser(ctx, model.User{Username: "admin", Role: model.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	// Burn some ids so nothing lines up by accident.
	for range 3 {
		if _, err := dst.CreateMission(ctx, model.Mission{Name: "other"}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := dst.ImportMission(ctx, restored, ImportOptions{
		CreateMissingUsers: true, OwnerID: admin.ID,
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if res.MissionID == mis.ID {
		t.Fatal("the test is not proving anything: the ids happen to match")
	}
	if res.Name != "client A" {
		t.Fatalf("mission name: %q", res.Name)
	}
	if len(res.SkippedColumns) != 0 {
		t.Fatalf("nothing should have been dropped between two identical builds: %v", res.SkippedColumns)
	}

	got, err := dst.Mission(ctx, res.MissionID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Client != "ACME" || len(got.ScopeCIDRs) != 1 || len(got.ExcludeCIDRs) != 1 {
		t.Fatalf("the mission came back incomplete: %+v", got)
	}

	nets, err := dst.ListNetworks(ctx, res.MissionID)
	if err != nil || len(nets) != 1 {
		t.Fatalf("networks: %d, %v", len(nets), err)
	}
	if nets[0].VLANID != 10 || nets[0].Interface != "eth0" || nets[0].L2.NativeVLAN != 10 {
		t.Fatalf("the network came back incomplete: %+v", nets[0])
	}

	scans, err := dst.ListScans(ctx, res.MissionID, 10)
	if err != nil || len(scans) != 1 {
		t.Fatalf("scans: %d, %v", len(scans), err)
	}
	if scans[0].NetworkID != nets[0].ID {
		t.Fatalf("the scan points at the wrong network: %d vs %d", scans[0].NetworkID, nets[0].ID)
	}
	phases, err := dst.PhaseProgress(ctx, scans[0].ID)
	if err != nil || len(phases) != 1 || phases[0].Total != 1 {
		t.Fatalf("the pending work unit did not come back: %+v, %v", phases, err)
	}
	logs, err := dst.ScanLogs(ctx, scans[0].ID, 0, 10)
	if err != nil || len(logs) == 0 {
		t.Fatalf("the scan log did not come back: %d, %v", len(logs), err)
	}

	hosts, err := dst.ListHosts(ctx, res.MissionID, 0)
	if err != nil || len(hosts) != 1 {
		t.Fatalf("hosts: %d, %v", len(hosts), err)
	}
	if hosts[0].MAC != "aa:bb:cc:dd:ee:ff" || hosts[0].AssetID == 0 {
		t.Fatalf("the host came back incomplete: %+v", hosts[0])
	}
	if hosts[0].LastScanID != scans[0].ID {
		t.Fatalf("the host points at the wrong scan: %d vs %d", hosts[0].LastScanID, scans[0].ID)
	}
	assets, err := dst.ListAssets(ctx, res.MissionID)
	if err != nil || len(assets) != 1 || assets[0].ID != hosts[0].AssetID {
		t.Fatalf("the asset did not come back attached: %+v, %v", assets, err)
	}

	services, err := dst.ListServices(ctx, ServiceFilter{MissionID: res.MissionID})
	if err != nil || len(services) != 1 {
		t.Fatalf("services: %d, %v", len(services), err)
	}
	s0 := services[0]
	if s0.Product != "Samba" || s0.Version != "4.19.2" || s0.HostID != hosts[0].ID {
		t.Fatalf("the service came back incomplete: %+v", s0)
	}
	if s0.Triage.Status != model.TriageFlagged || s0.Triage.Note != "tested by hand, relay confirmed" {
		t.Fatalf("the operator's review was lost: %+v", s0.Triage)
	}
	if s0.Triage.UpdatedBy == 0 || s0.Triage.UpdatedBy == op.ID {
		t.Fatalf("the author was not remapped to this installation: %d", s0.Triage.UpdatedBy)
	}
	if len(res.UsersCreated) != 1 || res.UsersCreated[0] != "operator" {
		t.Fatalf("the missing author should have been recreated: %+v", res.UsersCreated)
	}
	author, err := dst.UserByName(ctx, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if !author.Disabled {
		t.Fatal("a recreated author must not be able to sign in")
	}
	if author.ID != s0.Triage.UpdatedBy {
		t.Fatalf("the note points at %d, the account is %d", s0.Triage.UpdatedBy, author.ID)
	}

	findings, err := dst.ListFindings(ctx, FindingFilter{MissionID: res.MissionID})
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings: %d, %v", len(findings), err)
	}
	if findings[0].ServiceID != s0.ID || findings[0].HostID != hosts[0].ID {
		t.Fatalf("the finding lost its service or its host: %+v", findings[0])
	}

	members, err := dst.MissionMembers(ctx, res.MissionID)
	if err != nil {
		t.Fatal(err)
	}
	var hasAdmin, hasAuthor bool
	for _, id := range members {
		hasAdmin = hasAdmin || id == admin.ID
		hasAuthor = hasAuthor || id == author.ID
	}
	if !hasAdmin {
		t.Error("whoever imported the mission must be able to open it")
	}
	if !hasAuthor {
		t.Error("the original member was not restored")
	}
}

// Without the option, an account this installation does not have is reported rather than
// invented, and nothing else breaks.
func TestImportLeavesUnknownAuthorsUnattributed(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, _ := seedMission(t, src, "client B")
	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatal(err)
	}

	dst := testStore(t)
	res, err := dst.ImportMission(ctx, bundle, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.UsersUnmatched) != 1 || res.UsersUnmatched[0] != "operator" {
		t.Fatalf("the unknown author should have been reported: %+v", res.UsersUnmatched)
	}
	services, err := dst.ListServices(ctx, ServiceFilter{MissionID: res.MissionID})
	if err != nil || len(services) != 1 {
		t.Fatalf("services: %d, %v", len(services), err)
	}
	if services[0].Triage.Status != model.TriageFlagged {
		t.Fatalf("the review itself must survive even unattributed: %+v", services[0].Triage)
	}
	if services[0].Triage.UpdatedBy != 0 {
		t.Fatalf("an unmatched author must not point at an arbitrary account: %d", services[0].Triage.UpdatedBy)
	}
}

// A file that was truncated or edited is refused, rather than restored as an engagement
// that is quietly missing part of itself.
func TestImportRefusesADamagedBundle(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, _ := seedMission(t, src, "client C")
	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := range bundle.Tables {
		if bundle.Tables[i].Name == "services" && len(bundle.Tables[i].Rows) > 0 {
			bundle.Tables[i].Rows = nil
		}
	}
	dst := testStore(t)
	if _, err := dst.ImportMission(ctx, bundle, ImportOptions{}); err == nil {
		t.Fatal("a bundle whose contents do not match its checksum must be refused")
	}
}

// A bundle from a newer NETY is refused rather than half understood.
func TestImportRefusesAFutureFormat(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, _ := seedMission(t, src, "client D")
	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	bundle.Format = TransferFormat + 1
	bundle.Checksum = ""
	dst := testStore(t)
	if _, err := dst.ImportMission(ctx, bundle, ImportOptions{}); err == nil {
		t.Fatal("a bundle in a format this build does not know must be refused")
	}
}

// Two restores of the same bundle make two missions, because a restore never reconciles
// itself with an engagement that is already there.
func TestImportingTwiceMakesTwoMissions(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, _ := seedMission(t, src, "client E")
	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	dst := testStore(t)
	first, err := dst.ImportMission(ctx, bundle, ImportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := dst.ImportMission(ctx, bundle, ImportOptions{Name: "client E (restored)"})
	if err != nil {
		t.Fatal(err)
	}
	if first.MissionID == second.MissionID {
		t.Fatal("the second restore overwrote the first")
	}
	if second.Name != "client E (restored)" {
		t.Fatalf("the name override was ignored: %q", second.Name)
	}
	for _, id := range []int64{first.MissionID, second.MissionID} {
		services, err := dst.ListServices(ctx, ServiceFilter{MissionID: id})
		if err != nil || len(services) != 1 {
			t.Fatalf("mission %d: services %d, %v", id, len(services), err)
		}
	}
}

// An export is a point in time, so what it holds must not change underneath the person
// who took it.
func TestExportIsIndependentOfLaterChanges(t *testing.T) {
	ctx := context.Background()
	src := testStore(t)
	mis, _ := seedMission(t, src, "client F")
	bundle, err := src.ExportMission(ctx, mis.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.ResetMissionData(ctx, mis.ID); err != nil {
		t.Fatal(err)
	}

	dst := testStore(t)
	res, err := dst.ImportMission(ctx, bundle, ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	services, err := dst.ListServices(ctx, ServiceFilter{MissionID: res.MissionID})
	if err != nil || len(services) != 1 {
		t.Fatalf("the export should still hold what was reset away: %d, %v", len(services), err)
	}
	_ = time.Now
}
