package store

import (
	"context"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// A reset is the step before handing a mission back for a second pass: the
// results go, the setup stays. Re-creating the VLANs by hand would make it
// useless.
func TestResetMissionDataKeepsTheSetupAndDropsTheResults(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	mis, err := st.CreateMission(ctx, model.Mission{Name: "client A", ScopeCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	net, err := st.CreateNetwork(ctx, model.Network{
		MissionID: mis.ID, Name: "VLAN10", VLANID: 10,
		Interface: "eth0", Prefixes: []string{"10.0.0.0/24"},
		L2: model.L2Info{NativeVLAN: 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, model.User{Username: "op", Role: model.RoleOperator})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetMissionMembers(ctx, mis.ID, []int64{user.ID}); err != nil {
		t.Fatal(err)
	}

	sc, err := st.CreateScan(ctx, model.Scan{MissionID: mis.ID, NetworkID: net.ID, Kind: model.ScanDiscovery})
	if err != nil {
		t.Fatal(err)
	}
	host, err := st.UpsertHost(ctx, model.Host{MissionID: mis.ID, NetworkID: net.ID, IP: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertService(ctx, model.Service{
		MissionID: mis.ID, NetworkID: net.ID, HostID: host.ID,
		IP: "10.0.0.5", Port: 22, Protocol: model.TCP, State: model.PortOpen,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertFinding(ctx, model.Finding{
		MissionID: mis.ID, NetworkID: net.ID, HostID: host.ID, IP: "10.0.0.5",
		Port: 22, Protocol: model.TCP, CheckID: "demo", Title: "Demo", Severity: model.SevLow,
	}); err != nil {
		t.Fatal(err)
	}

	counts, err := st.ResetMissionData(ctx, mis.ID)
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if counts.Scans != 1 || counts.Hosts != 1 || counts.Services != 1 || counts.Findings != 1 {
		t.Fatalf("counts do not describe what was there: %+v", counts)
	}

	// Gone.
	if hosts, _ := st.ListHosts(ctx, mis.ID, 0); len(hosts) != 0 {
		t.Fatalf("hosts survived: %d", len(hosts))
	}
	if services, _ := st.ListServices(ctx, ServiceFilter{MissionID: mis.ID, IncludeSkippedHosts: true}); len(services) != 0 {
		t.Fatalf("services survived: %d", len(services))
	}
	if findings, _ := st.ListFindings(ctx, FindingFilter{MissionID: mis.ID, IncludeSkippedHosts: true}); len(findings) != 0 {
		t.Fatalf("findings survived: %d", len(findings))
	}
	if scans, _ := st.ListScans(ctx, mis.ID, 100); len(scans) != 0 {
		t.Fatalf("scans survived: %d", len(scans))
	}
	if _, err := st.Scan(ctx, sc.ID); err == nil {
		t.Fatal("the scan is still readable by id")
	}

	// Kept.
	got, err := st.Mission(ctx, mis.ID)
	if err != nil {
		t.Fatalf("the mission itself was deleted: %v", err)
	}
	if len(got.ScopeCIDRs) != 1 {
		t.Fatalf("the scope was lost: %+v", got.ScopeCIDRs)
	}
	nets, err := st.ListNetworks(ctx, mis.ID)
	if err != nil || len(nets) != 1 {
		t.Fatalf("the networks were lost: %d, %v", len(nets), err)
	}
	if nets[0].Interface != "eth0" || nets[0].VLANID != 10 {
		t.Fatalf("the network setup was altered: %+v", nets[0])
	}
	if nets[0].L2.NativeVLAN != 0 {
		t.Fatalf("the L2 panel is scan output and should have been cleared: %+v", nets[0].L2)
	}
	members, err := st.MissionMembers(ctx, mis.ID)
	if err != nil || len(members) != 1 {
		t.Fatalf("the team was lost: %d, %v", len(members), err)
	}
}
