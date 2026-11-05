package api

import (
	"net/http"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// Skipping a host, or a machine, is how an operator parks something that is
// out of scope: the client's own workstation, their own laptop, a device the
// client said not to touch. Everything that belongs to it has to leave the
// working views, and come back untouched when it is put back in scope.

// seedParkedHost creates a host with one service and one finding on it, which
// is the shape every test here works on.
func seedParkedHost(t *testing.T, e *testEnv, missionID, networkID int64, ip string) (model.Host, model.Service, model.Finding) {
	t.Helper()
	ctx := t.Context()
	h, err := e.store.UpsertHost(ctx, model.Host{
		MissionID: missionID, NetworkID: networkID, IP: ip, Hostname: "ws-042",
	})
	if err != nil {
		t.Fatalf("seed host: %v", err)
	}
	sv, err := e.store.UpsertService(ctx, model.Service{
		MissionID: missionID, NetworkID: networkID, HostID: h.ID, IP: ip, Port: 445,
		Protocol: model.TCP, State: model.PortOpen, Name: "microsoft-ds",
	})
	if err != nil {
		t.Fatalf("seed service: %v", err)
	}
	f, err := e.store.UpsertFinding(ctx, model.Finding{
		MissionID: missionID, NetworkID: networkID, HostID: h.ID, ServiceID: sv.ID,
		IP: ip, Port: 445, Protocol: model.TCP, CheckID: "smb-signing-not-required",
		Title: "SMB signing not required", Severity: model.SevMedium,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return h, sv, f
}

func TestHostTriageEndpoints(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	h, _, _ := seedParkedHost(t, e, m.ID, n.ID, "10.0.0.5")

	// A fresh host is to do, and the summary says so beside the services and
	// the findings.
	var summary struct {
		Hosts struct {
			Counts   map[string]int `json:"counts"`
			Total    int            `json:"total"`
			Reviewed int            `json:"reviewed"`
		} `json:"hosts"`
	}
	if got := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/triage", nil, &summary); got != http.StatusOK {
		t.Fatalf("summary: %d", got)
	}
	if summary.Hosts.Total != 1 || summary.Hosts.Reviewed != 0 || summary.Hosts.Counts["todo"] != 1 {
		t.Fatalf("unexpected host summary: %+v", summary.Hosts)
	}

	// Set a status and a note.
	var updated model.Host
	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{
		"status": "skipped", "note": "poste de travail du client, hors perimetre",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch: %d", got)
	}
	if updated.Triage.Status != model.TriageSkipped {
		t.Fatalf("status not applied: %+v", updated.Triage)
	}
	if updated.Triage.UpdatedByName != "alice" {
		t.Fatalf("author name not resolved: %+v", updated.Triage)
	}

	// A status-only update must not clear the note.
	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{
		"status": "todo",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch status only: %d", got)
	}
	if updated.Triage.Note == "" {
		t.Fatal("a status-only update cleared the note")
	}

	// Bad input is refused.
	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{
		"status": "nonsense",
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("an unknown status must be refused, got %d", got)
	}
	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{}, nil); got != http.StatusBadRequest {
		t.Fatalf("an empty patch must be refused, got %d", got)
	}

	// And a selection can be done in one call.
	var res struct {
		Updated int `json:"updated"`
	}
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/hosts/triage", map[string]any{
		"host_ids": []int64{h.ID}, "status": "skipped",
	}, &res); got != http.StatusOK {
		t.Fatalf("bulk: %d", got)
	}
	if res.Updated != 1 {
		t.Fatalf("expected 1 updated, got %d", res.Updated)
	}
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/hosts/triage", map[string]any{
		"host_ids": []int64{}, "status": "skipped",
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("an empty selection must be refused, got %d", got)
	}
}

// TestSkippingAHostHidesItsRows is the behaviour the operator asked for, read
// through the API exactly as the browser reads it.
func TestSkippingAHostHidesItsRows(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	h, sv, f := seedParkedHost(t, e, m.ID, n.ID, "10.0.0.5")
	// Another host nobody is parking, to prove only one disappears.
	seedParkedHost(t, e, m.ID, n.ID, "10.0.0.6")

	// The operator has already been through this service and this finding.
	if got := alice.do("PATCH", "/api/services/"+itoa(sv.ID), map[string]any{
		"status": "flagged", "note": "relais SMB confirme",
	}, nil); got != http.StatusOK {
		t.Fatalf("triage service: %d", got)
	}
	if got := alice.do("PATCH", "/api/findings/"+itoa(f.ID), map[string]any{
		"status": "flagged",
	}, nil); got != http.StatusOK {
		t.Fatalf("triage finding: %d", got)
	}

	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{
		"status": "skipped",
	}, nil); got != http.StatusOK {
		t.Fatalf("skip host: %d", got)
	}

	var services []model.Service
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services", nil, &services)
	if len(services) != 1 || services[0].HostID == h.ID {
		t.Fatalf("the skipped host's services should be gone: %+v", services)
	}
	var findings []model.Finding
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/findings", nil, &findings)
	if len(findings) != 1 || findings[0].HostID == h.ID {
		t.Fatalf("the skipped host's findings should be gone: %+v", findings)
	}

	// include_skipped brings them back, with the operator's own work on them
	// exactly as it was.
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services?include_skipped=true", nil, &services)
	if len(services) != 2 {
		t.Fatalf("include_skipped should show both hosts, got %d", len(services))
	}
	var hidden *model.Service
	for i := range services {
		if services[i].ID == sv.ID {
			hidden = &services[i]
		}
	}
	if hidden == nil || hidden.Triage.Status != model.TriageFlagged || hidden.Triage.Note == "" {
		t.Fatalf("the hidden service lost its own triage: %+v", hidden)
	}
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/findings?include_skipped=true", nil, &findings)
	if len(findings) != 2 {
		t.Fatalf("include_skipped should show both hosts' findings, got %d", len(findings))
	}

	// The host is still listed, which is where it gets put back in scope, and
	// its own screen still has everything.
	var hosts []model.Host
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/hosts", nil, &hosts)
	if len(hosts) != 2 {
		t.Fatalf("a skipped host must stay on the hosts screen, got %d", len(hosts))
	}
	var detail struct {
		Host     model.Host      `json:"host"`
		Services []model.Service `json:"services"`
		Findings []model.Finding `json:"findings"`
	}
	if got := alice.do("GET", "/api/hosts/"+itoa(h.ID), nil, &detail); got != http.StatusOK {
		t.Fatalf("host detail: %d", got)
	}
	if len(detail.Services) != 1 || len(detail.Findings) != 1 {
		t.Fatalf("the host's own screen must show its rows: %+v", detail)
	}

	// The counts the UI puts above those tables agree with them, and say what
	// was left out.
	var summary struct {
		Total    int `json:"total"`
		Findings struct {
			Total int `json:"total"`
		} `json:"findings"`
		Hidden struct {
			Hosts    int      `json:"hosts"`
			Labels   []string `json:"host_labels"`
			Services int      `json:"services"`
			Findings int      `json:"findings"`
		} `json:"hidden"`
	}
	if got := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/triage", nil, &summary); got != http.StatusOK {
		t.Fatalf("summary: %d", got)
	}
	if summary.Total != 1 || summary.Findings.Total != 1 {
		t.Fatalf("the totals must match the listings: %+v", summary)
	}
	if summary.Hidden.Hosts != 1 || summary.Hidden.Services != 1 || summary.Hidden.Findings != 1 {
		t.Fatalf("the summary must say what is hidden: %+v", summary.Hidden)
	}
	if len(summary.Hidden.Labels) != 1 || summary.Hidden.Labels[0] != "ws-042" {
		t.Fatalf("and name the host: %+v", summary.Hidden.Labels)
	}

	// Putting it back in scope restores the listing.
	if got := alice.do("PATCH", "/api/hosts/"+itoa(h.ID), map[string]any{
		"status": "todo",
	}, nil); got != http.StatusOK {
		t.Fatalf("un-skip: %d", got)
	}
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services", nil, &services)
	if len(services) != 2 {
		t.Fatalf("un-skipping must bring the services back, got %d", len(services))
	}
}

// TestSkippingAMachineCoversEveryAddress: the status is set on the machine and
// every address it answers on follows.
func TestSkippingAMachineCoversEveryAddress(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	asset, err := e.store.SaveAsset(t.Context(), model.Asset{MissionID: m.ID, Label: "ws-042"})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	for _, ip := range []string{"10.0.0.5", "10.0.1.5"} {
		h, _, _ := seedParkedHost(t, e, m.ID, n.ID, ip)
		if err := e.store.SetHostAsset(t.Context(), h.ID, asset.ID); err != nil {
			t.Fatalf("attach: %v", err)
		}
	}

	var updated model.Asset
	if got := alice.do("PATCH", "/api/assets/"+itoa(asset.ID), map[string]any{
		"status": "skipped", "note": "machine du client, hors perimetre",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch asset: %d", got)
	}
	if updated.Triage.Status != model.TriageSkipped || updated.Triage.Note == "" {
		t.Fatalf("asset triage not applied: %+v", updated.Triage)
	}

	var hosts []model.Host
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/hosts", nil, &hosts)
	if len(hosts) != 2 {
		t.Fatalf("expected both addresses, got %d", len(hosts))
	}
	for _, h := range hosts {
		if h.Triage.Status != model.TriageSkipped {
			t.Fatalf("address %s did not follow the machine: %+v", h.IP, h.Triage)
		}
	}
	var services []model.Service
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services", nil, &services)
	if len(services) != 0 {
		t.Fatalf("the machine's services should all be hidden, got %d", len(services))
	}

	// Editing the label still works, and leaves the status alone.
	if got := alice.do("PATCH", "/api/assets/"+itoa(asset.ID), map[string]any{
		"label": "ws-042.acme.lan",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch label: %d", got)
	}
	if updated.Label != "ws-042.acme.lan" || updated.Triage.Status != model.TriageSkipped {
		t.Fatalf("an edit must not disturb the triage: %+v", updated)
	}

	// And a selection of machines can be parked in one call.
	var res struct {
		Updated int `json:"updated"`
	}
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/assets/triage", map[string]any{
		"asset_ids": []int64{asset.ID}, "status": "todo",
	}, &res); got != http.StatusOK {
		t.Fatalf("bulk: %d", got)
	}
	if res.Updated != 1 {
		t.Fatalf("expected 1 machine updated, got %d", res.Updated)
	}
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services", nil, &services)
	if len(services) != 2 {
		t.Fatalf("putting the machine back in scope must restore its services, got %d", len(services))
	}
}

// A viewer may read the triage but must not change it, and a non-member must
// not see the host or the machine at all.
func TestHostAndAssetTriagePermissions(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	e.newUser("vicky", model.RoleViewer)
	e.newUser("mallory", model.RoleOperator)
	e.newUser("root", model.RoleAdmin)

	alice := e.login("alice")
	admin := e.login("root")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	h, _, _ := seedParkedHost(t, e, m.ID, n.ID, "10.0.0.7")
	asset, err := e.store.SaveAsset(t.Context(), model.Asset{MissionID: m.ID, Label: "ws-042"})
	if err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	vicky := e.login("vicky")
	admin.do("PUT", "/api/missions/"+itoa(m.ID)+"/members",
		map[string]any{"user_ids": []int64{alice.user.ID, vicky.user.ID}}, nil)

	if got := vicky.do("GET", "/api/hosts/"+itoa(h.ID), nil, nil); got != http.StatusOK {
		t.Fatalf("a viewer should be able to read a host, got %d", got)
	}
	if got := vicky.do("PATCH", "/api/hosts/"+itoa(h.ID),
		map[string]any{"status": "skipped"}, nil); got != http.StatusForbidden {
		t.Fatalf("a viewer must not change the triage, got %d", got)
	}
	if got := vicky.do("POST", "/api/missions/"+itoa(m.ID)+"/hosts/triage",
		map[string]any{"host_ids": []int64{h.ID}, "status": "skipped"}, nil); got != http.StatusForbidden {
		t.Fatalf("a viewer must not bulk triage hosts, got %d", got)
	}
	if got := vicky.do("PATCH", "/api/assets/"+itoa(asset.ID),
		map[string]any{"status": "skipped"}, nil); got != http.StatusForbidden {
		t.Fatalf("a viewer must not triage a machine, got %d", got)
	}

	mallory := e.login("mallory")
	if got := mallory.do("GET", "/api/hosts/"+itoa(h.ID), nil, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not see the host, got %d", got)
	}
	if got := mallory.do("PATCH", "/api/hosts/"+itoa(h.ID),
		map[string]any{"status": "skipped"}, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not triage the host, got %d", got)
	}
	if got := mallory.do("POST", "/api/missions/"+itoa(m.ID)+"/assets/triage",
		map[string]any{"asset_ids": []int64{asset.ID}, "status": "skipped"}, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not bulk triage machines, got %d", got)
	}
}
