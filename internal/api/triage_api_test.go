package api

import (
	"net/http"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

func seedService(t *testing.T, e *testEnv, missionID, networkID int64, ip string, port int) model.Service {
	t.Helper()
	sv, err := e.store.UpsertService(t.Context(), model.Service{
		MissionID: missionID, NetworkID: networkID, IP: ip, Port: port,
		Protocol: model.TCP, State: model.PortOpen, Name: "http",
	})
	if err != nil {
		t.Fatalf("seed service: %v", err)
	}
	return sv
}

func TestTriageEndpoints(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	sv := seedService(t, e, m.ID, n.ID, "10.0.0.5", 445)

	// A fresh service is to do, and the summary says so.
	var summary struct {
		Counts   map[string]int `json:"counts"`
		Total    int            `json:"total"`
		Reviewed int            `json:"reviewed"`
	}
	if got := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/triage", nil, &summary); got != http.StatusOK {
		t.Fatalf("summary: %d", got)
	}
	if summary.Total != 1 || summary.Reviewed != 0 || summary.Counts["todo"] != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	// Set a status and a note.
	var updated model.Service
	if got := alice.do("PATCH", "/api/services/"+itoa(sv.ID), map[string]any{
		"status": "flagged", "note": "identifiants par defaut acceptes",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch: %d", got)
	}
	if updated.Triage.Status != model.TriageFlagged {
		t.Fatalf("status not applied: %+v", updated.Triage)
	}
	if updated.Triage.UpdatedByName != "alice" {
		t.Fatalf("author name not resolved: %+v", updated.Triage)
	}

	// A status-only update must not clear the note.
	if got := alice.do("PATCH", "/api/services/"+itoa(sv.ID), map[string]any{
		"status": "done",
	}, &updated); got != http.StatusOK {
		t.Fatalf("patch status only: %d", got)
	}
	if updated.Triage.Note == "" {
		t.Fatal("a status-only update cleared the note")
	}

	// Bad input is refused.
	if got := alice.do("PATCH", "/api/services/"+itoa(sv.ID), map[string]any{
		"status": "nonsense",
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("an unknown status must be refused, got %d", got)
	}
	if got := alice.do("PATCH", "/api/services/"+itoa(sv.ID), map[string]any{}, nil); got != http.StatusBadRequest {
		t.Fatalf("an empty patch must be refused, got %d", got)
	}

	// The list can be narrowed to a status.
	var listed []model.Service
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services?triage=done", nil, &listed)
	if len(listed) != 1 {
		t.Fatalf("expected the done service, got %d", len(listed))
	}
	alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services?triage=todo", nil, &listed)
	if len(listed) != 0 {
		t.Fatalf("expected nothing left to do, got %d", len(listed))
	}
	if got := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/services?triage=bogus", nil, nil); got != http.StatusBadRequest {
		t.Fatalf("an unknown triage filter must be refused, got %d", got)
	}
}

func TestBulkTriageEndpoint(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	var ids []int64
	for _, port := range []int{80, 443, 8080} {
		ids = append(ids, seedService(t, e, m.ID, n.ID, "10.0.0.6", port).ID)
	}

	var res struct {
		Updated int `json:"updated"`
	}
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/services/triage", map[string]any{
		"service_ids": ids, "status": "skipped",
	}, &res); got != http.StatusOK {
		t.Fatalf("bulk: %d", got)
	}
	if res.Updated != 3 {
		t.Fatalf("expected 3 updated, got %d", res.Updated)
	}
	if got := alice.do("POST", "/api/missions/"+itoa(m.ID)+"/services/triage", map[string]any{
		"service_ids": []int64{}, "status": "done",
	}, nil); got != http.StatusBadRequest {
		t.Fatalf("an empty selection must be refused, got %d", got)
	}
}

// A viewer may read the triage but must not change it, and a non-member must
// not see the service at all.
func TestTriagePermissions(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	e.newUser("vicky", model.RoleViewer)
	e.newUser("mallory", model.RoleOperator)
	e.newUser("root", model.RoleAdmin)

	alice := e.login("alice")
	admin := e.login("root")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	sv := seedService(t, e, m.ID, n.ID, "10.0.0.7", 22)

	vicky := e.login("vicky")
	admin.do("PUT", "/api/missions/"+itoa(m.ID)+"/members",
		map[string]any{"user_ids": []int64{alice.user.ID, vicky.user.ID}}, nil)

	if got := vicky.do("GET", "/api/services/"+itoa(sv.ID), nil, nil); got != http.StatusOK {
		t.Fatalf("a viewer should be able to read a service, got %d", got)
	}
	if got := vicky.do("PATCH", "/api/services/"+itoa(sv.ID),
		map[string]any{"status": "done"}, nil); got != http.StatusForbidden {
		t.Fatalf("a viewer must not change the triage, got %d", got)
	}

	mallory := e.login("mallory")
	if got := mallory.do("GET", "/api/services/"+itoa(sv.ID), nil, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not see the service, got %d", got)
	}
	if got := mallory.do("PATCH", "/api/services/"+itoa(sv.ID),
		map[string]any{"status": "done"}, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not triage the service, got %d", got)
	}
}

var _ = store.ErrNotFound
