package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// A scope that cannot be enumerated must be refused while the operator is still looking
// at the form. Before this, an IPv6 /64 was accepted, and the planner then allocated work
// units until the kernel killed the process; all the operator saw was the server
// restarting.
func TestImpossibleScopeIsRefused(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")

	for _, target := range []string{"fe80::/64", "2001:db8::/32", "10.0.0.0/7"} {
		status, body, _ := alice.rawPost("/api/missions/"+itoa(m.ID)+"/scans", map[string]any{
			"network_id": n.ID, "kind": "discovery",
			"options": map[string]any{"tcp_ports": "80", "targets": []string{target}},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("%s should be refused, got %d", target, status)
		}
		if !strings.Contains(string(body), "targets") {
			t.Fatalf("%s: unhelpful error %s", target, body)
		}
	}

	// Sizes an operator actually uses still go through.
	for _, target := range []string{"10.0.0.0/8", "10.20.30.0/24", "2001:db8::/112"} {
		status, body, _ := alice.rawPost("/api/missions/"+itoa(m.ID)+"/scans", map[string]any{
			"network_id": n.ID, "kind": "discovery",
			"options": map[string]any{"tcp_ports": "80", "targets": []string{target}},
		})
		if status != http.StatusCreated {
			t.Fatalf("%s should be accepted, got %d: %s", target, status, body)
		}
	}
}
