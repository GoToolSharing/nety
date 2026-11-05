package api

import (
	"net/http"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// An operator on a mission must see who else is on it. Listing every account is an
// administrator's privilege, so returning bare ids left a plain operator with an empty
// team on a mission they belong to.
func TestOperatorSeesTheMissionTeam(t *testing.T) {
	e := newEnv(t)
	e.newUser("root", model.RoleAdmin)
	e.newUser("alice", model.RoleOperator)
	e.newUser("bob", model.RoleOperator)
	e.newUser("mallory", model.RoleOperator)

	admin := e.login("root")
	alice := e.login("alice")
	bob := e.login("bob")
	mallory := e.login("mallory")

	m := admin.createMission("ACME")
	if got := admin.do("PUT", "/api/missions/"+itoa(m.ID)+"/members", map[string]any{
		"user_ids": []int64{admin.user.ID, alice.user.ID, bob.user.ID},
	}, nil); got != http.StatusOK {
		t.Fatalf("set members: %d", got)
	}

	var resp struct {
		UserIDs []int64         `json:"user_ids"`
		Members []missionMember `json:"members"`
	}
	if got := alice.do("GET", "/api/missions/"+itoa(m.ID)+"/members", nil, &resp); got != http.StatusOK {
		t.Fatalf("an operator on the mission must read its team, got %d", got)
	}
	if len(resp.Members) != 3 {
		t.Fatalf("expected 3 members, got %d (%+v)", len(resp.Members), resp.Members)
	}
	byName := map[string]missionMember{}
	for _, mm := range resp.Members {
		byName[mm.Username] = mm
	}
	if byName["bob"].DisplayName == "" && byName["bob"].Username != "bob" {
		t.Fatalf("members should carry enough to display them: %+v", resp.Members)
	}
	if byName["root"].Role != model.RoleAdmin {
		t.Fatalf("roles should come back: %+v", resp.Members)
	}
	// The ids are still there for the admin dialog.
	if len(resp.UserIDs) != 3 {
		t.Fatalf("user_ids should still be returned, got %v", resp.UserIDs)
	}

	// Listing every account stays an administrator's privilege.
	if got := alice.do("GET", "/api/users", nil, nil); got != http.StatusForbidden {
		t.Fatalf("an operator must not list every account, got %d", got)
	}
	// And someone outside the mission still sees nothing.
	if got := mallory.do("GET", "/api/missions/"+itoa(m.ID)+"/members", nil, nil); got != http.StatusNotFound {
		t.Fatalf("a non-member must not read the team, got %d", got)
	}
}
