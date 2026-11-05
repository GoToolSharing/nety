package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// The address filter and the sortable headers reach every result listing through the same
// two parameters, so they are checked together here.
func TestListingsFilterByAddressAndSort(t *testing.T) {
	e := newEnv(t)
	e.newUser("alice", model.RoleOperator)
	alice := e.login("alice")
	m := alice.createMission("ACME")
	n := alice.createNetwork(m.ID, "VLAN10")
	for _, ip := range []string{"10.20.0.9", "10.20.0.100", "10.20.1.4"} {
		seedService(t, e, m.ID, n.ID, ip, 443)
	}
	base := "/api/missions/" + itoa(m.ID) + "/services"

	// A subnet keeps the two addresses in it, in numeric order: .9 then .100, which is
	// the pair a text sort gets backwards.
	var listed []model.Service
	if got := alice.do("GET", base+"?ip=10.20.0.0/24&sort=ip", nil, &listed); got != http.StatusOK {
		t.Fatalf("filtered listing: %d", got)
	}
	if len(listed) != 2 || listed[0].IP != "10.20.0.9" || listed[1].IP != "10.20.0.100" {
		t.Fatalf("unexpected rows for 10.20.0.0/24: %+v", addressesOf(listed))
	}

	// Reversing the direction reverses the listing.
	if got := alice.do("GET", base+"?ip=10.20.0.0/24&sort=ip&dir=desc", nil, &listed); got != http.StatusOK {
		t.Fatalf("reversed listing: %d", got)
	}
	if len(listed) != 2 || listed[0].IP != "10.20.0.100" {
		t.Fatalf("dir=desc did not reverse the listing: %+v", addressesOf(listed))
	}

	// A single address is exactly that address.
	if got := alice.do("GET", base+"?ip=10.20.1.4", nil, &listed); got != http.StatusOK {
		t.Fatalf("single address: %d", got)
	}
	if len(listed) != 1 || listed[0].IP != "10.20.1.4" {
		t.Fatalf("unexpected rows for a single address: %+v", addressesOf(listed))
	}

	// A sort key the server does not know leaves the listing alone instead of failing, so
	// an old bookmark still shows the table.
	if got := alice.do("GET", base+"?sort=banner", nil, &listed); got != http.StatusOK || len(listed) != 3 {
		t.Fatalf("an unknown sort key must fall back: %d, %d rows", got, len(listed))
	}

	// A malformed filter is refused, and the message says what was wrong.
	for _, bad := range []string{"ip=10.20.0.0/33", "ip=banana", "ip=10.20.0.300"} {
		status, body, _ := alice.raw("GET", base+"?"+bad)
		if status != http.StatusBadRequest {
			t.Fatalf("%s must be refused, got %d", bad, status)
		}
		if !strings.Contains(string(body), "CIDR") {
			t.Fatalf("%s: the error should say what was expected: %s", bad, body)
		}
	}

	// The other three listings take the same parameters.
	for _, path := range []string{"/hosts", "/findings", "/assets"} {
		url := "/api/missions/" + itoa(m.ID) + path
		if got := alice.do("GET", url+"?ip=10.20.0.0/24&sort=ip", nil, nil); got != http.StatusOK {
			t.Fatalf("%s with an address filter: %d", path, got)
		}
		if got := alice.do("GET", url+"?ip=nonsense", nil, nil); got != http.StatusBadRequest {
			t.Fatalf("%s must refuse a malformed address, got %d", path, got)
		}
	}
}

func addressesOf(services []model.Service) []string {
	out := make([]string, len(services))
	for i, sv := range services {
		out[i] = sv.IP
	}
	return out
}
