package store

import (
	"context"
	"sort"
	"strconv"
	"testing"

	"github.com/GoToolSharing/nety/internal/model"
)

// The whole point of the key is that comparing two of them as text is
// comparing the two addresses as numbers, which is what `ORDER BY ip` could
// never do.
func TestIPSortKeyOrdersAddressesNumerically(t *testing.T) {
	ordered := []string{
		"0.0.0.0",
		"10.0.0.9",
		"10.0.0.100",
		"10.0.1.0",
		"10.20.0.7",
		"10.20.0.12",
		"192.168.1.1",
		"255.255.255.255",
		// Every v6 address sorts after every v4 one, whatever its text is.
		"::1",
		"2001:db8::1",
		"2001:db8::a",
		"2001:db8::10",
		"2001:db8:1::1",
		"fe80::1",
	}
	shuffled := []string{
		"2001:db8::10", "10.0.0.100", "fe80::1", "10.20.0.12", "0.0.0.0",
		"2001:db8::a", "192.168.1.1", "10.0.0.9", "2001:db8:1::1", "10.0.1.0",
		"255.255.255.255", "::1", "10.20.0.7", "2001:db8::1",
	}
	sort.Slice(shuffled, func(i, j int) bool {
		return ipSortKey(shuffled[i]) < ipSortKey(shuffled[j])
	})
	for i := range ordered {
		if shuffled[i] != ordered[i] {
			t.Fatalf("sorted by key:\n got %v\nwant %v", shuffled, ordered)
		}
	}

	// A v4-mapped v6 address is the v4 address it wraps, and sorts with it.
	if got, want := ipSortKey("::ffff:10.0.0.9"), ipSortKey("10.0.0.9"); got != want {
		t.Fatalf("a v4-mapped address must share the v4 key: %q vs %q", got, want)
	}
	// Anything that is not an address has no place in the order.
	for _, bad := range []string{"", "not-an-ip", "10.0.0.256", "10.0.0"} {
		if key := ipSortKey(bad); key != "" {
			t.Fatalf("%q is not an address but got the key %q", bad, key)
		}
	}
}

func TestParseAddressFilterRefusesNonsense(t *testing.T) {
	for _, bad := range []string{"10.0.0.300", "10.0.0.0/33", "banana", "10.0.0.0/", "/24", "10.0.0.1-10.0.0.9"} {
		if _, err := ParseAddressFilter(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	// An empty filter is not an error: it is a listing with no filter at all.
	f, err := ParseAddressFilter("  ")
	if err != nil || !f.Empty() {
		t.Fatalf("an empty value must mean no filter: %+v, %v", f, err)
	}
	// A prefix with host bits set is the subnet it names, not an error.
	f, err = ParseAddressFilter("10.20.0.7/24")
	if err != nil || f.Empty() {
		t.Fatalf("a prefix with host bits set must be accepted: %+v, %v", f, err)
	}
	if f.lo != ipSortKey("10.20.0.0") || f.hi != ipSortKey("10.20.0.255") {
		t.Fatalf("unexpected bounds for 10.20.0.7/24: %+v", f)
	}
}

// seedAddresses puts one service and one finding on each address, so the
// filter can be exercised on both listings.
func seedAddresses(t *testing.T, s *Store, missionID int64, ips []string) {
	t.Helper()
	ctx := context.Background()
	for i, ip := range ips {
		if _, err := s.UpsertService(ctx, model.Service{
			MissionID: missionID, NetworkID: 1, IP: ip, Port: 22 + i,
			Protocol: model.TCP, State: model.PortOpen, Name: "ssh",
		}); err != nil {
			t.Fatalf("seed service %s: %v", ip, err)
		}
		if _, err := s.UpsertFinding(ctx, model.Finding{
			MissionID: missionID, NetworkID: 1, IP: ip, Port: 22 + i,
			Protocol: model.TCP, CheckID: "weak-ssh", Title: "weak ssh",
			Severity: model.SevLow,
		}); err != nil {
			t.Fatalf("seed finding %s: %v", ip, err)
		}
	}
}

func TestAddressFilterSelectsOneSubnet(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	seedAddresses(t, s, m.ID, []string{
		"10.20.0.7", "10.20.0.12", "10.20.1.4", "192.168.0.1",
		"2001:db8::1", "2001:db8:1::5",
	})

	cases := []struct {
		filter string
		want   []string
	}{
		{"10.20.0.0/24", []string{"10.20.0.7", "10.20.0.12"}},
		{"10.20.0.7/32", []string{"10.20.0.7"}},
		{"10.20.0.7", []string{"10.20.0.7"}},
		{"10.0.0.0/8", []string{"10.20.0.7", "10.20.0.12", "10.20.1.4"}},
		{"2001:db8::/64", []string{"2001:db8::1"}},
		{"2001:db8::/32", []string{"2001:db8::1", "2001:db8:1::5"}},
		{"0.0.0.0/0", []string{"10.20.0.7", "10.20.0.12", "10.20.1.4", "192.168.0.1"}},
		{"172.16.0.0/12", nil},
	}
	for _, c := range cases {
		f, err := ParseAddressFilter(c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		services, err := s.ListServices(ctx, ServiceFilter{MissionID: m.ID, Address: f, Sort: "ip"})
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		var got []string
		for _, sv := range services {
			got = append(got, sv.IP)
		}
		if !sameStrings(got, c.want) {
			t.Fatalf("services for %s:\n got %v\nwant %v", c.filter, got, c.want)
		}

		findings, err := s.ListFindings(ctx, FindingFilter{MissionID: m.ID, Address: f, Sort: "ip"})
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		got = nil
		for _, fd := range findings {
			got = append(got, fd.IP)
		}
		if !sameStrings(got, c.want) {
			t.Fatalf("findings for %s:\n got %v\nwant %v", c.filter, got, c.want)
		}
	}
}

func TestAddressFilterOnHostsAndAssets(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	for _, ip := range []string{"10.20.0.7", "10.20.1.9", "10.20.0.100"} {
		if _, err := s.UpsertHost(ctx, model.Host{MissionID: m.ID, NetworkID: 1, IP: ip}); err != nil {
			t.Fatalf("seed host %s: %v", ip, err)
		}
	}
	for _, a := range []struct {
		label string
		ips   []string
	}{
		{"srv-db", []string{"10.20.0.7", "10.20.5.7"}},
		{"ws-042", []string{"10.20.1.9"}},
	} {
		asset := model.Asset{MissionID: m.ID, Label: a.label}
		for _, ip := range a.ips {
			asset.IPs = append(asset.IPs, model.AssetIP{IP: ip, NetworkID: 1})
		}
		if _, err := s.SaveAsset(ctx, asset); err != nil {
			t.Fatalf("seed asset %s: %v", a.label, err)
		}
	}

	f, err := ParseAddressFilter("10.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := s.ListHostsFiltered(ctx, HostFilter{MissionID: m.ID, Address: f, Sort: "ip"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, h := range hosts {
		got = append(got, h.IP)
	}
	// Numeric order as well: .7 before .100, which text order would reverse.
	if !sameStrings(got, []string{"10.20.0.7", "10.20.0.100"}) {
		t.Fatalf("hosts in 10.20.0.0/24: %v", got)
	}

	// A machine is kept when any of its addresses is in the subnet.
	assets, err := s.ListAssetsFiltered(ctx, AssetFilter{MissionID: m.ID, Address: f})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Label != "srv-db" {
		t.Fatalf("assets in 10.20.0.0/24: %+v", assets)
	}
}

// A sort key the server does not know must leave the listing in its default
// order rather than being pasted into the query.
func TestUnknownSortFallsBackToTheDefault(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	seedAddresses(t, s, m.ID, []string{"10.0.0.9", "10.0.0.100", "10.0.0.2"})

	defaults, err := s.ListServices(ctx, ServiceFilter{MissionID: m.ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, nonsense := range []string{"id; DROP TABLE services", "banner", "", "IP"} {
		got, err := s.ListServices(ctx, ServiceFilter{MissionID: m.ID, Sort: nonsense})
		if err != nil {
			t.Fatalf("sort %q must not reach SQL: %v", nonsense, err)
		}
		if len(got) != len(defaults) {
			t.Fatalf("sort %q changed the rows: %d vs %d", nonsense, len(got), len(defaults))
		}
		// "IP" differs from the default order only in case, and is accepted.
		if nonsense == "IP" {
			continue
		}
		for i := range got {
			if got[i].ID != defaults[i].ID {
				t.Fatalf("sort %q changed the order", nonsense)
			}
		}
	}
}

func TestSortedPagingShowsEachRowOnce(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)

	// Several services share an address and several share a port, so every
	// sort has ties to break.
	var seeded int
	for i := 0; i < 7; i++ {
		for _, port := range []int{22, 80, 443} {
			if _, err := s.UpsertService(ctx, model.Service{
				MissionID: m.ID, NetworkID: 1, IP: "10.0.0." + strconv.Itoa(i*13+1), Port: port,
				Protocol: model.TCP, State: model.PortOpen, Name: "svc",
			}); err != nil {
				t.Fatal(err)
			}
			seeded++
		}
	}

	for _, sortKey := range []string{"ip", "port", "service", "status", "last_seen"} {
		for _, desc := range []bool{false, true} {
			seen := map[int64]int{}
			for offset := 0; offset < seeded+5; offset += 4 {
				page, err := s.ListServices(ctx, ServiceFilter{
					MissionID: m.ID, Sort: sortKey, Desc: desc, Limit: 4, Offset: offset,
				})
				if err != nil {
					t.Fatal(err)
				}
				for _, sv := range page {
					seen[sv.ID]++
				}
			}
			if len(seen) != seeded {
				t.Fatalf("sort %q desc=%v: paged over %d rows, expected %d",
					sortKey, desc, len(seen), seeded)
			}
			for id, n := range seen {
				if n != 1 {
					t.Fatalf("sort %q desc=%v: service %d came back %d times", sortKey, desc, id, n)
				}
			}
		}
	}
}

// Severity sorts by weight, not alphabetically: critical belongs above low,
// which "critical" < "high" < "low" < "medium" would never give.
func TestFindingsSortBySeverityRank(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	m := testMission(t, s)
	for i, sev := range []model.Severity{model.SevLow, model.SevCritical, model.SevMedium, model.SevHigh} {
		if _, err := s.UpsertFinding(ctx, model.Finding{
			MissionID: m.ID, NetworkID: 1, IP: "10.0.0." + strconv.Itoa(i+1), Port: 80,
			Protocol: model.TCP, CheckID: "c" + strconv.Itoa(i), Title: "t", Severity: sev,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListFindings(ctx, FindingFilter{MissionID: m.ID, Sort: "severity"})
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow}
	for i, sev := range want {
		if got[i].Severity != sev {
			t.Fatalf("severity order: %v", severitiesOf(got))
		}
	}
	got, err = s.ListFindings(ctx, FindingFilter{MissionID: m.ID, Sort: "severity", Desc: true})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Severity != model.SevLow {
		t.Fatalf("reversed severity order: %v", severitiesOf(got))
	}
}

func severitiesOf(findings []model.Finding) []model.Severity {
	out := make([]model.Severity, len(findings))
	for i, f := range findings {
		out[i] = f.Severity
	}
	return out
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
