package segment

import (
	"sort"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

// The technique catalogue. Each entry answers one question an auditor asks
// about a segmentation boundary, and the Description is shown verbatim in the
// UI next to the checkbox that enables it.
var techniqueCatalog = []engine.TechniqueInfo{
	{
		ID:          model.TechDirect,
		Title:       "Direct connection",
		Description: "Connects to the service with the machine's current routing, telling apart a refused connection (routed, port closed), a silent drop (filtered) and an ICMP unreachable (no route or administratively prohibited).",
		Default:     true,
	},
	{
		ID:          model.TechICMP,
		Title:       "ICMP echo",
		Description: "Pings the target host to find out whether the host itself is reachable across the boundary, even when none of its services are.",
		Default:     true,
	},
	{
		ID:          model.TechSrcPort53,
		Title:       "Source port 53 (DNS)",
		Description: "Repeats the test from source port 53; stateless ACLs that permit DNS replies in both directions often let any packet from this port through.",
		Default:     true,
	},
	{
		ID:          model.TechSrcPort88,
		Title:       "Source port 88 (Kerberos)",
		Description: "Repeats the test from source port 88, frequently allowed wholesale towards and from domain controllers.",
	},
	{
		ID:          model.TechSrcPort123,
		Title:       "Source port 123 (NTP)",
		Description: "Repeats the test from source port 123; NTP is one of the most commonly blanket-permitted services on an ACL.",
		Default:     true,
	},
	{
		ID:          model.TechSrcPort20,
		Title:       "Source port 20 (FTP-data)",
		Description: "Repeats the test from source port 20, which legacy ACLs permit to support active-mode FTP transfers.",
	},
	{
		ID:          model.TechSrcPort67,
		Title:       "Source port 67 (DHCP)",
		Description: "Repeats the test from source port 67, often permitted so DHCP relays can reach clients.",
	},
	{
		ID:          model.TechSrcPort500,
		Title:       "Source port 500 (IKE)",
		Description: "Repeats the test from source port 500, commonly opened for VPN tunnel negotiation.",
	},
	{
		ID:          model.TechIPv6,
		Title:       "IPv6",
		Description: "Retries over the target's known IPv6 addresses; filtering rules are regularly written for IPv4 only and silently leave IPv6 wide open.",
		Default:     true,
	},
	{
		ID:          model.TechGatewayRoute,
		Title:       "Route via local gateway",
		Description: "Temporarily installs a route to the target network through the local default gateway, tests, then removes it — this shows whether the router would forward the traffic if only the client knew the way.",
		Default:     true,
	},
	{
		ID:          model.TechAltGateway,
		Title:       "Route via another next hop",
		Description: "Repeats the route test through every other router or multi-homed host found on the local segment, which may forward where the default gateway refuses.",
	},
	{
		ID:          model.TechFragment,
		Title:       "Fragmented SYN",
		Description: "Sends a TCP SYN split across IP fragments; stateless filters that inspect only the first fragment can be slipped past this way.",
	},
	{
		ID:          model.TechDot1QSubif,
		Title:       "802.1Q sub-interface",
		Description: "Creates a tagged sub-interface for the target VLAN, obtains an address on it and tests from inside that VLAN — this works when the switch port is a trunk rather than an access port.",
		L2Active:    true,
	},
	{
		ID:          model.TechDTPTrunk,
		Title:       "DTP trunk negotiation",
		Description: "Asks the switch port to become a trunk over DTP, then tests through a tagged sub-interface. Only attempted when the port was seen advertising that it will negotiate.",
		L2Active:    true,
	},
	{
		ID:          model.TechDoubleTag,
		Title:       "802.1Q double tagging",
		Description: "Emits a frame carrying the native VLAN tag followed by the target VLAN tag, which a trunk strips down to a frame injected straight into the target VLAN. Traffic only travels one way, so delivery cannot be confirmed from here.",
		L2Active:    true,
		OneWay:      true,
	},
}

var techniqueByID = func() map[string]engine.TechniqueInfo {
	m := make(map[string]engine.TechniqueInfo, len(techniqueCatalog))
	for _, t := range techniqueCatalog {
		m[t.ID] = t
	}
	return m
}()

// srcPortTechniques maps the fixed-source-port techniques to their port.
var srcPortTechniques = map[string]uint16{
	model.TechSrcPort53:  53,
	model.TechSrcPort88:  88,
	model.TechSrcPort123: 123,
	model.TechSrcPort20:  20,
	model.TechSrcPort67:  67,
	model.TechSrcPort500: 500,
}

// Techniques lists every supported technique for the UI.
func (t *Tester) Techniques() []engine.TechniqueInfo {
	out := make([]engine.TechniqueInfo, len(techniqueCatalog))
	copy(out, techniqueCatalog)
	return out
}

// DefaultTechniques are the techniques enabled when SegmentOptions.Techniques
// is empty: the ones that are safe on any engagement and answer most of the
// question on their own.
func DefaultTechniques() []string {
	var out []string
	for _, t := range techniqueCatalog {
		if t.Default {
			out = append(out, t.ID)
		}
	}
	return out
}

// selectTechniques resolves the requested technique list.
//
//   - an empty list means the default set;
//   - unknown ids are dropped (and reported in dropped);
//   - L2-active techniques are dropped unless allowL2 is set, because they can
//     disturb the client's switch;
//   - the result keeps catalogue order and contains no duplicates.
func selectTechniques(requested []string, allowL2 bool) (selected, dropped []string) {
	want := map[string]bool{}
	if len(requested) == 0 {
		for _, id := range DefaultTechniques() {
			want[id] = true
		}
	} else {
		for _, id := range requested {
			info, ok := techniqueByID[id]
			if !ok {
				dropped = appendUnique(dropped, id)
				continue
			}
			want[info.ID] = true
		}
	}
	for _, info := range techniqueCatalog {
		if !want[info.ID] {
			continue
		}
		if info.L2Active && !allowL2 {
			dropped = appendUnique(dropped, info.ID)
			continue
		}
		selected = append(selected, info.ID)
	}
	return selected, dropped
}

// isL2Active reports whether id needs SegmentOptions.AllowL2Active.
func isL2Active(id string) bool { return techniqueByID[id].L2Active }

// isOneWay reports whether id can only ever produce model.ReachSent.
func isOneWay(id string) bool { return techniqueByID[id].OneWay }

// needsExclusiveAccess reports whether a technique changes system state and
// must therefore run on its own, never alongside another technique.
func needsExclusiveAccess(id string) bool {
	switch id {
	case model.TechGatewayRoute, model.TechAltGateway,
		model.TechDot1QSubif, model.TechDTPTrunk, model.TechDoubleTag:
		return true
	}
	return false
}

func appendUnique(dst []string, s string) []string {
	for _, x := range dst {
		if x == s {
			return dst
		}
	}
	return append(dst, s)
}

func sortedVLANs(in []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(in))
	for _, v := range in {
		if v < 1 || v > 4094 {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}
