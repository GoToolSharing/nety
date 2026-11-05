package segment

import (
	"net/netip"
	"sort"
	"strconv"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

// job is one (target, technique) test.
type job struct {
	target  engine.ReachTarget
	tech    string
	ip      netip.Addr // the address actually probed (v4, or one of the v6s)
	vlanID  int        // L2 techniques
	via     netip.Addr // route techniques: the next hop to install
	srcPort uint16     // fixed source-port techniques
	srcAddr netip.Addr // set by the L2 techniques once the sub-interface is up
	iface   string     // set by the L2 techniques
}

// exclusiveGroup is a batch of jobs that share one system change: one route, or one
// tagged sub-interface. The change is made once, every job in the group is tested, then
// the change is reverted.
type exclusiveGroup struct {
	tech   string
	vlanID int
	via    netip.Addr
	prefix netip.Prefix // the prefix a route technique installs
	jobs   []job
}

type plan struct {
	parallel  []job
	exclusive []exclusiveGroup
}

func (p plan) count() int {
	n := len(p.parallel)
	for _, g := range p.exclusive {
		n += len(g.jobs)
	}
	return n
}

// buildPlan expands targets x techniques into jobs, drops the combinations that cannot
// apply, and de-duplicates: several services on the same host collapse into a single ICMP
// test, and a repeated target never produces two identical rows in the matrix.
func buildPlan(opts engine.SegmentOptions, targets []engine.ReachTarget, techs []string) plan {
	var p plan
	seen := map[string]struct{}{}
	groups := map[string]*exclusiveGroup{}
	var groupOrder []string

	add := func(j job) {
		k := jobKey(j)
		if _, dup := seen[k]; dup {
			return
		}
		seen[k] = struct{}{}
		if !needsExclusiveAccess(j.tech) {
			p.parallel = append(p.parallel, j)
			return
		}
		gk := groupKey(j)
		g, ok := groups[gk]
		if !ok {
			g = &exclusiveGroup{tech: j.tech, vlanID: j.vlanID, via: j.via, prefix: routedPrefix(j.target)}
			groups[gk] = g
			groupOrder = append(groupOrder, gk)
		}
		g.jobs = append(g.jobs, j)
	}

	for _, tgt := range targets {
		if !tgt.IP.IsValid() && len(tgt.IPv6) == 0 {
			continue
		}
		for _, tech := range techs {
			for _, j := range expand(opts, tgt, tech) {
				add(j)
			}
		}
	}
	for _, gk := range groupOrder {
		p.exclusive = append(p.exclusive, *groups[gk])
	}
	return p
}

// expand turns one (target, technique) pair into zero or more jobs.
func expand(opts engine.SegmentOptions, tgt engine.ReachTarget, tech string) []job {
	base := job{target: tgt, tech: tech, ip: tgt.IP.Unmap()}

	switch tech {
	case model.TechICMP:
		if !tgt.IP.IsValid() {
			return nil
		}
		// Host-level: one test per host, whatever services it exposes.
		j := base
		j.target.TargetServiceID = 0
		j.target.Port = 0
		j.target.Proto = ""
		return []job{j}

	case model.TechIPv6:
		var out []job
		for i, a := range sortIPv6(tgt.IPv6) {
			if i >= maxIPv6PerTarget {
				break
			}
			j := base
			j.ip = a.Unmap()
			out = append(out, j)
		}
		return out

	case model.TechDirect:
		if !tgt.IP.IsValid() {
			return nil
		}
		return []job{base}

	case model.TechFragment:
		// Fragmenting a SYN only makes sense for a TCP service.
		if !tgt.IP.IsValid() || !tgt.IP.Is4() || tgt.Port == 0 || tgt.Proto == model.UDP {
			return nil
		}
		return []job{base}

	case model.TechGatewayRoute:
		if !tgt.IP.IsValid() || !opts.Local.Gateway.IsValid() {
			return nil
		}
		j := base
		j.via = opts.Local.Gateway
		return []job{j}

	case model.TechAltGateway:
		if !tgt.IP.IsValid() {
			return nil
		}
		var out []job
		for _, gw := range opts.AltGateways {
			if !gw.IsValid() || gw == opts.Local.Gateway {
				continue
			}
			j := base
			j.via = gw.Unmap()
			out = append(out, j)
		}
		return out

	case model.TechDot1QSubif, model.TechDTPTrunk, model.TechDoubleTag:
		if !tgt.IP.IsValid() {
			return nil
		}
		if tech == model.TechDTPTrunk && !portOffersTrunk(opts.L2) {
			return nil
		}
		var out []job
		for _, vid := range vlansFor(opts, tgt) {
			j := base
			j.vlanID = vid
			out = append(out, j)
		}
		return out
	}

	// src-port-*
	if sp, ok := srcPortTechniques[tech]; ok {
		if !tgt.IP.IsValid() || tgt.Port == 0 {
			return nil
		}
		j := base
		j.srcPort = sp
		return []job{j}
	}
	return nil
}

// vlansFor returns the VLAN ids to try for an L2 technique: the explicit list from the
// options, or the target network's own VLAN id.
func vlansFor(opts engine.SegmentOptions, tgt engine.ReachTarget) []int {
	if len(opts.VLANIDs) > 0 {
		return sortedVLANs(opts.VLANIDs)
	}
	return sortedVLANs([]int{tgt.TargetVLANID})
}

// portOffersTrunk reports whether the passive L2 recon saw the switch port advertise that
// it is willing to negotiate a trunk.
func portOffersTrunk(l2 model.L2Info) bool {
	if !l2.DTPSeen {
		return false
	}
	switch l2.DTPMode {
	case "on", "desirable", "auto":
		return true
	}
	return false
}

// routedPrefix is the prefix a route technique installs for a target: the target
// network's prefix that contains the IP, or a host route.
func routedPrefix(tgt engine.ReachTarget) netip.Prefix {
	ip := tgt.IP.Unmap()
	for _, p := range tgt.TargetPrefixes {
		if p.IsValid() && p.Addr().Is4() == ip.Is4() && p.Contains(ip) {
			return p.Masked()
		}
	}
	return netip.PrefixFrom(ip, ip.BitLen())
}

func jobKey(j job) string {
	return j.tech + "|" + j.ip.String() + "|" +
		strconv.Itoa(int(j.target.Port)) + "|" + string(j.target.Proto) + "|" +
		strconv.Itoa(j.vlanID) + "|" + j.via.String() + "|" +
		strconv.Itoa(int(j.srcPort))
}

func groupKey(j job) string {
	return j.tech + "|" + strconv.Itoa(j.vlanID) + "|" + j.via.String() + "|" + routedPrefix(j.target).String()
}

// sortIPv6 puts routable addresses first so maxIPv6PerTarget keeps the useful ones; a
// link-local address is almost never reachable across a boundary.
func sortIPv6(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	seen := map[netip.Addr]struct{}{}
	for _, a := range in {
		a = a.Unmap()
		if !a.IsValid() || a.Is4() {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool { return rankV6(out[i]) < rankV6(out[j]) })
	return out
}

func rankV6(a netip.Addr) int {
	switch {
	case a.IsGlobalUnicast() && !a.IsPrivate():
		return 0
	case a.IsGlobalUnicast():
		return 1
	case a.IsLinkLocalUnicast():
		return 2
	}
	return 3
}
