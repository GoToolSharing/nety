package segment

import (
	"net/netip"
	"testing"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
)

func svc(ip string, port uint16, proto model.Protocol, hostID, svcID int64) engine.ReachTarget {
	return engine.ReachTarget{
		TargetNetworkID: 2,
		TargetHostID:    hostID,
		TargetServiceID: svcID,
		IP:              netip.MustParseAddr(ip),
		Port:            port,
		Proto:           proto,
		ServiceName:     "http",
		TargetPrefixes:  []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		TargetVLANID:    20,
	}
}

func baseOpts() engine.SegmentOptions {
	return engine.SegmentOptions{
		Interface: "eth0",
		Local: engine.NetContext{
			Interface: "eth0",
			LocalIP:   netip.MustParseAddr("10.10.0.5"),
			Gateway:   netip.MustParseAddr("10.10.0.1"),
		},
	}
}

func jobsFor(p plan, tech string) []job {
	var out []job
	for _, j := range p.parallel {
		if j.tech == tech {
			out = append(out, j)
		}
	}
	for _, g := range p.exclusive {
		for _, j := range g.jobs {
			if j.tech == tech {
				out = append(out, j)
			}
		}
	}
	return out
}

// Several services on one host must collapse into a single ICMP test: pinging the same
// address five times teaches nothing new and clutters the matrix.
func TestPlanDeduplicatesHostLevelICMP(t *testing.T) {
	targets := []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.10", 443, model.TCP, 1, 12),
		svc("10.20.0.10", 22, model.TCP, 1, 13),
		svc("10.20.0.11", 80, model.TCP, 2, 14),
	}
	p := buildPlan(baseOpts(), targets, []string{model.TechDirect, model.TechICMP})

	if got := len(jobsFor(p, model.TechICMP)); got != 2 {
		t.Errorf("icmp jobs = %d, want one per host (2)", got)
	}
	if got := len(jobsFor(p, model.TechDirect)); got != 4 {
		t.Errorf("direct jobs = %d, want one per service (4)", got)
	}
	for _, j := range jobsFor(p, model.TechICMP) {
		if j.target.TargetServiceID != 0 || j.target.Port != 0 {
			t.Errorf("icmp job still carries a service: %+v", j.target)
		}
	}
}

func TestPlanDeduplicatesIdenticalTargets(t *testing.T) {
	tgt := svc("10.20.0.10", 80, model.TCP, 1, 11)
	p := buildPlan(baseOpts(), []engine.ReachTarget{tgt, tgt, tgt}, []string{model.TechDirect})
	if got := len(p.parallel); got != 1 {
		t.Errorf("jobs = %d, want 1: the same target must not be tested three times", got)
	}
}

func TestPlanSkipsSourcePortTechniquesForHostTargets(t *testing.T) {
	host := engine.ReachTarget{
		TargetHostID: 1,
		IP:           netip.MustParseAddr("10.20.0.10"),
	}
	p := buildPlan(baseOpts(), []engine.ReachTarget{host},
		[]string{model.TechSrcPort53, model.TechICMP, model.TechDirect})

	if got := len(jobsFor(p, model.TechSrcPort53)); got != 0 {
		t.Errorf("src-port jobs = %d, want 0: there is no port to connect to", got)
	}
	if got := len(jobsFor(p, model.TechICMP)); got != 1 {
		t.Errorf("icmp jobs = %d, want 1", got)
	}
}

func TestPlanSourcePortIsSet(t *testing.T) {
	p := buildPlan(baseOpts(), []engine.ReachTarget{svc("10.20.0.10", 445, model.TCP, 1, 11)},
		[]string{model.TechSrcPort53, model.TechSrcPort123})
	for _, j := range p.parallel {
		want := srcPortTechniques[j.tech]
		if j.srcPort != want {
			t.Errorf("%s: srcPort = %d, want %d", j.tech, j.srcPort, want)
		}
	}
}

func TestPlanIPv6OnlyWithKnownAddresses(t *testing.T) {
	tgt := svc("10.20.0.10", 80, model.TCP, 1, 11)
	p := buildPlan(baseOpts(), []engine.ReachTarget{tgt}, []string{model.TechIPv6})
	if got := len(p.parallel); got != 0 {
		t.Fatalf("jobs = %d, want 0 when the asset has no IPv6 address", got)
	}

	tgt.IPv6 = []netip.Addr{
		netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("fd00::10"),
	}
	p = buildPlan(baseOpts(), []engine.ReachTarget{tgt}, []string{model.TechIPv6})
	jobs := jobsFor(p, model.TechIPv6)
	if len(jobs) != maxIPv6PerTarget {
		t.Fatalf("jobs = %d, want %d", len(jobs), maxIPv6PerTarget)
	}
	if jobs[0].ip.String() != "2001:db8::10" {
		t.Errorf("first IPv6 tried = %s, want the global address", jobs[0].ip)
	}
	if jobs[1].ip.String() != "fd00::10" {
		t.Errorf("second IPv6 tried = %s, want the ULA before the link-local one", jobs[1].ip)
	}
}

func TestPlanFragmentOnlyForTCP(t *testing.T) {
	p := buildPlan(baseOpts(), []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.10", 161, model.UDP, 1, 12),
	}, []string{model.TechFragment})
	jobs := jobsFor(p, model.TechFragment)
	if len(jobs) != 1 || jobs[0].target.Proto != model.TCP {
		t.Errorf("fragment jobs = %+v, want only the TCP target", jobs)
	}
}

func TestPlanGatewayRouteNeedsAGateway(t *testing.T) {
	opts := baseOpts()
	opts.Local.Gateway = netip.Addr{}
	p := buildPlan(opts, []engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)},
		[]string{model.TechGatewayRoute})
	if p.count() != 0 {
		t.Errorf("jobs = %d, want 0 without a local gateway", p.count())
	}
}

// One route is installed per target prefix, not per service.
func TestPlanGroupsRouteJobsByPrefix(t *testing.T) {
	p := buildPlan(baseOpts(), []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 443, model.TCP, 2, 12),
		svc("10.20.0.12", 22, model.TCP, 3, 13),
	}, []string{model.TechGatewayRoute})

	if len(p.exclusive) != 1 {
		t.Fatalf("groups = %d, want 1 (all three share 10.20.0.0/16)", len(p.exclusive))
	}
	g := p.exclusive[0]
	if g.prefix.String() != "10.20.0.0/16" {
		t.Errorf("prefix = %s", g.prefix)
	}
	if len(g.jobs) != 3 {
		t.Errorf("jobs in group = %d, want 3", len(g.jobs))
	}
	if len(p.parallel) != 0 {
		t.Errorf("route jobs must not run in the parallel phase")
	}
}

func TestPlanRoutedPrefixFallsBackToHostRoute(t *testing.T) {
	tgt := svc("10.20.0.10", 80, model.TCP, 1, 11)
	tgt.TargetPrefixes = nil
	if got := routedPrefix(tgt).String(); got != "10.20.0.10/32" {
		t.Errorf("routedPrefix = %s, want a host route", got)
	}
}

func TestPlanAltGatewayOnePerNextHop(t *testing.T) {
	opts := baseOpts()
	opts.AltGateways = []netip.Addr{
		netip.MustParseAddr("10.10.0.2"),
		netip.MustParseAddr("10.10.0.3"),
		netip.MustParseAddr("10.10.0.1"), // same as the default gateway: skipped
	}
	p := buildPlan(opts, []engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)},
		[]string{model.TechAltGateway})
	if len(p.exclusive) != 2 {
		t.Fatalf("groups = %d, want one per distinct next hop", len(p.exclusive))
	}
	for _, g := range p.exclusive {
		if g.via == opts.Local.Gateway {
			t.Error("the default gateway must not be retried as an alternate next hop")
		}
	}
}

func TestPlanL2GroupsByVLAN(t *testing.T) {
	opts := baseOpts()
	opts.AllowL2Active = true
	p := buildPlan(opts, []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
	}, []string{model.TechDot1QSubif})

	if len(p.exclusive) != 1 {
		t.Fatalf("groups = %d, want one per VLAN", len(p.exclusive))
	}
	if p.exclusive[0].vlanID != 20 {
		t.Errorf("vlan = %d, want the target network's VLAN id", p.exclusive[0].vlanID)
	}
	if len(p.exclusive[0].jobs) != 2 {
		t.Errorf("jobs = %d", len(p.exclusive[0].jobs))
	}
}

func TestPlanL2UsesExplicitVLANList(t *testing.T) {
	opts := baseOpts()
	opts.AllowL2Active = true
	opts.VLANIDs = []int{30, 40, 30}
	p := buildPlan(opts, []engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)},
		[]string{model.TechDot1QSubif})
	if len(p.exclusive) != 2 {
		t.Fatalf("groups = %d, want one per requested VLAN (de-duplicated)", len(p.exclusive))
	}
	if p.exclusive[0].vlanID != 30 || p.exclusive[1].vlanID != 40 {
		t.Errorf("vlans = %d, %d", p.exclusive[0].vlanID, p.exclusive[1].vlanID)
	}
}

func TestPlanL2SkippedWhenVLANUnknown(t *testing.T) {
	opts := baseOpts()
	opts.AllowL2Active = true
	tgt := svc("10.20.0.10", 80, model.TCP, 1, 11)
	tgt.TargetVLANID = 0
	p := buildPlan(opts, []engine.ReachTarget{tgt}, []string{model.TechDot1QSubif})
	if p.count() != 0 {
		t.Errorf("jobs = %d, want 0 when no VLAN id is known", p.count())
	}
}

// DTP trunking is only attempted when the port was actually seen offering it.
func TestPlanDTPNeedsAnOfferingPort(t *testing.T) {
	opts := baseOpts()
	opts.AllowL2Active = true
	tgt := svc("10.20.0.10", 80, model.TCP, 1, 11)

	p := buildPlan(opts, []engine.ReachTarget{tgt}, []string{model.TechDTPTrunk})
	if p.count() != 0 {
		t.Errorf("jobs = %d, want 0 when no DTP was observed", p.count())
	}

	opts.L2 = model.L2Info{DTPSeen: true, DTPMode: "access"}
	p = buildPlan(opts, []engine.ReachTarget{tgt}, []string{model.TechDTPTrunk})
	if p.count() != 0 {
		t.Errorf("jobs = %d, want 0 when the port is hard-coded to access", p.count())
	}

	for _, mode := range []string{"desirable", "auto", "on"} {
		opts.L2 = model.L2Info{DTPSeen: true, DTPMode: mode}
		p = buildPlan(opts, []engine.ReachTarget{tgt}, []string{model.TechDTPTrunk})
		if p.count() != 1 {
			t.Errorf("mode %q: jobs = %d, want 1", mode, p.count())
		}
	}
}

func TestPlanSkipsInvalidTargets(t *testing.T) {
	p := buildPlan(baseOpts(), []engine.ReachTarget{{TargetHostID: 1}}, []string{model.TechDirect, model.TechICMP})
	if p.count() != 0 {
		t.Errorf("jobs = %d, want 0 for a target with no address at all", p.count())
	}
}

func TestPlanCount(t *testing.T) {
	opts := baseOpts()
	opts.AllowL2Active = true
	p := buildPlan(opts, []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
	}, []string{model.TechDirect, model.TechICMP, model.TechGatewayRoute, model.TechDot1QSubif})

	// 2 direct + 2 icmp + 2 gateway-route + 2 dot1q
	if p.count() != 8 {
		t.Errorf("count = %d, want 8", p.count())
	}
	if len(p.parallel) != 4 {
		t.Errorf("parallel = %d, want direct + icmp only", len(p.parallel))
	}
}
