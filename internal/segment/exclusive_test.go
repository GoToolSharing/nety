package segment

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/model"
)

func l2Opts() engine.SegmentOptions {
	o := baseOpts()
	o.AllowL2Active = true
	o.Timeout = 200 * time.Millisecond
	o.L2 = model.L2Info{NativeVLAN: 1, DTPSeen: true, DTPMode: "desirable"}
	return o
}

// ---------------------------------------------------------------------------
// gateway-route / alt-gateway
// ---------------------------------------------------------------------------

func TestGatewayRouteInstallsAndRemovesTheRoute(t *testing.T) {
	tester, fa := newTester(t)
	tester.probe = func(_ context.Context, s probeSpec) probeResult {
		if len(fa.leaks()) == 0 {
			t.Error("the probe ran without the temporary route in place")
		}
		return probeResult{Status: model.ReachOpen, Detail: "ok"}
	}

	var c collector
	opts := baseOpts()
	opts.Techniques = []string{model.TechGatewayRoute}
	err := tester.Test(context.Background(), opts, []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
	}, c.add)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	fa.assertClean(t)

	log := fa.callLog()
	if len(log) != 2 {
		t.Fatalf("call log = %v, want exactly one add and one delete for two targets", log)
	}
	if !strings.HasPrefix(log[0], "AddRoute 10.20.0.0/16 via 10.10.0.1") {
		t.Errorf("first call = %q", log[0])
	}
	if !strings.HasPrefix(log[1], "DelRoute 10.20.0.0/16") {
		t.Errorf("last call = %q", log[1])
	}

	results := c.byTechnique(model.TechGatewayRoute)
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for _, r := range results {
		if !strings.Contains(r.Detail, "route 10.20.0.0/16 via 10.10.0.1 installed") {
			t.Errorf("detail should record the change made: %q", r.Detail)
		}
	}
}

func TestGatewayRouteSkipsInstallWhenARouteExists(t *testing.T) {
	tester, fa := newTester(t)
	fa.hasRoute = true
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachOpen}
	}
	var c collector
	opts := baseOpts()
	opts.Techniques = []string{model.TechGatewayRoute}
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	if log := fa.callLog(); len(log) != 0 {
		t.Errorf("call log = %v, want no routing change at all", log)
	}
	r := c.byTechnique(model.TechGatewayRoute)
	if len(r) != 1 || !strings.Contains(r[0].Detail, "already existed") {
		t.Errorf("detail = %+v, should say no route was installed", r)
	}
}

func TestGatewayRouteReportsAFailureForEveryTarget(t *testing.T) {
	tester, fa := newTester(t)
	fa.failRoute = errors.New("operation not permitted")
	var c collector
	opts := baseOpts()
	opts.Techniques = []string{model.TechGatewayRoute}
	err := tester.Test(context.Background(), opts, []engine.ReachTarget{
		svc("10.20.0.10", 80, model.TCP, 1, 11),
		svc("10.20.0.11", 80, model.TCP, 2, 12),
	}, c.add)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	fa.assertClean(t)

	results := c.byTechnique(model.TechGatewayRoute)
	if len(results) != 2 {
		t.Fatalf("results = %d, want a row for every target even when the setup fails", len(results))
	}
	for _, r := range results {
		if r.Status != model.ReachError || !strings.Contains(r.Detail, "not permitted") {
			t.Errorf("result = %+v", r)
		}
	}
}

func TestAltGatewayTriesEachNextHopInTurn(t *testing.T) {
	tester, fa := newTester(t)
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachOpen}
	}
	opts := baseOpts()
	opts.Techniques = []string{model.TechAltGateway}
	opts.AltGateways = []netip.Addr{
		netip.MustParseAddr("10.10.0.2"),
		netip.MustParseAddr("10.10.0.3"),
	}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)

	log := fa.callLog()
	want := []string{
		"AddRoute 10.20.0.0/16 via 10.10.0.2 dev eth0",
		"DelRoute 10.20.0.0/16 dev eth0",
		"AddRoute 10.20.0.0/16 via 10.10.0.3 dev eth0",
		"DelRoute 10.20.0.0/16 dev eth0",
	}
	if !reflect.DeepEqual(log, want) {
		t.Errorf("call log = %v,\nwant %v (each next hop set up and torn down in turn)", log, want)
	}
}

// ---------------------------------------------------------------------------
// dot1q-subif
// ---------------------------------------------------------------------------

func TestDot1QSubifFullLifecycle(t *testing.T) {
	tester, fa := newTester(t)
	var probedIface string
	var probedSrc netip.Addr
	tester.probe = func(_ context.Context, s probeSpec) probeResult {
		probedIface, probedSrc = s.Iface, s.SrcAddr
		return probeResult{Status: model.ReachOpen, Detail: "ok"}
	}

	opts := l2Opts()
	opts.Techniques = []string{model.TechDot1QSubif}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatalf("Test: %v", err)
	}
	fa.assertClean(t)

	if probedIface != "eth0.20" {
		t.Errorf("probe ran on %q, want the tagged sub-interface", probedIface)
	}
	if probedSrc.String() != "10.20.0.77" {
		t.Errorf("probe source = %s, want the DHCP address", probedSrc)
	}

	log := fa.callLog()
	if log[0] != "AddVLAN eth0.20" {
		t.Errorf("first call = %q", log[0])
	}
	if log[len(log)-1] != "DeleteVLAN eth0.20" {
		t.Errorf("last call = %q, the sub-interface must be removed last", log[len(log)-1])
	}
	if !containsString(log, "DHCP eth0.20") {
		t.Errorf("call log = %v, want a DHCP attempt on the sub-interface", log)
	}

	results := c.byTechnique(model.TechDot1QSubif)
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	if results[0].VLANID != 20 {
		t.Errorf("VLANID = %d, want 20", results[0].VLANID)
	}
	if !strings.Contains(results[0].Detail, "DHCP") || !strings.Contains(results[0].Detail, "VLAN 20") {
		t.Errorf("detail should explain the setup: %q", results[0].Detail)
	}
}

func TestDot1QSubifFallsBackToAStaticAddress(t *testing.T) {
	tester, fa := newTester(t)
	fa.failDHCP = errors.New("no DHCP offer")
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachOpen}
	}
	opts := l2Opts()
	opts.Techniques = []string{model.TechDot1QSubif}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)

	if !containsString(fa.callLog(), "AddAddr 10.20.255.250/16 dev eth0.20") {
		t.Errorf("call log = %v, want the static fallback applied", fa.callLog())
	}
	r := c.byTechnique(model.TechDot1QSubif)
	if len(r) != 1 || !strings.Contains(r[0].Detail, "static address") {
		t.Errorf("detail should say the address was static: %+v", r)
	}
}

func TestDot1QSubifReportsWhenNoAddressCanBeObtained(t *testing.T) {
	tester, fa := newTester(t)
	fa.failDHCP = errors.New("no DHCP offer")
	tester.SetStaticFallback(func(int, []netip.Prefix) (netip.Prefix, netip.Addr, bool) {
		return netip.Prefix{}, netip.Addr{}, false
	})
	probed := false
	tester.probe = func(context.Context, probeSpec) probeResult {
		probed = true
		return probeResult{Status: model.ReachOpen}
	}
	opts := l2Opts()
	opts.Techniques = []string{model.TechDot1QSubif}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)

	if probed {
		t.Error("a probe was sent from a sub-interface with no address")
	}
	r := c.byTechnique(model.TechDot1QSubif)
	if len(r) != 1 || r[0].Status != model.ReachError {
		t.Fatalf("results = %+v, want one error row", r)
	}
	if !strings.Contains(r[0].Detail, "no usable address") {
		t.Errorf("detail = %q", r[0].Detail)
	}
}

// Cancelling mid-technique must still tear down what was already created.
func TestDot1QSubifCleansUpOnCancellation(t *testing.T) {
	tester, fa := newTester(t)
	ctx, cancel := context.WithCancel(context.Background())
	fa.onAddVLAN = cancel

	opts := l2Opts()
	opts.Techniques = []string{model.TechDot1QSubif}
	var c collector
	err := tester.Test(ctx, opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	fa.assertClean(t)
	if !containsString(fa.callLog(), "DeleteVLAN eth0.20") {
		t.Fatalf("call log = %v, want the sub-interface deleted despite the cancellation", fa.callLog())
	}
}

func TestDot1QSubifReportsVLANCreationFailure(t *testing.T) {
	tester, fa := newTester(t)
	fa.failAddVLAN = errors.New("operation not permitted")
	opts := l2Opts()
	opts.Techniques = []string{model.TechDot1QSubif}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)
	r := c.byTechnique(model.TechDot1QSubif)
	if len(r) != 1 || r[0].Status != model.ReachError || !strings.Contains(r[0].Detail, "not permitted") {
		t.Errorf("results = %+v", r)
	}
}

func TestDTPTrunkNegotiatesBeforeTagging(t *testing.T) {
	tester, fa := newTester(t)
	tester.probe = func(context.Context, probeSpec) probeResult {
		return probeResult{Status: model.ReachOpen}
	}
	opts := l2Opts()
	opts.Techniques = []string{model.TechDTPTrunk}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)

	log := fa.callLog()
	if log[0] != "RequestTrunk eth0" {
		t.Errorf("first call = %q, the trunk must be requested before the sub-interface", log[0])
	}
	if !containsString(log, "AddVLAN eth0.20") {
		t.Errorf("call log = %v", log)
	}
	r := c.byTechnique(model.TechDTPTrunk)
	if len(r) != 1 || !strings.Contains(r[0].Detail, "DTP") {
		t.Errorf("detail should mention the DTP negotiation: %+v", r)
	}
	if !strings.Contains(r[0].Detail, "90s") {
		t.Errorf("detail should warn the operator the trunk lingers: %q", r[0].Detail)
	}
}

// ---------------------------------------------------------------------------
// double-tag
// ---------------------------------------------------------------------------

func TestDoubleTagIsOneWay(t *testing.T) {
	tester, fa := newTester(t)
	opts := l2Opts()
	opts.Techniques = []string{model.TechDoubleTag}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)

	r := c.byTechnique(model.TechDoubleTag)
	if len(r) != 1 {
		t.Fatalf("results = %d", len(r))
	}
	if r[0].Status != model.ReachSent {
		t.Errorf("status = %q, want 'sent': double tagging cannot confirm delivery", r[0].Status)
	}
	if r[0].VLANID != 20 {
		t.Errorf("VLANID = %d", r[0].VLANID)
	}
	for _, want := range []string{"one-way", "outer VLAN 1", "inner VLAN 20"} {
		if !strings.Contains(r[0].Detail, want) {
			t.Errorf("detail %q should contain %q", r[0].Detail, want)
		}
	}
	if !containsString(fa.callLog(), "SendFrames eth0 x1") {
		t.Errorf("call log = %v, want exactly one frame transmitted", fa.callLog())
	}
}

func TestDoubleTagNeedsTheNativeVLAN(t *testing.T) {
	tester, fa := newTester(t)
	opts := l2Opts()
	opts.L2.NativeVLAN = 0
	opts.Techniques = []string{model.TechDoubleTag}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)
	r := c.byTechnique(model.TechDoubleTag)
	if len(r) != 1 || r[0].Status != model.ReachError {
		t.Fatalf("results = %+v", r)
	}
	if !strings.Contains(r[0].Detail, "native VLAN") {
		t.Errorf("detail = %q", r[0].Detail)
	}
}

func TestDoubleTagRefusesTheNativeVLANAsTarget(t *testing.T) {
	tester, fa := newTester(t)
	opts := l2Opts()
	opts.L2.NativeVLAN = 20 // same as the target VLAN
	opts.Techniques = []string{model.TechDoubleTag}
	var c collector
	if err := tester.Test(context.Background(), opts,
		[]engine.ReachTarget{svc("10.20.0.10", 80, model.TCP, 1, 11)}, c.add); err != nil {
		t.Fatal(err)
	}
	fa.assertClean(t)
	r := c.byTechnique(model.TechDoubleTag)
	if len(r) != 1 || r[0].Status != model.ReachError ||
		!strings.Contains(r[0].Detail, "nothing to escape") {
		t.Errorf("results = %+v", r)
	}
}

// ---------------------------------------------------------------------------
// Cleanup primitive
// ---------------------------------------------------------------------------

func TestCleanupUnwindsLIFO(t *testing.T) {
	cl := newCleanup()
	var order []string
	cl.push("one", func() error { order = append(order, "one"); return nil })
	cl.push("two", func() error { order = append(order, "two"); return nil })
	cl.push("three", func() error { order = append(order, "three"); return nil })

	if got := cl.pending(); !reflect.DeepEqual(got, []string{"one", "two", "three"}) {
		t.Fatalf("pending = %v", got)
	}
	if err := cl.restore(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"three", "two", "one"}) {
		t.Errorf("order = %v, want LIFO", order)
	}
	if cl.depth() != 0 {
		t.Errorf("depth = %d after restore", cl.depth())
	}
}

func TestCleanupUnwindToPartially(t *testing.T) {
	cl := newCleanup()
	var order []string
	cl.push("keep", func() error { order = append(order, "keep"); return nil })
	depth := cl.depth()
	cl.push("drop-a", func() error { order = append(order, "drop-a"); return nil })
	cl.push("drop-b", func() error { order = append(order, "drop-b"); return nil })

	if err := cl.unwindTo(depth, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"drop-b", "drop-a"}) {
		t.Errorf("order = %v", order)
	}
	if cl.depth() != 1 {
		t.Errorf("depth = %d, want the earlier entry kept", cl.depth())
	}
}

func TestCleanupContinuesAfterAFailingStep(t *testing.T) {
	cl := newCleanup()
	ran := 0
	cl.push("a", func() error { ran++; return nil })
	cl.push("boom", func() error { return errors.New("stuck") })
	cl.push("b", func() error { ran++; return nil })

	err := cl.restore(nil)
	if err == nil || !strings.Contains(err.Error(), "stuck") {
		t.Fatalf("err = %v, want the failure reported", err)
	}
	if ran != 2 {
		t.Errorf("%d steps ran, want 2: one failure must not abort the cleanup", ran)
	}
}

func TestCleanupSurvivesAPanickingStep(t *testing.T) {
	cl := newCleanup()
	ran := false
	cl.push("sane", func() error { ran = true; return nil })
	cl.push("panics", func() error { panic("boom") })

	if err := cl.restore(nil); err == nil {
		t.Fatal("a panicking undo must be reported")
	}
	if !ran {
		t.Error("the remaining step did not run")
	}
}

func TestCleanupRestoreIsIdempotent(t *testing.T) {
	cl := newCleanup()
	calls := 0
	cl.push("once", func() error { calls++; return nil })
	_ = cl.restore(nil)
	_ = cl.restore(nil)
	if calls != 1 {
		t.Errorf("undo ran %d times, want 1", calls)
	}
}
