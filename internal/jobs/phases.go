package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/oui"
	"github.com/GoToolSharing/nety/internal/ports"
	"github.com/GoToolSharing/nety/internal/store"
)

// Work-unit payloads. Each is a small JSON document stored in scan_work, so a resume
// rebuilds the exact same unit of work after a restart.
type (
	l2Payload struct {
		Interface string `json:"interface"`
		Seconds   int    `json:"seconds"`
	}
	discoveryPayload struct {
		Targets []string `json:"targets"` // prefixes
	}
	portsPayload struct {
		IPs      []string       `json:"ips"`
		Ports    []uint16       `json:"ports"`
		Protocol model.Protocol `json:"protocol"`
	}
	fingerprintPayload struct {
		ServiceID int64 `json:"service_id"`
	}
	hostPayload struct {
		HostID int64 `json:"host_id"`
	}
	segmentPayload struct {
		ServiceIDs []int64 `json:"service_ids"`
		HostIDs    []int64 `json:"host_ids"` // host-level targets (ICMP)
	}
)

// phasesFor lists the phases a scan kind walks through, in order.
func phasesFor(kind model.ScanKind) []model.WorkPhase {
	switch kind {
	case model.ScanSegmentation:
		return []model.WorkPhase{model.PhaseL2, model.PhaseSegment}
	case model.ScanL2Probe:
		return []model.WorkPhase{model.PhaseL2}
	case model.ScanChecks:
		return []model.WorkPhase{model.PhaseFingerprint, model.PhaseIdentity, model.PhaseChecks}
	default:
		return []model.WorkPhase{
			model.PhaseL2, model.PhaseDiscovery,
			model.PhasePortsTCP, model.PhasePortsUDP,
			model.PhaseFingerprint, model.PhaseIdentity, model.PhaseChecks,
		}
	}
}

func marshalUnits[T any](items []T) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// --------------------------------------------------------------------------- planning
// ---------------------------------------------------------------------------

// plan creates the initial work units of a scan. It is idempotent: resuming a scan that
// already has units adds nothing.
func (r *Runner) plan(ctx context.Context, sc model.Scan) error {
	net, err := r.st.Network(ctx, sc.NetworkID)
	if err != nil && sc.NetworkID != 0 {
		return fmt.Errorf("load network: %w", err)
	}

	// Each phase is planned on its own and only if it has no work yet.
	//
	// Checking "does this scan have any phase at all" instead would make planning
	// all-or-nothing: a process that died after writing the L2 unit but before the
	// discovery ones left a scan that resumed into a plan missing its main phase, ran the
	// L2 recon, found nothing to do and reported itself completed. Per-phase, a resume
	// finishes the plan.

	// L2 recon of the switch port we are plugged into. A checks scan works from the
	// inventory and never touches the wire at layer 2, so it is the one kind that skips
	// this.
	if sc.Kind != model.ScanChecks && r.eng.NetInspector != nil && net.Interface != "" {
		has, err := r.phaseHasWork(ctx, sc.ID, model.PhaseL2)
		if err != nil {
			return err
		}
		if !has {
			units, err := marshalUnits([]l2Payload{{Interface: net.Interface, Seconds: 45}})
			if err != nil {
				return err
			}
			if _, err := r.st.AddWork(ctx, sc.ID, model.PhaseL2, units); err != nil {
				return err
			}
		}
	}

	switch sc.Kind {
	case model.ScanSegmentation:
		has, err := r.phaseHasWork(ctx, sc.ID, model.PhaseSegment)
		if err != nil || has {
			return err
		}
		return r.planSegment(ctx, sc)
	case model.ScanL2Probe:
		return nil
	case model.ScanChecks:
		return r.planChecks(ctx, sc)
	}

	// The scanning phases are fed by discovery, so once any of them exists the plan is
	// under way and must not be rebuilt on top of itself.
	started, err := r.phaseHasWork(ctx, sc.ID,
		model.PhaseDiscovery, model.PhasePortsTCP, model.PhasePortsUDP)
	if err != nil {
		return err
	}
	if started {
		return nil
	}

	targets, excludes, err := r.resolveTargets(ctx, sc, net)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no target to scan: set targets explicitly or enable auto targets on a network with known prefixes")
	}
	filter := NewExcludeFilter(excludes)

	// Refuse an impossible scope before building a single work unit. Without this an IPv6
	// /64 picked up from a local interface takes the process down with it, which looks to
	// the operator like an unexplained restart.
	if err := CheckScanSize(targets, excludes); err != nil {
		return err
	}
	count, exact := CountAddresses(targets, MaxScanAddresses)
	size := fmt.Sprintf("%d addresses", count)
	if !exact {
		size = fmt.Sprintf("more than %d addresses", count)
	}
	r.logScan(ctx, sc, "info", fmt.Sprintf("scope: %s (%s)",
		strings.Join(PrefixStrings(targets), ", "), size))

	if sc.Options.HostDiscovery {
		var units []discoveryPayload
		ChunkAddresses(targets, filter, r.opts.DiscoveryChunk, func(batch []netip.Addr) bool {
			// Store the chunk as prefixes so the payload stays small.
			units = append(units, discoveryPayload{Targets: AddrStrings(batch)})
			return true
		})
		raw, err := marshalUnits(units)
		if err != nil {
			return err
		}
		n, err := r.st.AddWork(ctx, sc.ID, model.PhaseDiscovery, raw)
		if err != nil {
			return err
		}
		r.logScan(ctx, sc, "info", fmt.Sprintf("host discovery planned: %d work units", n))
		return nil
	}

	// No host discovery: port-scan every target address directly.
	return r.planPortUnits(ctx, sc, targets, filter)
}

// planPortUnits builds port-scan units for a set of addresses.
func (r *Runner) planPortUnits(ctx context.Context, sc model.Scan, targets []netip.Prefix, filter ExcludeFilter) error {
	tcp, udp, err := r.scanPorts(sc)
	if err != nil {
		return err
	}
	var addrs []netip.Addr
	IterateAddresses(targets, filter, func(a netip.Addr) bool {
		addrs = append(addrs, a)
		return true
	})
	return r.addPortUnits(ctx, sc, addrs, tcp, udp)
}

// addPortUnits chunks host×port space into work units of about PortChunk probes each.
func (r *Runner) addPortUnits(ctx context.Context, sc model.Scan, addrs []netip.Addr, tcp, udp []uint16) error {
	add := func(phase model.WorkPhase, portList []uint16, proto model.Protocol) error {
		if len(portList) == 0 || len(addrs) == 0 {
			return nil
		}
		// A crash between the TCP and the UDP call would otherwise duplicate the first
		// one when the plan is finished on resume.
		if has, err := r.phaseHasWork(ctx, sc.ID, phase); err != nil || has {
			return err
		}
		hostsPerUnit := max(1, r.opts.PortChunk/len(portList))
		var units []portsPayload
		for i := 0; i < len(addrs); i += hostsPerUnit {
			end := min(i+hostsPerUnit, len(addrs))
			units = append(units, portsPayload{
				IPs:      AddrStrings(addrs[i:end]),
				Ports:    portList,
				Protocol: proto,
			})
		}
		raw, err := marshalUnits(units)
		if err != nil {
			return err
		}
		n, err := r.st.AddWork(ctx, sc.ID, phase, raw)
		if err != nil {
			return err
		}
		r.logScan(ctx, sc, "info", fmt.Sprintf("%s scan planned: %d hosts × %d ports in %d work units",
			strings.ToUpper(string(proto)), len(addrs), len(portList), n))
		return nil
	}
	if err := add(model.PhasePortsTCP, tcp, model.TCP); err != nil {
		return err
	}
	return add(model.PhasePortsUDP, udp, model.UDP)
}

// scanPorts resolves the port specification of a scan.
func (r *Runner) scanPorts(sc model.Scan) (tcp, udp []uint16, err error) {
	spec := sc.Options.TCPPorts
	if spec == "" {
		spec = "top1000"
	}
	if spec != "none" {
		if tcp, err = ports.Parse(spec, model.TCP); err != nil {
			return nil, nil, fmt.Errorf("tcp ports: %w", err)
		}
	}
	if u := sc.Options.UDPPorts; u != "" && u != "none" {
		if udp, err = ports.Parse(u, model.UDP); err != nil {
			return nil, nil, fmt.Errorf("udp ports: %w", err)
		}
	}
	return tcp, udp, nil
}

// resolveTargets merges the explicit targets, the network prefixes and the mission scope,
// then the exclusions.
func (r *Runner) resolveTargets(ctx context.Context, sc model.Scan, net model.Network) ([]netip.Prefix, []netip.Prefix, error) {
	specs := append([]string{}, sc.Options.Targets...)
	if sc.Options.AutoTargets {
		specs = append(specs, net.Prefixes...)
		if m, err := r.st.Mission(ctx, sc.MissionID); err == nil {
			specs = append(specs, m.ScopeCIDRs...)
		}
	}
	targets, err := ParseTargets(specs)
	if err != nil {
		return nil, nil, err
	}
	// Auto-targets come from what was detected on the interface, which includes
	// addressing that is not a scan scope.
	targets, dropped := KeepScannable(targets)
	if len(dropped) > 0 {
		r.log.Info("jobs: prefixes dropped from the scope, not scannable",
			"scan", sc.ID, "prefixes", PrefixStrings(dropped))
	}

	excludes, err := r.exclusions(ctx, sc, net)
	if err != nil {
		return nil, nil, err
	}
	return targets, excludes, nil
}

// exclusions gathers everything that must never be probed: the scan's own exclusion list,
// the mission-wide one, and the operator's own address.
func (r *Runner) exclusions(ctx context.Context, sc model.Scan, net model.Network) ([]netip.Prefix, error) {
	specs := append([]string{}, sc.Options.Excludes...)
	if m, err := r.st.Mission(ctx, sc.MissionID); err == nil {
		specs = append(specs, m.ExcludeCIDRs...)
	}
	if net.LocalIP != "" {
		specs = append(specs, net.LocalIP)
	}
	out, err := ParseTargets(specs)
	if err != nil {
		return nil, fmt.Errorf("exclusions: %w", err)
	}
	return out, nil
}

// exclusionFilter builds the in-scope test for a scan.
func (r *Runner) exclusionFilter(ctx context.Context, sc model.Scan) (ExcludeFilter, error) {
	net, _ := r.st.Network(ctx, sc.NetworkID)
	excludes, err := r.exclusions(ctx, sc, net)
	if err != nil {
		return ExcludeFilter{}, err
	}
	return NewExcludeFilter(excludes), nil
}

// planSegment builds the segmentation work units: every service discovered on the OTHER
// networks of the mission becomes a target to try to reach from here.
func (r *Runner) planSegment(ctx context.Context, sc model.Scan) error {
	networks, err := r.st.ListNetworks(ctx, sc.MissionID)
	if err != nil {
		return err
	}
	wanted := map[int64]bool{}
	for _, id := range sc.Options.SourceNetworkIDs {
		wanted[id] = true
	}

	// Exclusions are a scope boundary, not a discovery detail: an address the client told
	// us to stay away from must not be probed from here either, even though it was
	// inventoried before the exclusion was added.
	filter, err := r.exclusionFilter(ctx, sc)
	if err != nil {
		return err
	}
	skipped := 0
	skippedHosts := 0
	inScope := func(ip string) bool {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		if filter.Allows(addr) {
			return true
		}
		skipped++
		return false
	}

	var serviceIDs []int64
	var hostIDs []int64
	for _, n := range networks {
		if n.ID == sc.NetworkID {
			continue // we are plugged here, nothing to prove
		}
		if len(wanted) > 0 && !wanted[n.ID] {
			continue
		}
		services, err := r.st.ListServices(ctx, store.ServiceFilter{MissionID: sc.MissionID, NetworkID: n.ID})
		if err != nil {
			return err
		}
		for _, sv := range services {
			if !inScope(sv.IP) {
				continue
			}
			serviceIDs = append(serviceIDs, sv.ID)
		}
		hosts, err := r.st.ListHosts(ctx, sc.MissionID, n.ID)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if !inScope(h.IP) {
				continue
			}
			// A skipped host is out of scope for the operator, and its services are
			// already left out by the service listing. Probing it at host level would
			// contradict that, and it would put the machine back in the matrix through
			// the ICMP row.
			if h.Triage.Status == model.TriageSkipped {
				skippedHosts++
				continue
			}
			hostIDs = append(hostIDs, h.ID)
		}
	}
	if skipped > 0 {
		r.logScan(ctx, sc, "info",
			fmt.Sprintf("%d inventoried targets skipped: they are outside the scope (exclusions)", skipped))
	}
	if skippedHosts > 0 {
		r.logScan(ctx, sc, "info",
			fmt.Sprintf("%d hosts skipped: the operator marked them out of scope", skippedHosts))
	}
	if len(serviceIDs) == 0 && len(hostIDs) == 0 {
		return fmt.Errorf("nothing to test: run a discovery scan on at least one other network first, and check the exclusion list")
	}

	var units []segmentPayload
	for i := 0; i < len(serviceIDs); i += r.opts.SegmentChunk {
		end := min(i+r.opts.SegmentChunk, len(serviceIDs))
		units = append(units, segmentPayload{ServiceIDs: serviceIDs[i:end]})
	}
	for i := 0; i < len(hostIDs); i += r.opts.SegmentChunk {
		end := min(i+r.opts.SegmentChunk, len(hostIDs))
		units = append(units, segmentPayload{HostIDs: hostIDs[i:end]})
	}
	raw, err := marshalUnits(units)
	if err != nil {
		return err
	}
	n, err := r.st.AddWork(ctx, sc.ID, model.PhaseSegment, raw)
	if err != nil {
		return err
	}
	r.logScan(ctx, sc, "info", fmt.Sprintf(
		"segmentation test planned: %d services and %d hosts from other networks, in %d work units",
		len(serviceIDs), len(hostIDs), n))
	return nil
}

// generate creates the work units of the phase that follows the one that just finished,
// from the results stored so far.
//
// A phase only reaches this point once it has fully completed, but `execute` walks every
// phase again on a resume, so a phase that was already complete before the pause would
// get here a second time. Generating again would append a duplicate set of units and redo
// work the scan had already done, which is exactly what requirement R2 forbids, hence
// the guard below.
func (r *Runner) generate(ctx context.Context, sc model.Scan, finished model.WorkPhase) error {
	if generated, ok := generatedPhases[finished]; ok {
		already, err := r.phaseHasWork(ctx, sc.ID, generated...)
		if err != nil {
			return err
		}
		if already {
			return nil
		}
	}
	switch finished {
	case model.PhaseDiscovery:
		if !sc.Options.HostDiscovery {
			return nil // units were planned upfront
		}
		hosts, err := r.st.ListHosts(ctx, sc.MissionID, sc.NetworkID)
		if err != nil {
			return err
		}
		addrs := make([]netip.Addr, 0, len(hosts))
		for _, h := range hosts {
			if a, err := netip.ParseAddr(h.IP); err == nil {
				addrs = append(addrs, a)
			}
		}
		if len(addrs) == 0 {
			r.logScan(ctx, sc, "warn", "host discovery found no live host; nothing to port-scan")
			return nil
		}
		tcp, udp, err := r.scanPorts(sc)
		if err != nil {
			return err
		}
		return r.addPortUnits(ctx, sc, addrs, tcp, udp)

	case model.PhasePortsUDP:
		if !sc.Options.ServiceDetection {
			return nil
		}
		return r.addFingerprintUnits(ctx, sc)

	case model.PhaseFingerprint:
		if !sc.Options.IdentityCollection {
			return nil
		}
		return r.addHostUnits(ctx, sc, model.PhaseIdentity, "identity collection")

	case model.PhaseIdentity:
		if !sc.Options.Checks {
			return nil
		}
		return r.addHostUnits(ctx, sc, model.PhaseChecks, "checks")
	}
	return nil
}

// generatedPhases maps a finished phase to the phases whose units it creates. Host
// discovery feeds both port-scan phases, so both must be considered when deciding whether
// generation already happened.
var generatedPhases = map[model.WorkPhase][]model.WorkPhase{
	model.PhaseDiscovery:   {model.PhasePortsTCP, model.PhasePortsUDP},
	model.PhasePortsUDP:    {model.PhaseFingerprint},
	model.PhaseFingerprint: {model.PhaseIdentity},
	model.PhaseIdentity:    {model.PhaseChecks},
}

// phaseHasWork reports whether any of the given phases already has work units.
func (r *Runner) phaseHasWork(ctx context.Context, scanID int64, want ...model.WorkPhase) (bool, error) {
	phases, err := r.st.PhaseProgress(ctx, scanID)
	if err != nil {
		return false, err
	}
	for _, p := range phases {
		if p.Total == 0 {
			continue
		}
		for _, w := range want {
			if p.Phase == w {
				return true, nil
			}
		}
	}
	return false, nil
}

// addFingerprintUnits plans one unit per known service of the scan's network.
func (r *Runner) addFingerprintUnits(ctx context.Context, sc model.Scan) error {
	services, err := r.st.ListServices(ctx, store.ServiceFilter{
		MissionID: sc.MissionID, NetworkID: sc.NetworkID,
	})
	if err != nil {
		return err
	}
	var units []fingerprintPayload
	for _, sv := range services {
		if sv.Confidence >= 80 && sv.LastScanID == sc.ID {
			continue // already identified during this scan
		}
		units = append(units, fingerprintPayload{ServiceID: sv.ID})
	}
	raw, err := marshalUnits(units)
	if err != nil {
		return err
	}
	n, err := r.st.AddWork(ctx, sc.ID, model.PhaseFingerprint, raw)
	if err != nil {
		return err
	}
	r.logScan(ctx, sc, "info", fmt.Sprintf("service detection planned: %d services", n))
	return nil
}

// planChecks seeds a scan that works from what previous scans already found.
//
// There is no discovery and no port scan here: the operator mapped the network once,
// often with the checks switched off, and now wants the detection and the checks run over
// that inventory. The three phases already chain to one another exactly as they do after
// a port scan, so all this has to do is feed the first one that is enabled.
//
// Nothing is duplicated by running it twice: hosts, services and findings are all keyed
// on what identifies them, so a second pass updates the rows that are there instead of
// adding more, and it leaves the operator's triage alone.
func (r *Runner) planChecks(ctx context.Context, sc model.Scan) error {
	// Any of the three phases existing means the plan is already under way.
	started, err := r.phaseHasWork(ctx, sc.ID,
		model.PhaseFingerprint, model.PhaseIdentity, model.PhaseChecks)
	if err != nil || started {
		return err
	}

	hosts, err := r.st.ListHosts(ctx, sc.MissionID, sc.NetworkID)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("nothing to work from: run a discovery scan on this network first")
	}

	switch {
	case sc.Options.ServiceDetection:
		return r.addFingerprintUnits(ctx, sc)
	case sc.Options.IdentityCollection:
		return r.addHostUnits(ctx, sc, model.PhaseIdentity, "identity collection")
	case sc.Options.Checks:
		return r.addHostUnits(ctx, sc, model.PhaseChecks, "checks")
	}
	return errors.New("nothing to run: enable service detection, identity collection or checks")
}

func (r *Runner) addHostUnits(ctx context.Context, sc model.Scan, phase model.WorkPhase, label string) error {
	hosts, err := r.st.ListHosts(ctx, sc.MissionID, sc.NetworkID)
	if err != nil {
		return err
	}
	units := make([]hostPayload, 0, len(hosts))
	for _, h := range hosts {
		units = append(units, hostPayload{HostID: h.ID})
	}
	raw, err := marshalUnits(units)
	if err != nil {
		return err
	}
	n, err := r.st.AddWork(ctx, sc.ID, phase, raw)
	if err != nil {
		return err
	}
	r.logScan(ctx, sc, "info", fmt.Sprintf("%s planned: %d hosts", label, n))
	return nil
}

// --------------------------------------------------------------------------- phase
// implementations: every result is stored and published immediately
// ---------------------------------------------------------------------------

func (r *Runner) execL2(ctx context.Context, sc model.Scan, _ *runState, u model.WorkUnit) error {
	if r.eng.NetInspector == nil {
		return nil
	}
	var p l2Payload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	dur := time.Duration(p.Seconds) * time.Second
	if dur <= 0 {
		dur = 45 * time.Second
	}

	// Over Wi-Fi there is no switch port to learn about: CDP, LLDP, DTP and STP are wired
	// link protocols and an access point does not relay them to a station. Say so instead
	// of listening for 45 seconds to find nothing.
	if r.interfaceIsWireless(p.Interface) {
		r.logScan(ctx, sc, "info", fmt.Sprintf(
			"%s is a Wi-Fi interface: skipping the switch-port recon (CDP/LLDP/DTP/STP exist only on a wired port). "+
				"Everything else in this scan works exactly as it does on a cable.", p.Interface))
		return nil
	}
	r.logScan(ctx, sc, "info", fmt.Sprintf("listening on %s for switch-port information (%s)", p.Interface, dur))

	l2, err := r.eng.NetInspector.SniffL2(ctx, p.Interface, dur)
	if err != nil {
		// L2 recon is a bonus, never a reason to fail the scan.
		r.logScan(ctx, sc, "warn", "passive L2 recon unavailable: "+err.Error())
		return nil
	}
	net, err := r.st.Network(ctx, sc.NetworkID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	l2.CapturedAt = &now
	net.L2 = l2
	if net.VLANID == 0 && l2.NativeVLAN != 0 {
		net.VLANID = l2.NativeVLAN
	}
	if err := r.st.UpdateNetwork(ctx, net); err != nil {
		return err
	}
	r.bus.PublishData(model.EvtNetwork, sc.MissionID, sc.ID, net)

	for _, n := range l2.Neighbors {
		r.logScan(ctx, sc, "info", fmt.Sprintf("%s neighbour: %s on port %s (%s)",
			strings.ToUpper(n.Protocol), n.DeviceID, n.PortID, n.Platform))
	}
	if l2.DTPSeen {
		r.logScan(ctx, sc, "warn", fmt.Sprintf(
			"the switch port negotiates trunking (DTP mode %q) - a trunk may be obtainable from here", l2.DTPMode))
	}
	return nil
}

func (r *Runner) execDiscovery(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.Discoverer == nil {
		return nil
	}
	var p discoveryPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	prefixes, err := ParseTargets(p.Targets)
	if err != nil {
		return err
	}
	net, _ := r.st.Network(ctx, sc.NetworkID)

	opts := engine.DiscoveryOptions{
		Interface: net.Interface,
		Targets:   prefixes,
		Rate:      r.rate(sc),
		Retries:   sc.Options.Retries,
		Timeout:   r.timeout(sc),
	}
	st.add(func(s *model.ScanStats) { s.TargetsTotal += int64(len(p.Targets)) })

	return r.eng.Discoverer.Discover(ctx, opts, func(dh engine.DiscoveredHost) {
		h := model.Host{
			MissionID:    sc.MissionID,
			NetworkID:    sc.NetworkID,
			IP:           dh.IP.String(),
			TTL:          int(dh.TTL),
			DiscoveredBy: dh.Methods,
			LastScanID:   sc.ID,
		}
		if len(dh.MAC) > 0 {
			h.MAC = dh.MAC.String()
			h.Vendor = oui.Lookup(h.MAC)
		}
		saved, err := r.st.UpsertHost(ctx, h)
		if err != nil {
			r.log.Warn("cannot store host", "ip", h.IP, "error", err)
			return
		}
		st.rememberHost(saved.IP, saved.ID)
		st.add(func(s *model.ScanStats) { s.HostsUp++ })
		r.bus.PublishData(model.EvtHost, sc.MissionID, sc.ID, saved)
	})
}

func (r *Runner) execPorts(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.PortScanner == nil {
		return nil
	}
	var p portsPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	addrs := ParseAddrs(p.IPs)
	if len(addrs) == 0 || len(p.Ports) == 0 {
		return nil
	}
	net, _ := r.st.Network(ctx, sc.NetworkID)

	opts := engine.PortScanOptions{
		Interface: net.Interface,
		Hosts:     addrs,
		Mode:      engine.ScanMode(sc.Options.ScanMode),
		Rate:      r.rate(sc),
		Retries:   sc.Options.Retries,
		Timeout:   r.timeout(sc),
	}
	if opts.Mode == "" {
		opts.Mode = engine.ModeAuto
	}
	if p.Protocol == model.UDP {
		opts.UDPPorts = p.Ports
	} else {
		opts.TCPPorts = p.Ports
	}

	return r.eng.PortScanner.Scan(ctx, opts, func(pr engine.PortResult) {
		ip := pr.IP.String()
		hostID, ok := st.lookupHost(ip)
		if !ok {
			// A port answered on a host discovery missed: record it as live.
			h, err := r.st.UpsertHost(ctx, model.Host{
				MissionID: sc.MissionID, NetworkID: sc.NetworkID, IP: ip,
				TTL: int(pr.TTL), LastScanID: sc.ID,
				DiscoveredBy: []string{fmt.Sprintf("%s:%d", pr.Proto, pr.Port)},
			})
			if err != nil {
				r.log.Warn("cannot store host", "ip", ip, "error", err)
				return
			}
			hostID = h.ID
			st.rememberHost(ip, hostID)
			st.add(func(s *model.ScanStats) { s.HostsUp++ })
			r.bus.PublishData(model.EvtHost, sc.MissionID, sc.ID, h)
		}

		sv := model.Service{
			MissionID: sc.MissionID, NetworkID: sc.NetworkID, HostID: hostID,
			IP: ip, Port: int(pr.Port), Protocol: pr.Proto, State: pr.State,
			Reason: pr.Reason, Name: ports.ServiceName(pr.Port, pr.Proto),
			Confidence: 20, Method: "port-table", LastScanID: sc.ID,
		}
		saved, err := r.st.UpsertService(ctx, sv)
		if err != nil {
			r.log.Warn("cannot store service", "ip", ip, "port", pr.Port, "error", err)
			return
		}
		st.add(func(s *model.ScanStats) { s.PortsOpen++ })
		r.bus.PublishData(model.EvtService, sc.MissionID, sc.ID, saved)
	})
}

func (r *Runner) execFingerprint(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.Fingerprinter == nil {
		return nil
	}
	var p fingerprintPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	sv, err := r.st.Service(ctx, p.ServiceID)
	if err != nil {
		return nil // deleted meanwhile, nothing to do
	}
	addr, err := netip.ParseAddr(sv.IP)
	if err != nil {
		return nil
	}
	host, _ := r.st.Host(ctx, sv.HostID)

	res, err := r.eng.Fingerprinter.Fingerprint(ctx, addr, uint16(sv.Port), sv.Protocol,
		engine.FingerprintOptions{
			Timeout:   r.timeout(sc),
			Intensity: 7,
			Hostname:  firstNonEmptyStr(host.Hostname, host.Domain),
		})
	if err != nil {
		return err
	}
	res.ID = sv.ID
	res.MissionID, res.NetworkID, res.HostID = sv.MissionID, sv.NetworkID, sv.HostID
	res.IP, res.Port, res.Protocol = sv.IP, sv.Port, sv.Protocol
	res.LastScanID = sc.ID
	if res.State == "" {
		res.State = sv.State
	}
	saved, err := r.st.UpsertService(ctx, res)
	if err != nil {
		return err
	}
	st.add(func(s *model.ScanStats) { s.Services++ })
	r.bus.PublishData(model.EvtService, sc.MissionID, sc.ID, saved)
	return nil
}

func (r *Runner) execIdentity(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.Identity == nil && r.eng.Correlator == nil {
		return nil
	}
	var p hostPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	host, err := r.st.Host(ctx, p.HostID)
	if err != nil {
		return nil
	}
	services, err := r.st.ServicesForHost(ctx, host.ID)
	if err != nil {
		return err
	}
	net, _ := r.st.Network(ctx, sc.NetworkID)

	var evidence []model.IdentityEvidence
	if r.eng.Identity != nil {
		dns := ParseAddrs(net.DNSServers)
		evidence, err = r.eng.Identity.Collect(ctx, host, services, dns)
		if err != nil {
			return err
		}
	}
	if r.eng.Correlator == nil {
		return nil
	}

	host = r.eng.Correlator.Enrich(host, services, evidence)
	host.LastScanID = sc.ID
	saved, err := r.st.UpsertHost(ctx, host)
	if err != nil {
		return err
	}

	existing, err := r.st.ListAssets(ctx, sc.MissionID)
	if err != nil {
		return err
	}
	decision := r.eng.Correlator.Resolve(existing, model.HostObservation{
		MissionID: sc.MissionID,
		NetworkID: sc.NetworkID,
		SameL2:    sameL2(net, saved),
		Host:      saved,
		Services:  services,
		Evidence:  evidence,
		SeenAt:    time.Now().UTC(),
	})
	asset, err := r.st.SaveAsset(ctx, decision.Asset)
	if err != nil {
		return err
	}
	if err := r.st.SetHostAsset(ctx, saved.ID, asset.ID); err != nil {
		return err
	}
	saved.AssetID = asset.ID

	st.add(func(s *model.ScanStats) {
		if decision.Matched {
			s.MatchedAssets++
		} else {
			s.NewAssets++
		}
	})
	r.bus.PublishData(model.EvtHost, sc.MissionID, sc.ID, saved)
	r.bus.PublishData(model.EvtAsset, sc.MissionID, sc.ID, asset)
	if decision.Matched && len(decision.Reasons) > 0 {
		r.logScan(ctx, sc, "debug", fmt.Sprintf("%s identified as %s (%s)",
			saved.IP, asset.Label, strings.Join(decision.Reasons, ", ")))
	}
	return nil
}

func (r *Runner) execChecks(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.Checker == nil {
		return nil
	}
	var p hostPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	host, err := r.st.Host(ctx, p.HostID)
	if err != nil {
		return nil
	}
	services, err := r.st.ServicesForHost(ctx, host.ID)
	if err != nil {
		return err
	}
	findings, err := r.eng.Checker.Run(ctx, host, services, engine.CheckOptions{
		Timeout:           r.timeout(sc),
		AllowDefaultCreds: sc.Options.AllowDefaultCreds,
	})
	if err != nil {
		return err
	}
	byPort := make(map[string]int64, len(services))
	for _, sv := range services {
		byPort[fmt.Sprintf("%d/%s", sv.Port, sv.Protocol)] = sv.ID
	}
	for _, f := range findings {
		f.MissionID, f.NetworkID, f.HostID = sc.MissionID, sc.NetworkID, host.ID
		if f.IP == "" {
			f.IP = host.IP
		}
		if f.ServiceID == 0 {
			f.ServiceID = byPort[fmt.Sprintf("%d/%s", f.Port, f.Protocol)]
		}
		f.LastScanID = sc.ID
		saved, err := r.st.UpsertFinding(ctx, f)
		if err != nil {
			r.log.Warn("cannot store finding", "check", f.CheckID, "error", err)
			continue
		}
		st.add(func(s *model.ScanStats) { s.Findings++ })
		r.bus.PublishData(model.EvtFinding, sc.MissionID, sc.ID, saved)
	}
	return nil
}

func (r *Runner) execSegment(ctx context.Context, sc model.Scan, st *runState, u model.WorkUnit) error {
	if r.eng.Segment == nil {
		return nil
	}
	var p segmentPayload
	if err := json.Unmarshal(u.Payload, &p); err != nil {
		return err
	}
	net, err := r.st.Network(ctx, sc.NetworkID)
	if err != nil {
		return err
	}

	targets, err := r.buildReachTargets(ctx, sc, p)
	if err != nil || len(targets) == 0 {
		return err
	}

	local := engine.NetContext{Interface: net.Interface}
	if a, err := netip.ParseAddr(net.LocalIP); err == nil {
		local.LocalIP = a
	}
	if g, err := netip.ParseAddr(net.Gateway); err == nil {
		local.Gateway = g
	}
	if prefixes, err := ParseTargets(net.Prefixes); err == nil {
		local.Prefixes = prefixes
	}

	opts := engine.SegmentOptions{
		Interface:     net.Interface,
		Local:         local,
		L2:            net.L2,
		Techniques:    sc.Options.Techniques,
		AllowL2Active: sc.Options.AllowL2Active,
		Rate:          r.rate(sc),
		Timeout:       r.timeout(sc),
		Concurrency:   max(1, min(sc.Options.Concurrency, 128)),
		Log:           r.log.With("scan", sc.ID),
	}
	if sc.Options.VLANRange != "" {
		opts.VLANIDs = parseVLANRange(sc.Options.VLANRange)
	}

	return r.eng.Segment.Test(ctx, opts, targets, func(res model.ReachResult) {
		res.MissionID = sc.MissionID
		res.ScanID = sc.ID
		res.SourceNetworkID = sc.NetworkID
		saved, err := r.st.UpsertReach(ctx, res)
		if err != nil {
			r.log.Warn("cannot store reachability result", "ip", res.IP, "error", err)
			return
		}
		st.add(func(s *model.ScanStats) {
			s.ReachTested++
			if saved.Status == model.ReachOpen {
				s.ReachOK++
			}
		})
		r.bus.PublishData(model.EvtReach, sc.MissionID, sc.ID, saved)
		if saved.Status == model.ReachOpen {
			r.logScan(ctx, sc, "warn", fmt.Sprintf(
				"segmentation crossed: %s:%d/%s reachable via %s",
				saved.IP, saved.Port, saved.Protocol, saved.Technique))
		}
	})
}

// buildReachTargets turns stored services/hosts into engine targets.
func (r *Runner) buildReachTargets(ctx context.Context, sc model.Scan, p segmentPayload) ([]engine.ReachTarget, error) {
	netCache := map[int64]model.Network{}
	loadNet := func(id int64) model.Network {
		if n, ok := netCache[id]; ok {
			return n
		}
		n, _ := r.st.Network(ctx, id)
		netCache[id] = n
		return n
	}

	out := make([]engine.ReachTarget, 0, len(p.ServiceIDs)+len(p.HostIDs))
	for _, id := range p.ServiceIDs {
		sv, err := r.st.Service(ctx, id)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(sv.IP)
		if err != nil {
			continue
		}
		n := loadNet(sv.NetworkID)
		prefixes, _ := ParseTargets(n.Prefixes)
		out = append(out, engine.ReachTarget{
			TargetNetworkID: sv.NetworkID,
			TargetHostID:    sv.HostID,
			TargetServiceID: sv.ID,
			IP:              addr,
			Port:            uint16(sv.Port),
			Proto:           sv.Protocol,
			ServiceName:     sv.Name,
			TargetPrefixes:  prefixes,
			TargetVLANID:    n.VLANID,
		})
	}
	for _, id := range p.HostIDs {
		h, err := r.st.Host(ctx, id)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		n := loadNet(h.NetworkID)
		prefixes, _ := ParseTargets(n.Prefixes)
		out = append(out, engine.ReachTarget{
			TargetNetworkID: h.NetworkID,
			TargetHostID:    h.ID,
			IP:              addr,
			TargetPrefixes:  prefixes,
			TargetVLANID:    n.VLANID,
		})
	}
	return out, nil
}

// --------------------------------------------------------------------------- small
// helpers ---------------------------------------------------------------------------

// interfaceIsWireless reports whether the named interface is a Wi-Fi link. Unknown
// interfaces are treated as wired, which is the safe default: at worst the recon runs and
// finds nothing.
func (r *Runner) interfaceIsWireless(name string) bool {
	if name == "" || r.eng.NetInspector == nil {
		return false
	}
	ifaces, err := r.eng.NetInspector.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ifaces {
		if i.Name == name {
			return i.Wireless
		}
	}
	return false
}

func (r *Runner) rate(sc model.Scan) int {
	rate := sc.Options.Rate
	if rate <= 0 {
		rate = r.opts.DefaultRate
	}
	return min(rate, r.opts.MaxRate)
}

func (r *Runner) timeout(sc model.Scan) time.Duration {
	if sc.Options.TimeoutMs > 0 {
		return time.Duration(sc.Options.TimeoutMs) * time.Millisecond
	}
	return r.opts.DefaultTimeout
}

// sameL2 reports whether the host sits on the same layer-2 segment as us, so its MAC
// address is its own and not a router's.
func sameL2(net model.Network, h model.Host) bool {
	if h.MAC == "" {
		return false
	}
	addr, err := netip.ParseAddr(h.IP)
	if err != nil {
		return false
	}
	prefixes, err := ParseTargets(net.Prefixes)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// parseVLANRange parses "1-4094" or "10,20,30-40" into VLAN ids.
func parseVLANRange(spec string) []int {
	var out []int
	for _, tok := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' }) {
		if lo, hi, ok := strings.Cut(tok, "-"); ok {
			var a, b int
			if _, err := fmt.Sscanf(lo, "%d", &a); err != nil {
				continue
			}
			if _, err := fmt.Sscanf(hi, "%d", &b); err != nil {
				continue
			}
			for v := a; v <= b && v <= 4094; v++ {
				if v >= 1 {
					out = append(out, v)
				}
			}
			continue
		}
		var v int
		if _, err := fmt.Sscanf(tok, "%d", &v); err == nil && v >= 1 && v <= 4094 {
			out = append(out, v)
		}
	}
	return out
}
