package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/store"
)

// seedScans writes the scan history: one discovery per network, the segmentation run,
// plus a paused one so the resume path is visible.
func seedScans(ctx context.Context, st *store.Store, raw *sql.DB, missionID int64, nets []demoNet, userID int64, now time.Time) error {
	type phasePlan struct {
		phase      model.WorkPhase
		total, bad int
	}

	mk := func(net demoNet, kind model.ScanKind, status model.ScanStatus, opts model.ScanOptions,
		startedAgo, ranFor time.Duration, stats model.ScanStats, phases []phasePlan, phaseName string,
		progress float64, errText string, logLines []logLine) error {

		sc, err := st.CreateScan(ctx, model.Scan{
			MissionID: missionID, NetworkID: net.ID, Kind: kind,
			Options: opts, CreatedBy: userID,
		})
		if err != nil {
			return err
		}
		// Work units, so the phase breakdown in the UI is real.
		for _, p := range phases {
			payloads := make([]json.RawMessage, p.total)
			for i := range payloads {
				payloads[i] = json.RawMessage(fmt.Sprintf(`{"demo":%d}`, i))
			}
			if _, err := st.AddWork(ctx, sc.ID, p.phase, payloads); err != nil {
				return err
			}
			units, err := st.ClaimWork(ctx, sc.ID, p.phase, p.total)
			if err != nil {
				return err
			}
			for i, u := range units {
				if i < p.total-p.bad {
					if err := st.CompleteWork(ctx, u.ID); err != nil {
						return err
					}
					continue
				}
				// Leave the tail pending for a paused scan, failed otherwise.
				if status == model.ScanPaused {
					if err := st.FailWork(ctx, u.ID, "", true); err != nil {
						return err
					}
				} else if err := st.FailWork(ctx, u.ID, "timeout", false); err != nil {
					return err
				}
			}
		}
		if err := st.UpdateScanProgress(ctx, sc.ID, phaseName, progress, stats); err != nil {
			return err
		}
		if err := st.SetScanStatus(ctx, sc.ID, status, errText); err != nil {
			return err
		}
		// The log pane is the part of the scan screen an operator watches, so a demo with
		// an empty one shows the opposite of what the tool does.
		for _, l := range logLines {
			if err := st.AppendScanLog(ctx, sc.ID, l.level, l.msg); err != nil {
				return err
			}
		}
		return backdate(ctx, raw, sc.ID, now.Add(-startedAgo), ranFor, status)
	}

	std := model.ScanOptions{
		Profile: "standard", AutoTargets: true, TCPPorts: "top1000", UDPPorts: "top20",
		Rate: 5000, Retries: 1, TimeoutMs: 3000, Concurrency: 64, ScanMode: "syn",
		HostDiscovery: true, ServiceDetection: true, IdentityCollection: true, Checks: true,
	}
	discoveryPhases := func(hosts, services int) []phasePlan {
		return []phasePlan{
			{model.PhaseL2, 1, 0},
			{model.PhaseDiscovery, 1, 0},
			{model.PhasePortsTCP, 2, 0},
			{model.PhasePortsUDP, 1, 0},
			{model.PhaseFingerprint, services, 0},
			{model.PhaseIdentity, hosts, 0},
			{model.PhaseChecks, hosts, 0},
		}
	}

	plans := []struct {
		net                 int
		hosts, services     int
		startedAgo, ranFor  time.Duration
		findings, newAssets int64
	}{
		{0, 14, 41, 52 * time.Hour, 23 * time.Minute, 11, 14},
		{1, 11, 48, 46 * time.Hour, 31 * time.Minute, 15, 11},
		{2, 7, 15, 28 * time.Hour, 12 * time.Minute, 8, 7},
		{3, 6, 16, 26 * time.Hour, 9 * time.Minute, 11, 6},
	}
	for _, p := range plans {
		err := mk(nets[p.net], model.ScanDiscovery, model.ScanCompleted, std,
			p.startedAgo, p.ranFor,
			model.ScanStats{
				TargetsTotal: 254, HostsUp: int64(p.hosts), PortsOpen: int64(p.services),
				Services: int64(p.services), Findings: p.findings, NewAssets: p.newAssets,
			},
			discoveryPhases(p.hosts, p.services), string(model.PhaseChecks), 1, "",
			discoveryLog(nets[p.net], p.hosts, p.services, int(p.findings)))
		if err != nil {
			return err
		}
	}

	// The segmentation run, from the office VLAN.
	segOpts := model.ScanOptions{
		Profile: "custom", Rate: 2000, TimeoutMs: 2000, Concurrency: 32,
		Techniques:    []string{model.TechDirect, model.TechICMP, model.TechSrcPort53, model.TechSrcPort123, model.TechGatewayRoute},
		AllowL2Active: false,
	}
	if err := mk(nets[0], model.ScanSegmentation, model.ScanCompleted, segOpts,
		20*time.Hour, 47*time.Minute,
		model.ScanStats{ReachTested: 412, ReachOK: 37},
		[]phasePlan{{model.PhaseL2, 1, 0}, {model.PhaseSegment, 7, 0}},
		string(model.PhaseSegment), 1, "", segmentationLog()); err != nil {
		return err
	}

	// A long one the operator paused to go to lunch, so the resume path is visible.
	full := std
	full.Profile, full.TCPPorts, full.UDPPorts = "full", "all", "top100"
	if err := mk(nets[1], model.ScanDiscovery, model.ScanPaused, full,
		3*time.Hour, 2*time.Hour,
		model.ScanStats{TargetsTotal: 254, HostsUp: 11, PortsOpen: 63, Services: 48, Findings: 15},
		[]phasePlan{
			{model.PhaseL2, 1, 0},
			{model.PhaseDiscovery, 1, 0},
			{model.PhasePortsTCP, 16, 6},
		},
		string(model.PhasePortsTCP), 0.62, "", pausedLog(nets[1])); err != nil {
		return err
	}
	return nil
}

// logLine is one line of a scan's log trail.
type logLine struct {
	level, msg string
}

// discoveryLog is what a discovery writes as it goes: the scope it resolved, the plan it
// built for each phase, and the counts it ended on. It is the running commentary an
// operator reads while the scan is live.
func discoveryLog(n demoNet, hosts, services, findings int) []logLine {
	return []logLine{
		{"info", "scan started"},
		{"info", fmt.Sprintf("listening on %s for switch-port information (45s)", n.Network.Interface)},
		{"info", fmt.Sprintf("scope: %s (254 addresses)", n.prefix)},
		{"info", "host discovery planned: 1 work unit"},
		{"info", fmt.Sprintf("host discovery finished: %d hosts answered", hosts)},
		{"info", fmt.Sprintf("TCP scan planned: %d hosts x 1000 ports in 2 work units", hosts)},
		{"info", fmt.Sprintf("UDP scan planned: %d hosts x 20 ports in 1 work unit", hosts)},
		{"info", fmt.Sprintf("service detection planned: %d services", services)},
		{"warn", "10.20.20.45:6379 answered before the banner was requested"},
		{"info", fmt.Sprintf("identity collection finished: %d machines matched", hosts)},
		{"info", fmt.Sprintf("checks finished: %d findings", findings)},
		{"info", "scan completed"},
	}
}

func segmentationLog() []logLine {
	return []logLine{
		{"info", "scan started"},
		{"info", "segmentation test planned: 412 services and 36 hosts from other networks, in 7 work units"},
		{"info", "techniques: direct, icmp, src-port-53, src-port-123, gateway-route"},
		{"warn", "10.20.99.0/24 answered nothing on the direct technique; falling back to the alternate route"},
		{"info", "source port 53 reached 6 services that plain routing could not"},
		{"info", "scan completed: 37 of 412 attempts crossed a boundary"},
	}
}

// pausedLog stops mid sentence, which is what a pause looks like.
func pausedLog(n demoNet) []logLine {
	return []logLine{
		{"info", "scan started"},
		{"info", fmt.Sprintf("scope: %s (254 addresses)", n.prefix)},
		{"info", "host discovery finished: 11 hosts answered"},
		{"info", "TCP scan planned: 11 hosts x 65535 ports in 16 work units"},
		{"error", "port unit 9 failed after 3 attempts: dial tcp 10.20.20.51:9100: i/o timeout"},
		{"info", "paused by demo: 12 of 18 work units done, the rest are kept"},
	}
}

// backdate rewrites timestamps through a second connection rather than adding a demo-only
// escape hatch to the store's API.
func backdate(ctx context.Context, raw *sql.DB, scanID int64, started time.Time, ranFor time.Duration, status model.ScanStatus) error {
	finished := started.Add(ranFor)
	_, err := raw.ExecContext(ctx,
		`UPDATE scans SET created_at = ?, started_at = ?,
		    finished_at = CASE WHEN ? IN ('completed','failed','cancelled') THEN ? ELSE NULL END,
		    paused_at   = CASE WHEN ? = 'paused' THEN ? ELSE NULL END
		 WHERE id = ?`,
		started.Add(-time.Minute).UnixMilli(), started.UnixMilli(),
		string(status), finished.UnixMilli(),
		string(status), finished.UnixMilli(),
		scanID)
	return err
}

// ---------------------------------------------------------------------------
// reachability
// ---------------------------------------------------------------------------

// seedReachability fills the matrix with a result that tells a story: the office VLAN is
// mostly contained but leaks a few flows to the servers, the voice VLAN is not separated
// from the offices at all, and management is reachable from nowhere it should not be.
func seedReachability(ctx context.Context, st *store.Store, missionID int64, nets []demoNet, now time.Time, rng *rand.Rand) error {
	services, err := st.ListServices(ctx, store.ServiceFilter{MissionID: missionID})
	if err != nil {
		return err
	}
	byNet := map[int64][]model.Service{}
	for _, s := range services {
		byNet[s.NetworkID] = append(byNet[s.NetworkID], s)
	}

	// How a source network behaves towards a target network.
	type rule struct {
		src, dst int
		// share of services reachable directly, and via a bypass technique.
		direct, bypass float64
		closed         float64
		technique      string
	}
	rules := []rule{
		// Offices → servers: filtered, but file sharing and the intranet pass, and a
		// stateless rule lets anything with source port 53 through.
		{src: 0, dst: 1, direct: 0.18, bypass: 0.12, closed: 0.05, technique: model.TechSrcPort53},
		// Offices → telephony: wide open, the two VLANs share the same switch.
		{src: 0, dst: 2, direct: 0.85, bypass: 0, closed: 0.05},
		// Offices → management: properly blocked.
		{src: 0, dst: 3, direct: 0, bypass: 0, closed: 0},
		// Telephony → offices: the voice VLAN is not isolated either.
		{src: 2, dst: 0, direct: 0.7, bypass: 0.1, closed: 0.05, technique: model.TechGatewayRoute},
		// Telephony → servers: blocked except one leak.
		{src: 2, dst: 1, direct: 0.04, bypass: 0, closed: 0},
		// Servers → offices: allowed (management agents).
		{src: 1, dst: 0, direct: 0.6, bypass: 0, closed: 0.1},
		// Management → everything, as expected.
		{src: 3, dst: 0, direct: 0.95, bypass: 0, closed: 0},
		{src: 3, dst: 1, direct: 0.95, bypass: 0, closed: 0},
		{src: 3, dst: 2, direct: 0.9, bypass: 0, closed: 0},
	}

	for _, r := range rules {
		src, dst := nets[r.src], nets[r.dst]
		for _, sv := range byNet[dst.ID] {
			tested := now.Add(-time.Duration(18+rng.Intn(6)) * time.Hour)

			// The plain attempt.
			status := model.ReachFiltered
			detail := "aucune réponse - paquet filtré"
			roll := rng.Float64()
			switch {
			case roll < r.direct:
				status = model.ReachOpen
				detail = "connexion établie"
			case roll < r.direct+r.closed:
				status = model.ReachClosed
				detail = "RST reçu - routé, port fermé"
			}
			if r.direct == 0 && r.closed == 0 {
				status = model.ReachUnreachable
				detail = "ICMP administratively prohibited depuis 10.20.10.1"
			}
			rtt := 0.0
			if status == model.ReachOpen || status == model.ReachClosed {
				rtt = 0.4 + rng.Float64()*2.4
			}
			if _, err := st.UpsertReach(ctx, model.ReachResult{
				MissionID: missionID, SourceNetworkID: src.ID, TargetNetworkID: dst.ID,
				TargetHostID: sv.HostID, TargetServiceID: sv.ID,
				IP: sv.IP, Port: sv.Port, Protocol: sv.Protocol,
				Technique: model.TechDirect, Status: status, Detail: detail,
				RTTMs: rtt, TestedAt: tested,
			}); err != nil {
				return err
			}

			// A bypass attempt on what the plain one could not reach.
			if r.technique != "" && status != model.ReachOpen && rng.Float64() < r.bypass*3 {
				if _, err := st.UpsertReach(ctx, model.ReachResult{
					MissionID: missionID, SourceNetworkID: src.ID, TargetNetworkID: dst.ID,
					TargetHostID: sv.HostID, TargetServiceID: sv.ID,
					IP: sv.IP, Port: sv.Port, Protocol: sv.Protocol,
					Technique: r.technique, Status: model.ReachOpen,
					Detail: "connexion établie en contournant le filtrage",
					RTTMs:  0.6 + rng.Float64()*2, TestedAt: tested.Add(time.Minute),
				}); err != nil {
					return err
				}
			}
		}

		// Host-level ICMP, a handful per pair.
		hosts, err := st.ListHosts(ctx, missionID, dst.ID)
		if err != nil {
			return err
		}
		for i, h := range hosts {
			if i >= 4 {
				break
			}
			status := model.ReachOpen
			detail := "ICMP echo reply"
			if r.direct == 0 {
				status = model.ReachUnreachable
				detail = "ICMP administratively prohibited"
			}
			if _, err := st.UpsertReach(ctx, model.ReachResult{
				MissionID: missionID, SourceNetworkID: src.ID, TargetNetworkID: dst.ID,
				TargetHostID: h.ID, IP: h.IP,
				Technique: model.TechICMP, Status: status, Detail: detail,
				RTTMs: 0.3 + rng.Float64(), TestedAt: now.Add(-19 * time.Hour),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
