package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/vaadata/nety/internal/engine"
	"github.com/vaadata/nety/internal/jobs"
	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/ports"
	"github.com/vaadata/nety/internal/store"
)

// scanProfile is a preset the launch form offers so the common cases are one
// click and the operator only drops to custom when they need to.
type scanProfile struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Options     model.ScanOptions `json:"options"`
}

func scanProfiles() []scanProfile {
	base := func(tcp, udp string, checks bool) model.ScanOptions {
		return model.ScanOptions{
			TCPPorts: tcp, UDPPorts: udp, AutoTargets: true,
			ScanMode: string(engine.ModeAuto), Retries: 1, TimeoutMs: 3000,
			Concurrency: 64, HostDiscovery: true, ServiceDetection: true,
			IdentityCollection: true, Checks: checks,
		}
	}
	quick := base("top100", "", false)
	quick.Profile, quick.Rate = "quick", 10000

	standard := base("top1000", "top20", true)
	standard.Profile, standard.Rate = "standard", 5000

	full := base("all", "top100", true)
	full.Profile, full.Rate = "full", 20000

	stealth := base("top1000", "", true)
	stealth.Profile, stealth.Rate = "stealth", 300
	stealth.ScanMode = string(engine.ModeConnect)
	stealth.Retries = 2

	return []scanProfile{
		{ID: "quick", Title: "Quick",
			Description: "Top 100 TCP ports, no UDP, no checks. A first look at a VLAN in a few minutes.",
			Options:     quick},
		{ID: "standard", Title: "Standard",
			Description: "Top 1000 TCP and top 20 UDP ports, full fingerprinting, identity collection and checks. The usual choice.",
			Options:     standard},
		{ID: "full", Title: "Full",
			Description: "All 65535 TCP ports and top 100 UDP. Thorough but long; run it overnight — it can be paused and resumed.",
			Options:     full},
		{ID: "stealth", Title: "Low and slow",
			Description: "Connect scan at 300 packets per second, extra retries. For fragile networks or when an IPS is in the way.",
			Options:     stealth},
	}
}

func (a *API) handleScanProfiles(w http.ResponseWriter, r *http.Request, _ model.User) {
	a.ok(w, scanProfiles())
}

func (a *API) handleTechniques(w http.ResponseWriter, r *http.Request, _ model.User) {
	if a.Engines.Segment == nil {
		a.ok(w, []engine.TechniqueInfo{})
		return
	}
	a.ok(w, a.Engines.Segment.Techniques())
}

func (a *API) handleChecks(w http.ResponseWriter, r *http.Request, _ model.User) {
	if a.Engines.Checker == nil {
		a.ok(w, []engine.CheckInfo{})
		return
	}
	a.ok(w, a.Engines.Checker.Catalog())
}

func (a *API) handleExportFormats(w http.ResponseWriter, r *http.Request, _ model.User) {
	a.ok(w, a.Exporter.Formats())
}

// ---------------------------------------------------------------------------
// scans
// ---------------------------------------------------------------------------

func (a *API) handleListScans(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	scans, err := a.Store.ListScans(r.Context(), m.ID, queryInt(r, "limit", 100))
	if err != nil {
		a.failStore(w, err, "scans")
		return
	}
	a.ok(w, scans)
}

func (a *API) handleCreateScan(w http.ResponseWriter, r *http.Request, u model.User) {
	m, ok := a.requireMission(w, r, u)
	if !ok {
		return
	}
	var req struct {
		NetworkID int64             `json:"network_id"`
		Kind      model.ScanKind    `json:"kind"`
		Options   model.ScanOptions `json:"options"`
		Start     bool              `json:"start"`
	}
	if !a.decode(w, r, &req) {
		return
	}
	if req.Kind == "" {
		req.Kind = model.ScanDiscovery
	}
	switch req.Kind {
	case model.ScanDiscovery, model.ScanSegmentation, model.ScanL2Probe:
	default:
		a.fail(w, http.StatusBadRequest, "invalid", "unknown scan kind")
		return
	}

	net, err := a.Store.Network(r.Context(), req.NetworkID)
	if err != nil || net.MissionID != m.ID {
		a.fail(w, http.StatusBadRequest, "invalid", "pick a network of this mission to scan from")
		return
	}
	if err := a.validateScanOptions(&req.Options, req.Kind, net); err != nil {
		a.fail(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}

	sc, err := a.Store.CreateScan(r.Context(), model.Scan{
		MissionID: m.ID, NetworkID: net.ID, Kind: req.Kind,
		Options: req.Options, CreatedBy: u.ID,
	})
	if err != nil {
		a.failStore(w, err, "scan")
		return
	}
	a.audit(r, u, m.ID, "scan.created",
		fmt.Sprintf("%s on %s", req.Kind, net.Name))

	if req.Start {
		if err := a.Runner.Start(r.Context(), sc.ID); err != nil {
			// The scan exists and can be started later; report the reason.
			sc.Error = err.Error()
			a.created(w, sc)
			return
		}
		sc, _ = a.Store.Scan(r.Context(), sc.ID)
	}
	a.Bus.PublishData(model.EvtScanStatus, m.ID, sc.ID, sc)
	a.created(w, sc)
}

// validateScanOptions applies defaults and refuses configurations that would
// fail later, when the operator is no longer watching.
func (a *API) validateScanOptions(o *model.ScanOptions, kind model.ScanKind, net model.Network) error {
	if o.Profile == "" {
		o.Profile = "custom"
	}
	if o.TCPPorts == "" {
		o.TCPPorts = "top1000"
	}
	if o.TCPPorts != "none" {
		if _, err := ports.Parse(o.TCPPorts, model.TCP); err != nil {
			return fmt.Errorf("TCP ports: %w", err)
		}
	}
	if o.UDPPorts != "" && o.UDPPorts != "none" {
		if _, err := ports.Parse(o.UDPPorts, model.UDP); err != nil {
			return fmt.Errorf("UDP ports: %w", err)
		}
	}
	if o.Rate <= 0 {
		o.Rate = a.Config.DefaultRate
	}
	if o.Rate > a.Config.MaxRate {
		return fmt.Errorf("rate %d exceeds the server limit of %d packets per second", o.Rate, a.Config.MaxRate)
	}
	if o.TimeoutMs <= 0 {
		o.TimeoutMs = int(a.Config.DefaultTimeout.Milliseconds())
	}
	if o.Concurrency <= 0 {
		o.Concurrency = a.Config.WorkerCount
	}
	if o.Retries < 0 || o.Retries > 10 {
		return errors.New("retries must be between 0 and 10")
	}
	switch engine.ScanMode(o.ScanMode) {
	case "", engine.ModeAuto, engine.ModeSYN, engine.ModeConnect:
	default:
		return errors.New("scan mode must be auto, syn or connect")
	}

	if kind == model.ScanDiscovery {
		if len(o.Targets) == 0 && !o.AutoTargets {
			return errors.New("give at least one target, or enable automatic targets")
		}
		if o.AutoTargets && len(o.Targets) == 0 && len(net.Prefixes) == 0 {
			return errors.New("this network has no known prefix: set one, or give explicit targets")
		}
		if _, err := jobs.ParseTargets(o.Targets); err != nil {
			return fmt.Errorf("targets: %w", err)
		}
		if _, err := jobs.ParseTargets(o.Excludes); err != nil {
			return fmt.Errorf("exclusions: %w", err)
		}
	}

	if kind == model.ScanSegmentation {
		known := map[string]engine.TechniqueInfo{}
		if a.Engines.Segment != nil {
			for _, t := range a.Engines.Segment.Techniques() {
				known[t.ID] = t
			}
		}
		for _, t := range o.Techniques {
			info, ok := known[t]
			if !ok {
				return fmt.Errorf("unknown technique %q", t)
			}
			if info.L2Active && !o.AllowL2Active {
				return fmt.Errorf("technique %q changes the switch port configuration: enable the layer-2 option explicitly to use it", t)
			}
		}
	}
	return nil
}

// requireScan loads a scan and checks mission access.
func (a *API) requireScan(w http.ResponseWriter, r *http.Request, u model.User) (model.Scan, bool) {
	id, ok := a.pathID(w, r)
	if !ok {
		return model.Scan{}, false
	}
	sc, err := a.Store.Scan(r.Context(), id)
	if err != nil {
		a.failStore(w, err, "scan")
		return model.Scan{}, false
	}
	if _, ok := a.missionByID(w, r, u, sc.MissionID); !ok {
		return model.Scan{}, false
	}
	return sc, true
}

func (a *API) handleGetScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	a.ok(w, sc)
}

func (a *API) handleDeleteScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	if a.Runner.IsRunning(sc.ID) {
		a.fail(w, http.StatusConflict, "busy", "stop the scan before deleting it")
		return
	}
	if err := a.Store.DeleteScan(r.Context(), sc.ID); err != nil {
		a.failStore(w, err, "scan")
		return
	}
	a.audit(r, u, sc.MissionID, "scan.deleted", fmt.Sprintf("scan #%d", sc.ID))
	a.ok(w, map[string]bool{"ok": true})
}

// handleStartScan starts a queued scan or resumes a paused/interrupted one —
// the same endpoint, because from the operator's point of view it is the same
// gesture and the runner picks up exactly where it stopped.
func (a *API) handleStartScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	action := "scan.started"
	if sc.Status == model.ScanPaused || sc.Status == model.ScanCancelled || sc.Status == model.ScanFailed {
		action = "scan.resumed"
	}
	if err := a.Runner.Start(r.Context(), sc.ID); err != nil {
		switch {
		case errors.Is(err, jobs.ErrBusy):
			a.fail(w, http.StatusConflict, "busy",
				"too many scans are already running; pause one or wait for it to finish")
		default:
			a.fail(w, http.StatusConflict, "conflict", err.Error())
		}
		return
	}
	a.audit(r, u, sc.MissionID, action, fmt.Sprintf("scan #%d", sc.ID))
	updated, _ := a.Store.Scan(r.Context(), sc.ID)
	a.ok(w, updated)
}

func (a *API) handlePauseScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	if err := a.Runner.Pause(sc.ID); err != nil {
		a.fail(w, http.StatusConflict, "conflict", "this scan is not running")
		return
	}
	a.audit(r, u, sc.MissionID, "scan.paused", fmt.Sprintf("scan #%d", sc.ID))
	a.ok(w, map[string]any{"ok": true, "message": "pausing: work in flight is finishing, nothing will be lost"})
}

func (a *API) handleStopScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	if err := a.Runner.Stop(sc.ID); err != nil {
		a.fail(w, http.StatusConflict, "conflict", "this scan is not running")
		return
	}
	a.audit(r, u, sc.MissionID, "scan.stopped", fmt.Sprintf("scan #%d", sc.ID))
	a.ok(w, map[string]any{"ok": true, "message": "stopping: results collected so far are kept"})
}

func (a *API) handleRetryScan(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	n, err := a.Store.RetryFailedWork(r.Context(), sc.ID)
	if err != nil {
		a.failStore(w, err, "scan")
		return
	}
	a.audit(r, u, sc.MissionID, "scan.retry_failed", fmt.Sprintf("scan #%d, %d units", sc.ID, n))
	a.ok(w, map[string]any{"requeued": n})
}

func (a *API) handleScanLogs(w http.ResponseWriter, r *http.Request, u model.User) {
	sc, ok := a.requireScan(w, r, u)
	if !ok {
		return
	}
	logs, err := a.Store.ScanLogs(r.Context(), sc.ID, queryInt64(r, "after"), queryInt(r, "limit", 500))
	if err != nil {
		a.failStore(w, err, "scan logs")
		return
	}
	a.ok(w, logs)
}

// storeServiceFilter is a small constructor so handlers stay readable.
func storeServiceFilter(missionID, networkID int64) store.ServiceFilter {
	return store.ServiceFilter{MissionID: missionID, NetworkID: networkID}
}

var _ = strings.TrimSpace
