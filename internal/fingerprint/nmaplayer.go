package fingerprint

import (
	"context"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// The nmap-service-probes data file is NOT shipped with NETY: it belongs to the Nmap
// project and carries its licence. It is read at RUNTIME from $NETY_NMAP_PROBES,
// /usr/share/nmap/nmap-service-probes or /usr/local/share/nmap/nmap-service-probes,
// parsed once and cached. When it is absent this layer is simply skipped and detection
// falls back to the fingerprintx plugins, the banner heuristics and the port table.

// nmapBudget bounds the whole probe phase for one service.
func nmapBudget(timeout time.Duration) time.Duration {
	return capDuration(6*timeout, 30*time.Second)
}

// probeNmap runs the nmap probe engine against the target. nullResp is the banner already
// collected by the NULL probe, reused instead of reopening a connection. It returns the
// outcome, or nil when no probe file is installed.
func (f *fingerprinter) probeNmap(
	ctx context.Context, d *dialer, nullResp []byte, useTLS bool, intensity int,
) *probeOutcome {
	db := loadProbeDB(f.log)
	if db == nil {
		return nil
	}
	deadline := time.Now().Add(nmapBudget(d.timeout))
	dial := d.connDial(useTLS)
	if d.proto == string(model.UDP) {
		return db.runUDP(ctx, dial, d.port, intensity, d.timeout, deadline)
	}
	return db.runTCP(ctx, f.log, dial, d.port, useTLS, intensity, nullResp, d.timeout, deadline)
}

// applyProbeOutcome copies a probe match into the service. A hard match wins over
// anything less confident; a softmatch only fills a gap.
func applyProbeOutcome(svc *model.Service, out *probeOutcome) {
	if out == nil {
		return
	}
	if out.banner != nil && svc.Banner == "" {
		svc.Banner = printable(out.banner)
	}
	switch {
	case out.hard != nil:
		applyMatchResult(svc, out.hard, ConfProbeMatch, MethodProbeMatch)
	case out.soft != nil:
		applyMatchResult(svc, out.soft, ConfSoftMatch, MethodSoftMatch)
	case out.wrapped && svc.Confidence < ConfBanner:
		// Every connection was accepted then closed without a byte: the classic
		// tcpwrapped / ACL-on-connect signature.
		svc.Name = "tcpwrapped"
		svc.ExtraInfo = "connection accepted then closed without data"
		svc.Method = MethodProbeMatch
		svc.Confidence = ConfSoftMatch
	}
}

func applyMatchResult(svc *model.Service, r *matchResult, conf int, method string) {
	if r == nil || r.service == "" || conf < svc.Confidence {
		return
	}
	svc.Name = strings.TrimPrefix(r.service, "ssl/")
	if strings.HasPrefix(r.service, "ssl/") {
		svc.Tunnel = "ssl"
	}
	if r.product != "" {
		svc.Product = truncate(cleanText(r.product), 128)
	}
	if r.version != "" {
		svc.Version = truncate(cleanText(r.version), 64)
	}
	if r.info != "" {
		svc.ExtraInfo = truncate(cleanText(r.info), 200)
	}
	if r.ostype != "" {
		svc.OSType = truncate(cleanText(r.ostype), 64)
	}
	if r.hostname != "" {
		setExtra(svc, "probe.hostname", r.hostname)
	}
	if r.devicetype != "" {
		setExtra(svc, "probe.device_type", r.devicetype)
	}
	if r.probe != "" {
		setExtra(svc, "probe.name", r.probe)
	}
	svc.CPEs = mergeUnique(svc.CPEs, r.cpes)
	svc.Method = method
	svc.Confidence = conf
}

// httpRefineProbes are nmap's HTTP probes, used to put a product name on a web server
// that did not identify itself in a Server header.
var httpRefineProbes = []string{"GetRequest", "HTTPOptions"}

// refineHTTP asks the nmap probe engine for a product/version when the HTTP layer could
// not name the server. It is a no-op without the data file.
func (f *fingerprinter) refineHTTP(ctx context.Context, d *dialer, svc *model.Service, useTLS bool) {
	if svc.Product != "" && svc.Version != "" {
		return
	}
	db := loadProbeDB(f.log)
	if db == nil || ctx.Err() != nil {
		return
	}
	deadline := time.Now().Add(capDuration(2*d.timeout, 10*time.Second))
	out := db.runTCPFiltered(ctx, f.log, d.connDial(useTLS), d.port, useTLS,
		nil, d.timeout, deadline, httpRefineProbes)
	if out == nil || out.hard == nil {
		return
	}
	// The HTTP layer already named the service; only the product facts the probe knows
	// better are taken, never the confidence or the name.
	r := out.hard
	if svc.Product == "" && r.product != "" {
		svc.Product = truncate(cleanText(r.product), 128)
	}
	if svc.Version == "" && r.version != "" {
		svc.Version = truncate(cleanText(r.version), 64)
	}
	if svc.ExtraInfo == "" && r.info != "" {
		svc.ExtraInfo = truncate(cleanText(r.info), 200)
	}
	if svc.OSType == "" && r.ostype != "" {
		svc.OSType = truncate(cleanText(r.ostype), 64)
	}
	svc.CPEs = mergeUnique(svc.CPEs, r.cpes)
	setExtra(svc, "probe.name", r.probe)
}
