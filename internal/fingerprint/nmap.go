package fingerprint

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/vaadata/nety/internal/fingerprint/nmapdb"
	"github.com/vaadata/nety/internal/model"
)

// The nmap-service-probes data file is NOT shipped with NETY: it belongs to
// the Nmap project and carries its licence. It is loaded at runtime from
// $NETY_NMAP_PROBES, /usr/share/nmap/nmap-service-probes or
// /usr/local/share/nmap/nmap-service-probes. Detection degrades gracefully to
// the other layers when it is absent.
const (
	// maxNmapProbes bounds how many probes we send to a single port.
	maxNmapProbes = 20
	// nmapBudget bounds the whole nmap phase for one service.
	nmapBudgetFactor = 6
	nmapBudgetMax    = 30 * time.Second
)

var nmapLoadOnce sync.Once

// loadNmapDB returns the parsed probe database, logging the outcome once.
func (f *fingerprinter) loadNmapDB() *nmapdb.DB {
	db, err := nmapdb.Load()
	nmapLoadOnce.Do(func() {
		switch {
		case err != nil:
			f.log.Info("nmap service probes not loaded, version detection degraded",
				"err", err,
				"hint", "set NETY_NMAP_PROBES or install nmap-service-probes")
		default:
			probes, matches := db.Stats()
			f.log.Info("nmap service probes loaded",
				"path", nmapdb.Path(), "probes", probes, "matches", matches)
		}
	})
	if err != nil {
		return nil
	}
	return db
}

// probeNmap runs the selected nmap probes against the target and returns the
// best match. nullResp, when non-empty, is reused as the answer to the NULL
// probe so we do not reopen a connection for it.
func (f *fingerprinter) probeNmap(
	ctx context.Context, d *dialer, svc *model.Service,
	nullResp []byte, useTLS bool, intensity int,
) *nmapdb.Result {
	db := f.loadNmapDB()
	if db == nil {
		return nil
	}
	probes := db.Select(d.proto, d.port, useTLS, intensity)
	if len(probes) == 0 {
		return nil
	}

	budget := capDuration(time.Duration(nmapBudgetFactor)*d.timeout, nmapBudgetMax)
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var soft *nmapdb.Result
	sent := 0
	for _, p := range probes {
		if ctx.Err() != nil || sent >= maxNmapProbes {
			break
		}
		resp := nullResp
		if len(p.Data) > 0 || len(resp) == 0 {
			var err error
			sent++
			resp, err = d.sendProbe(ctx, p.Data, useTLS, p.TotalWait)
			if err != nil {
				f.log.Debug("nmap probe failed",
					"target", d.addr(), "probe", p.Name, "err", err)
				// A refused or reset connection usually means the service died
				// on the previous probe; keep going, other probes may be fine.
				continue
			}
		}
		if len(resp) == 0 {
			continue
		}
		if svc.Banner == "" {
			svc.Banner = printable(resp)
		}
		r, ok := db.Match(p, resp)
		if !ok {
			continue
		}
		if !r.Soft {
			return r
		}
		if soft == nil {
			soft = r
		}
	}
	return soft
}

// applyNmapResult copies a probe match into the service.
func applyNmapResult(svc *model.Service, r *nmapdb.Result) {
	if r == nil || r.Service == "" {
		return
	}
	conf := confProbeMatch
	method := MethodProbeMatch
	if r.Soft {
		conf, method = confSoftMatch, MethodSoftMatch
	}
	if conf < svc.Confidence {
		return
	}
	svc.Name = strings.TrimPrefix(r.Service, "ssl/")
	if strings.HasPrefix(r.Service, "ssl/") {
		svc.Tunnel = "ssl"
	}
	if r.Product != "" {
		svc.Product = truncate(cleanText(r.Product), 128)
	}
	if r.Version != "" {
		svc.Version = truncate(cleanText(r.Version), 64)
	}
	if r.Info != "" {
		svc.ExtraInfo = truncate(cleanText(r.Info), 200)
	}
	if r.OSType != "" {
		svc.OSType = truncate(cleanText(r.OSType), 64)
	}
	if r.Hostname != "" {
		setExtra(svc, "probe.hostname", r.Hostname)
	}
	if r.DeviceType != "" {
		setExtra(svc, "probe.device_type", r.DeviceType)
	}
	svc.CPEs = mergeUnique(svc.CPEs, r.CPEs)
	svc.Method = method
	svc.Confidence = conf
}
