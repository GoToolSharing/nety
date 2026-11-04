package fingerprint

import (
	"context"
	"time"

	"github.com/vaadata/nety/internal/fingerprint/udpprobe"
	"github.com/vaadata/nety/internal/model"
)

// maxUDPProbes bounds how many payloads we send to one UDP port.
const maxUDPProbes = 8

// fingerprintUDP identifies a UDP service from the answers to a set of
// protocol probes. The port scanner already established that something
// answers there; our job is to say what.
func (f *fingerprinter) fingerprintUDP(
	ctx context.Context, d *dialer, svc *model.Service, intensity int,
) error {
	probes := udpprobe.For(d.port)
	budget := capDuration(time.Duration(len(probes)+1)*d.timeout, 20*time.Second)
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var lastResp []byte
	sent := 0
	for _, p := range probes {
		if pctx.Err() != nil || sent >= maxUDPProbes {
			break
		}
		sent++
		resp, err := d.sendProbe(pctx, p.Payload, false, capDuration(d.timeout, 4*time.Second))
		if err != nil {
			// ICMP port unreachable surfaces as ECONNREFUSED on a connected
			// UDP socket: the port is not actually serving.
			f.log.Debug("udp probe failed",
				"target", d.addr(), "probe", p.Name, "err", err)
			continue
		}
		if len(resp) == 0 {
			continue
		}
		lastResp = resp
		if svc.Banner == "" {
			svc.Banner = printable(resp)
		}
		r := udpprobe.Decode(p.Name, resp)
		if r == nil {
			r = udpprobe.DecodeAny(d.port, resp)
		}
		if r == nil {
			continue
		}
		applyUDPResult(svc, r)
		if svc.Confidence >= confidentEnough {
			return nil
		}
	}

	// fingerprintx has UDP plugins of its own for protocols we do not probe.
	if svc.Confidence < confidentEnough && ctx.Err() == nil {
		if s := f.probeFPX(ctx, d, false, intensity); s != nil {
			fillFromFPX(svc, s)
			if svc.Confidence >= confidentEnough {
				return nil
			}
		}
	}

	// nmap's UDP probes, when the data file is installed.
	if ctx.Err() == nil {
		if r := f.probeNmap(ctx, d, svc, nil, false, intensity); r != nil {
			applyNmapResult(svc, r)
			if svc.Confidence >= confidentEnough {
				return nil
			}
		}
	}

	f.fillFallback(svc, d, lastResp)
	return nil
}

func applyUDPResult(svc *model.Service, r *udpprobe.Result) {
	if r == nil || r.Name == "" {
		return
	}
	conf := r.Confidence
	switch {
	case conf <= 0:
		conf = confBanner
	case conf > 100:
		conf = 100
	}
	if conf < svc.Confidence {
		// Keep the better answer but still record the new facts.
		for k, v := range r.Extra {
			setExtra(svc, k, v)
		}
		return
	}
	svc.Name = r.Name
	if r.Product != "" {
		svc.Product = truncate(cleanText(r.Product), 128)
	}
	if r.Version != "" {
		svc.Version = truncate(cleanText(r.Version), 64)
	}
	if r.ExtraInfo != "" {
		svc.ExtraInfo = truncate(cleanText(r.ExtraInfo), 200)
	}
	if r.OSType != "" {
		svc.OSType = truncate(cleanText(r.OSType), 64)
	}
	svc.CPEs = mergeUnique(svc.CPEs, r.CPEs)
	for k, v := range r.Extra {
		setExtra(svc, k, v)
	}
	svc.Method = MethodUDPProbe
	svc.Confidence = conf
}
