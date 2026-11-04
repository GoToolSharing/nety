package fingerprint

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/vaadata/nety/internal/fingerprint/udpprobe"
	"github.com/vaadata/nety/internal/model"
)

const (
	// maxUDPProbes bounds how many datagrams we send to one UDP port.
	maxUDPProbes = 20
	// udpSweepIntensity is the intensity from which probes that do not claim
	// the port are tried too, so a service parked on a non-standard port is
	// still identified.
	udpSweepIntensity = 7
	// udpRepeatLimit stops the loop on a service that answers every probe
	// with the same bytes (echo services, dumb proxies).
	udpRepeatLimit = 3
)

// udpPlan orders the probes to send: the ones aimed at this port first, then,
// at high intensity, the rest. targeted is how many of them claim the port.
func udpPlan(port uint16, intensity int) (plan []udpprobe.Probe, targeted int) {
	plan = udpprobe.For(port)
	targeted = len(plan)
	if intensity < udpSweepIntensity {
		return plan, targeted
	}
	seen := make(map[string]bool, len(plan))
	for _, p := range plan {
		seen[p.Name] = true
	}
	for _, p := range udpprobe.All() {
		if len(plan) >= maxUDPProbes {
			break
		}
		if !seen[p.Name] {
			plan = append(plan, p)
		}
	}
	return plan, targeted
}

// fingerprintUDP identifies a UDP service from the answers to a set of
// protocol probes. The port scanner already established that something
// answers there; our job is to say what.
func (f *fingerprinter) fingerprintUDP(
	ctx context.Context, d *dialer, svc *model.Service, intensity int,
) error {
	probes, targeted := udpPlan(d.port, intensity)
	budget := capDuration(time.Duration(len(probes)+1)*d.timeout, 25*time.Second)
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var lastResp []byte
	sent, repeats := 0, 0
	for _, p := range probes {
		if pctx.Err() != nil || sent >= maxUDPProbes || repeats >= udpRepeatLimit {
			break
		}
		// Probes that do not claim this port are a long shot: give them one
		// round trip, not the full per-probe budget.
		wait := capDuration(d.timeout, 4*time.Second)
		if sent >= targeted {
			wait = capDuration(d.timeout, time.Second)
		}
		sent++
		resp, err := d.sendProbe(pctx, p.Payload, false, wait)
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
		if bytes.Equal(resp, lastResp) {
			repeats++
		} else {
			repeats = 0
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
		applyProbeOutcome(svc, f.probeNmap(ctx, d, nil, false, intensity))
		if svc.Confidence >= confidentEnough {
			return nil
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
		conf = ConfBanner
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

// udpExchange sends one datagram and waits for an answer, retrying a few
// times because UDP loses packets silently. It is used by the nmap UDP probe
// engine, which does not own the socket.
func udpExchange(ctx context.Context, dial func(context.Context) (net.Conn, error),
	payload []byte, wait time.Duration, retries int) []byte {
	if wait <= 0 {
		wait = defaultTimeout
	}
	if retries < 1 {
		retries = 1
	}
	for range retries {
		if ctx.Err() != nil {
			return nil
		}
		c, err := dial(ctx)
		if err != nil {
			// ICMP port unreachable surfaces here on a connected socket.
			return nil
		}
		resp := func() []byte {
			defer func() { _ = c.Close() }()
			if len(payload) > 0 {
				if err := c.SetWriteDeadline(time.Now().Add(wait)); err != nil {
					return nil
				}
				if _, err := c.Write(payload); err != nil {
					return nil
				}
			}
			data, _, _ := readResponse(c, wait, 300*time.Millisecond, nil)
			return data
		}()
		if len(resp) > 0 {
			return resp
		}
	}
	return nil
}
