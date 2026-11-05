// Package fingerprint identifies the service listening behind an open ip:port/proto and
// fills a model.Service with everything it can observe without authenticating.
//
// Detection is layered; each layer is tried in turn and the first confident
// answer wins:
//
//  1. TLS: a handshake on any TCP port that does not speak first, walking
//     from TLS 1.3 down to TLS 1.0 to record the highest accepted version.
//     Application probes then continue inside the tunnel with Tunnel="ssl".
//  2. HTTP(S): GET / without following redirects: status, title, headers,
//     authentication schemes, body digest, favicon hash, technologies.
//  3. SSH: identification banner, offered algorithms, host key fingerprints
//     and accepted authentication methods.
//  4. praetorian-inc/fingerprintx protocol plugins, driven as a library.
//  5. nmap's service-probes engine, loaded at RUNTIME from disk (the data file
//     is never embedded or vendored: it is nmap's, under nmap's licence).
//  6. Banner heuristics and, as a last resort, the port → name table.
//
// UDP services are identified from the answers to a set of protocol probes (DNS, SNMP,
// NTP, NetBIOS, IKE, SSDP, mDNS, memcached, IPMI, SIP...).
//
// Nothing here authenticates, writes or changes state on the target.
package fingerprint

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/engine"
	"github.com/GoToolSharing/nety/internal/model"
	"github.com/GoToolSharing/nety/internal/ports"
)

// Methods reported in model.Service.Method.
const (
	MethodHTTP         = "http"
	MethodSSH          = "ssh"
	MethodTLS          = "tls"
	MethodProbeMatch   = "probe-match"
	MethodSoftMatch    = "softmatch"
	MethodFingerprintX = "fingerprintx"
	MethodUDPProbe     = "udp-probe"
	MethodBanner       = "banner"
	MethodPortTable    = "port-table"
)

// Confidence attached to each detection method (0..100). Exported so the runner and the
// UI can reason about how much a result is worth.
const (
	ConfSSH          = 95
	ConfHTTP         = 90
	ConfProbeMatch   = 90
	ConfFingerprintX = 85
	ConfSoftMatch    = 60
	ConfTLSOnly      = 55
	ConfBanner       = 50
	ConfPortTable    = 20
)

// confidentEnough stops the layer chain.
const confidentEnough = 85

// Bounds on the free-form Extra map.
const (
	maxExtraKeys  = 48
	maxExtraValue = 256
)

type fingerprinter struct{ log *slog.Logger }

// New returns a Fingerprinter. log may be nil.
func New(log *slog.Logger) engine.Fingerprinter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &fingerprinter{log: log}
}

// Fingerprint identifies the service on ip:port/proto.
//
// The port is already known to be open, so a connection failure is not fatal: the
// port-table fallback is still returned (with the error) so the caller can record
// something useful. An error is returned for cancellation and for invalid arguments.
func (f *fingerprinter) Fingerprint(
	ctx context.Context, ip netip.Addr, port uint16,
	proto model.Protocol, opts engine.FingerprintOptions,
) (model.Service, error) {
	svc := model.Service{
		IP:       ip.String(),
		Port:     int(port),
		Protocol: proto,
		State:    model.PortOpen,
	}
	if !ip.IsValid() || port == 0 {
		return svc, fmt.Errorf("fingerprint: invalid target %s:%d", ip, port)
	}
	finalize(&svc, port, proto)

	if proto != model.TCP && proto != model.UDP {
		return svc, fmt.Errorf("fingerprint: unsupported protocol %q", proto)
	}
	if err := ctx.Err(); err != nil {
		return svc, err
	}

	d := &dialer{
		ip:       ip,
		port:     port,
		proto:    string(proto),
		timeout:  normalizeTimeout(opts.Timeout),
		hostname: opts.Hostname,
	}
	intensity := normalizeIntensity(opts.Intensity)

	start := time.Now()
	var err error
	if proto == model.UDP {
		err = f.fingerprintUDP(ctx, d, &svc, intensity)
	} else {
		err = f.fingerprintTCP(ctx, d, &svc, intensity)
	}
	f.log.Debug("fingerprint done",
		"target", d.addr(), "proto", proto, "name", svc.Name, "product", svc.Product,
		"method", svc.Method, "confidence", svc.Confidence, "took", time.Since(start))

	if ctxErr := ctx.Err(); ctxErr != nil {
		return svc, ctxErr
	}
	return svc, err
}

// --------------------------------------------------------------------------- TCP
// ---------------------------------------------------------------------------

func (f *fingerprinter) fingerprintTCP(
	ctx context.Context, d *dialer, svc *model.Service, intensity int,
) error {
	// Layer 0, the NULL probe. A service that speaks first hands us its banner and,
	// incidentally, proves it is not TLS (a TLS server never speaks before the
	// ClientHello), which lets us skip the handshake.
	peek := d.peek(ctx)
	if !peek.dialed {
		f.log.Debug("connect failed", "target", d.addr(), "err", peek.err)
		return peek.err
	}
	banner := peek.data

	// Layer 1, TLS.
	if len(banner) == 0 && ctx.Err() == nil {
		if info, conn, err := d.probeTLS(ctx, tlsALPN); err == nil {
			svc.TLS = info
			svc.Tunnel = "ssl"
			banner = d.peekConn(conn)
			_ = conn.Close()
			svc.Confidence = ConfTLSOnly
			svc.Method = MethodTLS
		} else {
			f.log.Debug("tls handshake failed", "target", d.addr(), "err", err)
		}
	}
	useTLS := svc.Tunnel == "ssl"
	if len(banner) > 0 {
		svc.Banner = printable(banner)
	}

	// Layer 3, SSH, hoisted because the banner already proves it.
	if bytes.HasPrefix(banner, []byte("SSH-")) {
		f.fillSSH(ctx, d, svc, banner)
		return nil
	}

	// Layer 2, HTTP(S). HTTP servers do not speak first, so we try whenever the service
	// stayed silent, when it answered with an HTTP response, or when ALPN announced HTTP
	// inside the tunnel.
	if ctx.Err() == nil && (len(banner) == 0 || looksHTTP(banner) || alpnIsHTTP(svc.TLS)) {
		if res, err := d.probeHTTP(ctx, useTLS); err == nil && res != nil {
			f.fillHTTP(svc, res, useTLS)
			f.refineHTTP(ctx, d, svc, useTLS)
			return nil
		} else if err != nil {
			f.log.Debug("http probe failed", "target", d.addr(), "tls", useTLS, "err", err)
		}
	}

	// Layer 4, the fingerprintx plugins.
	if ctx.Err() == nil {
		if s := f.probeFPX(ctx, d, useTLS, intensity); s != nil {
			fillFromFPX(svc, s)
			if svc.Confidence >= confidentEnough {
				return nil
			}
		}
	}

	// Layer 5, the nmap service probes (runtime data file).
	if ctx.Err() == nil {
		applyProbeOutcome(svc, f.probeNmap(ctx, d, banner, useTLS, intensity))
		if svc.Confidence >= confidentEnough {
			return nil
		}
	}

	// Layer 6, banner heuristics, then the port table.
	f.fillFallback(svc, d, banner)
	return nil
}

func (f *fingerprinter) fillSSH(ctx context.Context, d *dialer, svc *model.Service, banner []byte) {
	info := f.probeSSH(ctx, d, banner)
	svc.SSH = info
	svc.Name = "ssh"
	svc.Banner = printable([]byte(info.Banner))
	id := parseSSHIdent(info.Banner)
	svc.Product, svc.Version, svc.OSType = id.Product, id.Version, id.OS
	if id.Extra != "" {
		svc.ExtraInfo = id.Extra
	}
	svc.CPEs = mergeUnique(svc.CPEs, id.CPEs)
	svc.Method = MethodSSH
	svc.Confidence = ConfSSH
	if len(info.HostKeys) > 0 {
		setExtra(svc, "ssh.hostkey."+strings.ToLower(info.HostKeys[0].Type), info.HostKeys[0].SHA256)
	}
	if len(info.AuthMeth) == 1 && info.AuthMeth[0] == "none" {
		setExtra(svc, "ssh.none_auth", "true")
	}
}

func (f *fingerprinter) fillHTTP(svc *model.Service, res *httpResult, useTLS bool) {
	svc.HTTP = res.info
	svc.Name = "http"
	svc.Method = MethodHTTP
	svc.Confidence = ConfHTTP
	if len(res.banner) > 0 {
		svc.Banner = printable(res.banner)
	}

	sp := parseServerHeader(res.info.Server)
	svc.Product, svc.Version = sp.Product, sp.Version
	if sp.Extra != "" {
		svc.ExtraInfo = sp.Extra
	}
	if sp.OS != "" {
		svc.OSType = sp.OS
	}
	svc.CPEs = mergeUnique(svc.CPEs, sp.CPEs)

	if svc.Product == "" && len(res.info.Technologies) > 0 {
		svc.Product = res.info.Technologies[0]
	}
	if res.info.Title != "" {
		setExtra(svc, "http.title", res.info.Title)
	}
	if res.info.Location != "" {
		setExtra(svc, "http.location", res.info.Location)
	}
	if res.info.PoweredBy != "" {
		setExtra(svc, "http.powered_by", res.info.PoweredBy)
	}
	if len(res.info.Technologies) > 0 {
		setExtra(svc, "http.technologies", strings.Join(res.info.Technologies, ", "))
	}
	if len(res.info.AuthSchemes) > 0 {
		setExtra(svc, "http.auth_schemes", strings.Join(res.info.AuthSchemes, ", "))
	}
	if res.info.FaviconMMH3 != "" {
		setExtra(svc, "http.favicon_mmh3", res.info.FaviconMMH3)
	}
	setExtra(svc, "http.status", strconv.Itoa(res.info.StatusCode))
	if useTLS {
		svc.Tunnel = "ssl"
	}
}

func (f *fingerprinter) fillFallback(svc *model.Service, d *dialer, banner []byte) {
	// The banner rules describe TCP services that speak first; applying them to a UDP
	// datagram would be guesswork (a NetBIOS reply starting with 0xFF would read as a
	// telnet IAC), so UDP relies on its own decoders.
	if len(banner) > 0 && d.proto == string(model.TCP) {
		if rule, version, ok := bannerMatch(printable(banner)); ok && rule.name != "unknown" {
			if svc.Confidence < ConfBanner {
				svc.Name = rule.name
				svc.Product = rule.product
				svc.Version = version
				if rule.extra != "" {
					svc.ExtraInfo = rule.extra
				}
				if rule.ostype != "" {
					svc.OSType = rule.ostype
				}
				if rule.cpe != "" {
					svc.CPEs = mergeUnique(svc.CPEs, []string{rule.cpe})
				}
				svc.Method = MethodBanner
				svc.Confidence = ConfBanner
			}
			return
		}
	}
	if svc.Confidence >= ConfPortTable && svc.Name != "" {
		return
	}
	finalize(svc, d.port, model.Protocol(d.proto))
}

// --------------------------------------------------------------------------- shared
// helpers ---------------------------------------------------------------------------

// tlsALPN is offered on every handshake: it costs nothing and tells us whether the
// service behind the tunnel speaks HTTP.
var tlsALPN = []string{"http/1.1", "h2"}

func alpnIsHTTP(t *model.TLSInfo) bool {
	return t != nil && (t.ALPN == "http/1.1" || t.ALPN == "h2")
}

func finalize(svc *model.Service, port uint16, proto model.Protocol) {
	name := ports.ServiceName(port, proto)
	if name == "" {
		return
	}
	svc.Name = name
	if svc.Method == "" || svc.Confidence < ConfPortTable {
		svc.Method = MethodPortTable
		svc.Confidence = ConfPortTable
	}
}

func setExtra(svc *model.Service, key, value string) {
	value = truncate(cleanText(value), maxExtraValue)
	if key == "" || value == "" {
		return
	}
	if svc.Extra == nil {
		svc.Extra = make(map[string]string, 8)
	}
	if _, exists := svc.Extra[key]; !exists && len(svc.Extra) >= maxExtraKeys {
		return
	}
	svc.Extra[key] = value
}

func normalizeTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTimeout
	}
	if d > 60*time.Second {
		return 60 * time.Second
	}
	return d
}

func normalizeIntensity(i int) int {
	switch {
	case i <= 0:
		return 7
	case i > 9:
		return 9
	default:
		return i
	}
}
