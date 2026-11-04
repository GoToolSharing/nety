package identity

import (
	"strconv"
	"strings"

	"github.com/vaadata/nety/internal/model"
	"github.com/vaadata/nety/internal/oui"
)

// Confidence of the evidence derived from data the fingerprinter already
// collected. These cost no extra packet.
const (
	confSSHHostKey = 90
	confTLSUnique  = 80
	confTLSShared  = 35
	confFavicon    = 20
	confMACLocal   = 80
	confVendor     = 15
)

// fromServiceData mines evidence out of what the fingerprint phase already
// learned: SSH host key fingerprints, TLS leaf certificates, favicon hashes,
// and the host's own MAC with its OUI vendor. No packet is sent.
func (c *collector) fromServiceData(sink *evidenceSink, host model.Host, open []model.Service) {
	for _, s := range open {
		src := svcSource(s)
		sshEvidence(sink, s, src)
		tlsEvidence(sink, s, src)
		faviconEvidence(sink, s, src)
	}
	macEvidence(sink, host)
}

func svcSource(s model.Service) string {
	n := svcName(s)
	if n == "" {
		n = "svc"
	}
	return n + "/" + strconv.Itoa(s.Port)
}

// sshEvidence records SSH host key fingerprints. A host key is generated once
// at first boot and survives re-addressing, so it is one of the strongest
// identity keys available on non-Windows hosts.
func sshEvidence(sink *evidenceSink, s model.Service, src string) {
	if s.SSH == nil {
		return
	}
	for _, k := range s.SSH.HostKeys {
		fp := strings.TrimSpace(k.SHA256)
		if fp == "" {
			continue
		}
		attrs := map[string]string{"key_type": k.Type}
		if b := strings.TrimSpace(s.SSH.Banner); b != "" {
			attrs["banner"] = b
		}
		// The fingerprint alone is the key; the type disambiguates nothing
		// because a host presents one key per algorithm.
		sink.add(model.EvSSHHostKey, normalizeSSHFingerprint(fp), src, confSSHHostKey, attrs)
	}
}

// normalizeSSHFingerprint canonicalizes an OpenSSH style "SHA256:base64"
// fingerprint so the same key always produces the same asset key.
func normalizeSSHFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if i := strings.IndexByte(fp, ':'); i >= 0 && strings.EqualFold(fp[:i], "sha256") {
		fp = fp[i+1:]
	}
	// OpenSSH prints the base64 without padding; strip it for stability.
	return "SHA256:" + strings.TrimRight(strings.TrimSpace(fp), "=")
}

// tlsEvidence records the leaf certificate fingerprint. A certificate is a
// good key only when it is unique to the machine: wildcard certificates and
// the obvious vendor defaults are shared across whole fleets, so they are
// recorded at a much lower confidence and flagged for the correlator.
func tlsEvidence(sink *evidenceSink, s model.Service, src string) {
	if s.TLS == nil {
		return
	}
	fp := strings.ToLower(strings.TrimSpace(s.TLS.SHA256))
	fp = strings.NewReplacer(":", "", " ", "").Replace(fp)
	if fp == "" {
		return
	}
	shared := certIsShared(s.TLS)
	conf := confTLSUnique
	if shared {
		conf = confTLSShared
	}
	attrs := map[string]string{
		"subject_cn":  s.TLS.SubjectCN,
		"issuer":      s.TLS.Issuer,
		"self_signed": strconv.FormatBool(s.TLS.SelfSigned),
	}
	if shared {
		attrs["shared"] = "true"
	}
	sink.add(model.EvTLSCert, fp, src, conf, attrs)

	// A self-signed certificate's CN is usually the machine's own name
	// (Windows RDP/WinRM, ESXi, iDRAC, printers all behave this way). A
	// CA-issued certificate's CN is a service name, which may be a load
	// balancer: only trust the self-signed case.
	if !s.TLS.SelfSigned || shared {
		return
	}
	cn := cleanName(s.TLS.SubjectCN)
	if cn == "" || isIPLiteral(cn) || strings.HasPrefix(cn, "*") || !validHostname(cn) {
		return
	}
	if strings.Contains(cn, ".") {
		sink.add(model.EvFQDN, strings.ToLower(cn), src, 55, nil)
	}
	sink.add(model.EvHostname, strings.ToLower(shortLabel(cn)), src, 50, nil)
}

// sharedCertMarkers are subject/issuer strings of certificates that ship
// identically on every unit of a product, or that are issued per-service
// rather than per-machine.
var sharedCertMarkers = []string{
	"localhost",
	"vmware",
	"parallels panel",
	"plesk",
	"iis express development",
	"ubnt",
	"synology inc",
	"default web site",
	"snakeoil",
	"example.com",
	"invalid",
}

// publicCAMarkers identify certificates issued by a public CA: those are
// bound to a DNS name, not to a machine, and the same certificate is often
// installed on a whole pool.
var publicCAMarkers = []string{
	"let's encrypt", "digicert", "sectigo", "comodo", "globalsign",
	"go daddy", "godaddy", "entrust", "thawte", "geotrust", "rapidssl",
	"amazon", "google trust services", "zerossl", "certum", "actalis",
	"buypass", "ssl.com",
}

// certIsShared reports whether a leaf certificate is too widely shared to be
// used as a machine identity key.
func certIsShared(t *model.TLSInfo) bool {
	cn := strings.ToLower(strings.TrimSpace(t.SubjectCN))
	subject := strings.ToLower(t.Subject)
	issuer := strings.ToLower(t.Issuer)

	if strings.HasPrefix(cn, "*.") {
		return true
	}
	for _, s := range t.SANs {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "*.") {
			return true
		}
	}
	for _, m := range sharedCertMarkers {
		if strings.Contains(cn, m) || strings.Contains(subject, m) || strings.Contains(issuer, m) {
			return true
		}
	}
	if !t.SelfSigned {
		for _, m := range publicCAMarkers {
			if strings.Contains(issuer, m) {
				return true
			}
		}
	}
	return false
}

// faviconEvidence records the favicon hash. Many identical appliances serve
// the same favicon, so it is a very weak hint: useful to group a fleet, never
// to identify a machine.
func faviconEvidence(sink *evidenceSink, s model.Service, src string) {
	if s.HTTP == nil {
		return
	}
	h := strings.TrimSpace(s.HTTP.FaviconMMH3)
	if h == "" || h == "0" {
		return
	}
	attrs := map[string]string{"weak": "true"}
	if t := strings.TrimSpace(s.HTTP.Title); t != "" {
		attrs["title"] = t
	}
	sink.add(model.EvHTTPFavicon, h, src, confFavicon, attrs)
}

// macEvidence records the host's MAC and its OUI vendor. A MAC is only the
// host's own on the local segment: beyond an L3 boundary it is the last
// router's. The correlator enforces that (it only trusts EvMAC when the
// observation is flagged SameL2, or when the MAC came from NBSTAT, which is
// readable across a routed boundary), so the attribute below records where
// this one came from.
func macEvidence(sink *evidenceSink, host model.Host) {
	mac := strings.TrimSpace(host.MAC)
	if mac == "" {
		return
	}
	norm := oui.Normalize(mac)
	if norm == "" || oui.IsMulticast(norm) {
		return
	}
	attrs := map[string]string{"source": "arp"}
	vendor := oui.Lookup(norm)
	if oui.IsLocallyAdministered(norm) {
		attrs["locally_administered"] = "true"
	}
	if vendor != "" {
		attrs["vendor"] = vendor
	}
	sink.add(model.EvMAC, norm, "arp", confMACLocal, attrs)

	if vendor != "" && vendor != oui.Random {
		sink.add(model.EvVendor, vendor, "oui", confVendor, nil)
	}
}
