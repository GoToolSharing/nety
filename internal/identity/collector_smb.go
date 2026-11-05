package identity

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/GoToolSharing/nety/internal/identity/ntlm"
	"github.com/GoToolSharing/nety/internal/identity/smb"
	"github.com/GoToolSharing/nety/internal/model"
)

// ntlmEvidence converts an NTLM CHALLENGE into identity evidence. extra attributes are
// merged into every evidence item.
func ntlmEvidence(sink *evidenceSink, ch *ntlm.Challenge, source string, extra map[string]string) {
	if ch == nil {
		return
	}
	with := func(m map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range extra {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}
	nbName := strings.TrimSpace(ch.NetBIOSComputer)
	nbDomain := strings.TrimSpace(ch.NetBIOSDomain)
	dnsComp := strings.TrimRight(strings.TrimSpace(ch.DNSComputer), ".")
	dnsDomain := strings.TrimRight(strings.TrimSpace(ch.DNSDomain), ".")
	standalone := nbDomain != "" && strings.EqualFold(nbDomain, nbName)
	if nbDomain == "" && ch.TargetName != "" && ch.Flags&ntlm.FlagTargetTypeDomain != 0 {
		nbDomain = ch.TargetName
	}

	if nbName != "" {
		sink.add(model.EvNetBIOSName, nbName, source, 80, with(map[string]string{"domain": nbDomain}))
	}
	if nbDomain != "" && !standalone {
		sink.add(model.EvNetBIOSDomain, nbDomain, source, 80, with(nil))
	}
	switch {
	case strings.Contains(dnsComp, "."):
		sink.add(model.EvFQDN, strings.ToLower(dnsComp), source, 85, with(nil))
		sink.add(model.EvHostname, strings.ToLower(dnsComp[:strings.IndexByte(dnsComp, '.')]), source, 80, with(nil))
	case dnsComp != "":
		sink.add(model.EvHostname, strings.ToLower(dnsComp), source, 80, with(nil))
	case nbName != "":
		sink.add(model.EvHostname, strings.ToLower(nbName), source, 75, with(nil))
	}
	if dnsDomain != "" && !strings.EqualFold(dnsDomain, dnsComp) && !strings.EqualFold(dnsDomain, nbName) {
		sink.add(model.EvDomain, strings.ToLower(dnsDomain), source, 80, with(map[string]string{
			"forest":         strings.ToLower(strings.TrimRight(ch.DNSTree, ".")),
			"netbios_domain": nbDomain,
		}))
	}
	if ch.Version != nil {
		name, class := ch.Version.Product()
		attrs := with(map[string]string{
			"source":        "ntlm",
			"os_name":       name,
			"build":         strconv.Itoa(int(ch.Version.Build)),
			"ntlm_revision": strconv.Itoa(int(ch.Version.NTLMRevision)),
			"class":         string(class),
		})
		if !ch.Timestamp.IsZero() {
			attrs["server_time"] = ch.Timestamp.UTC().Format(time.RFC3339)
		}
		sink.add(model.EvOSVersion, ch.Version.String(), source, 40, attrs)
	}
}

// probeSMB collects SMB2 NEGOTIATE facts + NTLM CHALLENGE, and SMB1 native strings when
// the server still speaks SMB1.
func (c *collector) probeSMB(ctx context.Context, sink *evidenceSink, ip string, port int) error {
	pctx, cancel := withTimeout(ctx, 3*c.ioTimeout)
	defer cancel()
	p := strconv.Itoa(port)
	smb2Err := func() error {
		conn, err := smb.Dial(pctx, ip, port, c.ioTimeout)
		if err != nil {
			return err
		}
		defer conn.Close()
		ni, err := conn.Negotiate()
		if err != nil {
			return err
		}
		attrs := map[string]string{
			"dialect":          ni.DialectString(),
			"signing_enabled":  strconv.FormatBool(ni.SigningEnabled),
			"signing_required": strconv.FormatBool(ni.SigningRequired),
		}
		if !ni.SystemTime.IsZero() {
			attrs["system_time"] = ni.SystemTime.UTC().Format(time.RFC3339)
		}
		if !ni.ServerStartTime.IsZero() {
			attrs["boot_time"] = ni.ServerStartTime.UTC().Format(time.RFC3339)
		}
		if ni.ServerGUID != "" {
			sink.add(model.EvSMBGUID, ni.ServerGUID, "smb2/"+p, 95, attrs)
		}
		ch, err := conn.Challenge()
		if err != nil {
			return err
		}
		ntlmEvidence(sink, ch, "smb-ntlm/"+p, map[string]string{"smb_dialect": ni.DialectString()})
		return nil
	}()
	if smb2Err != nil && pctx.Err() != nil {
		return smb2Err
	}
	// SMB1: only when SMB2 failed (legacy host) or answered SMB1 only. Modern hosts with
	// SMB1 disabled would just reset the connection.
	if smb2Err == nil {
		return nil
	}
	info, err := smb.SMB1Probe(pctx, ip, port, c.ioTimeout)
	if err != nil {
		return errors.Join(smb2Err, err)
	}
	smb1Evidence(sink, info, "smb1/"+p)
	return nil
}

func smb1Evidence(sink *evidenceSink, info *smb.SMB1Info, source string) {
	if info == nil {
		return
	}
	if info.NativeOS != "" {
		attrs := map[string]string{"source": "smb1", "os_name": info.NativeOS, "lanman": info.NativeLanMan,
			"signing_required": strconv.FormatBool(info.SigningRequired)}
		sink.add(model.EvOSVersion, info.NativeOS, source, 35, attrs)
	}
	if info.Server != "" {
		sink.add(model.EvNetBIOSName, info.Server, source, 75, map[string]string{"domain": info.Domain})
		sink.add(model.EvHostname, strings.ToLower(info.Server), source, 70, nil)
	}
	dom := info.Domain
	if dom == "" {
		dom = info.PrimaryDomain
	}
	if dom != "" && !strings.EqualFold(dom, info.Server) {
		sink.add(model.EvNetBIOSDomain, dom, source, 75, nil)
	}
	if info.ServerGUID != "" {
		sink.add(model.EvSMBGUID, info.ServerGUID, source, 90, map[string]string{"dialect": "NT LM 0.12"})
	}
}
