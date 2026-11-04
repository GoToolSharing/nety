package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	// Blank import: every protocol plugin registers itself in an init().
	_ "github.com/praetorian-inc/fingerprintx/pkg/scan"
)

// fingerprintx is used as a LIBRARY: we drive its protocol plugins ourselves
// (Plugin.Run takes a net.Conn) instead of calling its scanner, so that every
// connection is ours — context-bound, deadlined and counted.
//
// By default only the plugins that claim the port (PortPriority) are run, so
// an unidentified port costs at most a couple of extra connections. A full
// sweep over every plugin is opt-in through a high FingerprintOptions.
// Intensity and is still capped.
const (
	fpxFullSweepIntensity = 8
	fpxMaxFullSweep       = 16
)

// fpxSkip lists plugins NETY implements better itself.
var fpxSkip = map[string]bool{
	"http": true, "https": true, "http2": true, "ssh": true,
}

var fpxPlugins = sync.OnceValue(func() map[plugins.Protocol][]plugins.Plugin {
	out := make(map[plugins.Protocol][]plugins.Plugin, 3)
	for _, proto := range []plugins.Protocol{plugins.TCP, plugins.TCPTLS, plugins.UDP} {
		list := append([]plugins.Plugin(nil), plugins.Plugins[proto]...)
		sort.SliceStable(list, func(i, j int) bool { return list[i].Priority() < list[j].Priority() })
		out[proto] = list
	}
	return out
})

// probeFPX runs the fingerprintx plugins against the target and returns the
// first positive identification, or nil.
func (f *fingerprinter) probeFPX(ctx context.Context, d *dialer, useTLS bool, intensity int) *plugins.Service {
	proto := plugins.TCP
	switch {
	case d.proto == "udp":
		proto = plugins.UDP
	case useTLS:
		proto = plugins.TCPTLS
	}
	list := fpxPlugins()[proto]
	if len(list) == 0 {
		return nil
	}

	target := plugins.Target{Address: netip.AddrPortFrom(d.ip, d.port), Host: d.hostname}
	timeout := capDuration(d.timeout, 8*time.Second)

	// Pass 1: plugins that claim this port.
	for _, p := range list {
		if ctx.Err() != nil {
			return nil
		}
		if fpxSkip[p.Name()] || !pluginClaims(p, d.port) {
			continue
		}
		if svc := f.runFPXPlugin(ctx, d, p, target, useTLS, timeout); svc != nil {
			return svc
		}
	}
	if intensity < fpxFullSweepIntensity {
		return nil
	}
	// Pass 2: opt-in sweep, bounded.
	tried := 0
	for _, p := range list {
		if ctx.Err() != nil || tried >= fpxMaxFullSweep {
			return nil
		}
		if fpxSkip[p.Name()] || pluginClaims(p, d.port) {
			continue
		}
		tried++
		if svc := f.runFPXPlugin(ctx, d, p, target, useTLS, timeout); svc != nil {
			return svc
		}
	}
	return nil
}

// pluginClaims guards PortPriority, which is third-party code reached with an
// attacker-chosen port number.
func pluginClaims(p plugins.Plugin, port uint16) (claims bool) {
	defer func() {
		if recover() != nil {
			claims = false
		}
	}()
	return p.PortPriority(port)
}

// runFPXPlugin gives one plugin a fresh, context-bound connection. Third-party
// parsing code faces hostile input here, so a panic is contained and logged
// rather than taking the scan down.
func (f *fingerprinter) runFPXPlugin(
	ctx context.Context, d *dialer, p plugins.Plugin,
	target plugins.Target, useTLS bool, timeout time.Duration,
) (svc *plugins.Service) {
	defer func() {
		if r := recover(); r != nil {
			f.log.Warn("fingerprintx plugin panicked",
				"plugin", p.Name(), "target", d.addr(), "panic", fmt.Sprint(r))
			svc = nil
		}
	}()

	conn, err := d.connDial(useTLS)(ctx)
	if err != nil {
		return nil
	}
	// The plugin may close the connection itself; a second Close is harmless.
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}

	s, err := p.Run(conn, timeout, target)
	if err != nil || s == nil || s.Protocol == "" {
		return nil
	}
	return s
}

// fpxExtra flattens a plugin's metadata document into printable key/values.
func fpxExtra(s *plugins.Service) map[string]string {
	if s == nil || len(s.Raw) == 0 {
		return nil
	}
	var doc map[string]any
	if err := json.Unmarshal(s.Raw, &doc); err != nil || len(doc) == 0 {
		return nil
	}
	out := make(map[string]string, len(doc))
	prefix := strings.ToLower(s.Protocol)
	for k, v := range doc {
		if len(out) >= maxExtraKeys {
			break
		}
		str := scalarString(v)
		if str == "" {
			continue
		}
		out[prefix+"."+camelToSnake(k)] = truncate(cleanText(str), maxExtraValue)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func scalarString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, min(len(t), 16))
		for _, e := range t {
			if len(parts) >= 16 {
				break
			}
			if s := scalarString(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	case map[string]any:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	default:
		return ""
	}
}

func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
func fillFromFPX(svc *model.Service, s *plugins.Service) {
	name := strings.ToLower(s.Protocol)
	if name == "" || name == "unknown" {
		return
	}
	svc.Name = name
	if s.Version != "" {
		svc.Version = truncate(cleanText(s.Version), 64)
	}
	if svc.Product == "" {
		svc.Product = fpxProductName(name)
	}
	for k, v := range fpxExtra(s) {
		setExtra(svc, k, v)
	}
	if s.TLS {
		svc.Tunnel = "ssl"
	}
	svc.Method = MethodFingerprintX
	svc.Confidence = confFPX
}

// fpxProductName gives a human product label for the protocols fingerprintx
// identifies but does not name.
var fpxProducts = map[string]string{
	"mongodb": "MongoDB", "mssql": "Microsoft SQL Server", "mysql": "MySQL",
	"postgresql": "PostgreSQL", "redis": "Redis key-value store",
	"oracle": "Oracle TNS Listener", "java-rmi": "Java RMI",
	"rdp": "Microsoft Terminal Services", "smb": "SMB",
	"vnc": "VNC", "telnet": "Telnet", "ftp": "FTP", "smtp": "SMTP",
	"imap": "IMAP", "pop3": "POP3", "ldap": "LDAP", "ldaps": "LDAP over TLS",
	"snmp": "SNMP agent", "ntp": "NTP", "dns": "DNS", "dhcp": "DHCP",
	"kafka": "Apache Kafka", "mqtt": "MQTT broker", "modbus": "Modbus",
	"ipmi": "IPMI", "ipsec": "ISAKMP/IKE", "jdwp": "Java Debug Wire Protocol",
	"rsync": "rsyncd", "rtsp": "RTSP", "stun": "STUN", "echo": "echo",
	"netbios": "NetBIOS", "openvpn": "OpenVPN", "snpp": "SNPP", "rpc": "RPC portmapper",
}

func fpxProductName(name string) string { return fpxProducts[name] }
