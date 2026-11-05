// Package engine defines the contracts between the scanning engines and the platform (job
// runner). Engine packages implement these interfaces; the job runner only depends on
// this package, and cmd/nety wires implementations.
//
// Conventions for every engine:
//   - Honour ctx cancellation promptly (scans can be cancelled from the UI).
//   - Stream results through the callback as soon as they are known; the
//     callback may be called from several goroutines concurrently.
//   - Never panic; return an error for fatal conditions only. Per-target
//     failures are logged (slog) and skipped.
//   - Linux is the production target. Code must still COMPILE on darwin
//     (build tags + stubs returning ErrUnsupported) so devs can run tests.
package engine

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/GoToolSharing/nety/internal/model"
)

// ErrUnsupported is returned by features that need Linux / raw sockets.
var ErrUnsupported = errors.New("not supported on this platform")

// ErrNeedPrivileges is returned when raw sockets are required but unavailable (not root
// and no CAP_NET_RAW / CAP_NET_ADMIN).
var ErrNeedPrivileges = errors.New("raw socket privileges required (run as root or grant CAP_NET_RAW,CAP_NET_ADMIN)")

// Progress reports done/total units of work for the current phase.
type Progress func(done, total int64)

// --------------------------------------------------------------------------- Network
// interface inspection (package netif)
// ---------------------------------------------------------------------------

type InterfaceInfo struct {
	Name      string         `json:"name"`
	MAC       string         `json:"mac"`
	Up        bool           `json:"up"`
	Addresses []netip.Prefix `json:"addresses"`
	MTU       int            `json:"mtu"`
	IsVLAN    bool           `json:"is_vlan"` // 802.1Q sub-interface
	VLANID    int            `json:"vlan_id,omitempty"`
	Parent    string         `json:"parent,omitempty"`
	// Kind is "ethernet", "wireless", "bridge", "vlan", "loopback", "tunnel" or "other".
	// Wireless matters: everything that works over a cable also works over Wi-Fi except
	// the switch-port techniques, which have no meaning on an access point association.
	Kind     string `json:"kind"`
	Wireless bool   `json:"wireless"`
}

// LinkKind values for InterfaceInfo.Kind.
const (
	LinkEthernet = "ethernet"
	LinkWireless = "wireless"
	LinkBridge   = "bridge"
	LinkVLAN     = "vlan"
	LinkLoopback = "loopback"
	LinkTunnel   = "tunnel"
	LinkOther    = "other"
)

// ErrWirelessUnsupported is returned by the techniques that only exist on a wired switch
// port when the attachment is a Wi-Fi association.
var ErrWirelessUnsupported = errors.New("not applicable on a wireless interface: 802.1Q tagging and switch-port negotiation only exist on a wired switch port")

// NetContext is what the operator's machine sees on the attached network.
type NetContext struct {
	Interface    string           `json:"interface"`
	LocalIP      netip.Addr       `json:"local_ip"`
	LocalIPv6    []netip.Addr     `json:"local_ipv6"`
	LocalMAC     net.HardwareAddr `json:"local_mac"`
	Prefixes     []netip.Prefix   `json:"prefixes"`
	Gateway      netip.Addr       `json:"gateway"`
	GatewayMAC   net.HardwareAddr `json:"gateway_mac"`
	DNSServers   []netip.Addr     `json:"dns_servers"`
	DomainSearch []string         `json:"domain_search"`
	DHCPServer   netip.Addr       `json:"dhcp_server"`
}

type NetInspector interface {
	// Interfaces lists local interfaces (for the UI interface picker).
	Interfaces() ([]InterfaceInfo, error)
	// Detect reads addressing/routing/DNS/DHCP lease info for iface ("" = the interface
	// holding the default route).
	Detect(ctx context.Context, iface string) (NetContext, error)
	// SniffL2 passively listens for CDP/LLDP/DTP/STP/802.1Q frames for dur.
	SniffL2(ctx context.Context, iface string, dur time.Duration) (model.L2Info, error)
}

// --------------------------------------------------------------------------- Host
// discovery (package discovery)
// ---------------------------------------------------------------------------

type DiscoveryOptions struct {
	Interface string
	Targets   []netip.Prefix // already expanded from user input, excludes applied by Excludes
	Excludes  []netip.Prefix
	// Methods: "arp" (local segment only), "icmp-echo", "icmp-timestamp", "tcp-syn" (on
	// TCPPorts), "tcp-ack", "udp" (on UDPPorts). Empty = sane default.
	Methods  []string
	TCPPorts []uint16 // default: 21,22,23,25,53,80,88,135,139,389,443,445,3389,5985,8080,8443
	UDPPorts []uint16 // default: 53,123,137,161,500
	Rate     int      // packets per second, 0 = default (e.g. 5000)
	Retries  int
	Timeout  time.Duration // how long to wait for late replies after the last probe
	Progress Progress
}

type DiscoveredHost struct {
	IP      netip.Addr
	MAC     net.HardwareAddr // set when the host is on the local L2 segment
	TTL     uint8
	RTT     time.Duration
	Methods []string // which probes got an answer, e.g. "arp", "tcp-syn:445"
}

type Discoverer interface {
	Discover(ctx context.Context, opts DiscoveryOptions, out func(DiscoveredHost)) error
}

// --------------------------------------------------------------------------- Port
// scanning (package portscan)
// ---------------------------------------------------------------------------

type ScanMode string

const (
	ModeAuto    ScanMode = "auto"    // syn if privileged, else connect
	ModeSYN     ScanMode = "syn"     // stateless raw SYN scan (masscan style)
	ModeConnect ScanMode = "connect" // full TCP connect()
)

type PortScanOptions struct {
	Interface  string
	Hosts      []netip.Addr
	TCPPorts   []uint16
	UDPPorts   []uint16
	Mode       ScanMode
	Rate       int // packets per second, 0 = default
	Retries    int
	Timeout    time.Duration
	SourcePort uint16 // 0 = random/ephemeral; used by segmentation techniques
	Progress   Progress
}

type PortResult struct {
	IP     netip.Addr
	Port   uint16
	Proto  model.Protocol
	State  model.PortState
	Reason string // syn-ack, rst, udp-response, icmp-port-unreach ...
	TTL    uint8
	RTT    time.Duration
}

type PortScanner interface {
	// Scan reports open ports only (TCP: SYN-ACK / connect success, UDP: a response was
	// received). Closed/filtered ports are NOT reported to keep volume manageable.
	Scan(ctx context.Context, opts PortScanOptions, out func(PortResult)) error
}

// Port specs ("top100", "top1000", "all", "22,80,8000-8100") are parsed by package ports:
// ports.Parse(spec, proto) ([]uint16, error).

// --------------------------------------------------------------------------- Service
// fingerprinting (package fingerprint)
// ---------------------------------------------------------------------------

type FingerprintOptions struct {
	Timeout   time.Duration // per connection
	Intensity int           // 0..9 like nmap --version-intensity, default 7
	Hostname  string        // SNI / Host header if known
}

type Fingerprinter interface {
	// Fingerprint identifies the service on ip:port/proto and returns a filled
	// model.Service (IDs, mission/network/host fields left zero: the caller sets them).
	// It must fill TLS/HTTP/SSH sub-structs when relevant.
	Fingerprint(ctx context.Context, ip netip.Addr, port uint16, proto model.Protocol, opts FingerprintOptions) (model.Service, error)
}

// --------------------------------------------------------------------------- Identity
// collection & correlation (package identity)
// ---------------------------------------------------------------------------

type IdentityCollector interface {
	// Collect gathers identity evidence for a host using its open services (SMB/NTLM,
	// RDP/NTLM, NetBIOS, mDNS, LLMNR, SNMP, SSH host keys, TLS certs, reverse DNS,
	// MAC/OUI ...). dns may be invalid (system resolver).
	Collect(ctx context.Context, host model.Host, services []model.Service, dns []netip.Addr) ([]model.IdentityEvidence, error)
}

type Correlator interface {
	// Resolve decides which existing asset (if any) the observation belongs to and
	// returns the merged asset. Pure function: no I/O.
	Resolve(existing []model.Asset, obs model.HostObservation) model.AssetDecision
	// Enrich derives Host-level fields (Hostname, Domain, OS, Hostnames) from evidence
	// and services. Pure function.
	Enrich(host model.Host, services []model.Service, ev []model.IdentityEvidence) model.Host
}

// --------------------------------------------------------------------------- Light
// vulnerability / misconfiguration checks (package checks)
// ---------------------------------------------------------------------------

type CheckOptions struct {
	Timeout time.Duration
	// Credentials attempts (default creds) can be disabled by the operator.
	AllowDefaultCreds bool
}

type Checker interface {
	// Run executes every applicable check against the host's services and returns
	// findings (IDs/mission/network left zero: caller sets them; HostID/ServiceID left
	// zero too, caller maps by IP/Port/Protocol).
	Run(ctx context.Context, host model.Host, services []model.Service, opts CheckOptions) ([]model.Finding, error)
	// Catalog lists every check (id, title, severity) for the UI.
	Catalog() []CheckInfo
}

type CheckInfo struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Severity    model.Severity `json:"severity"`
	Services    []string       `json:"services"`  // service names it applies to
	Intrusive   bool           `json:"intrusive"` // e.g. login attempts
	Description string         `json:"description"`
	// Remediation is what a finding from this check carries. It lives in the catalogue as
	// well so that anything describing a check, rather than running one, quotes the
	// product's own words instead of writing its own and drifting from them.
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ---------------------------------------------------------------------------
// Segmentation testing (package segment)
// ---------------------------------------------------------------------------

type ReachTarget struct {
	TargetNetworkID int64
	TargetHostID    int64
	TargetServiceID int64 // 0 = host-level target (ICMP only)
	IP              netip.Addr
	IPv6            []netip.Addr // known IPv6 addresses of the same asset, if any
	Port            uint16
	Proto           model.Protocol
	ServiceName     string
	TargetPrefixes  []netip.Prefix // prefixes of the target network (for route techniques)
	TargetVLANID    int            // VLAN ID of the target network if known (L2 techniques)
}

type SegmentOptions struct {
	Interface     string
	Local         NetContext
	L2            model.L2Info // passive L2 recon of the current port (native VLAN, DTP...)
	AltGateways   []netip.Addr // local IPs of multi-homed assets / other routers to try as next hop
	Techniques    []string     // model.Tech*; empty = all non-L2 techniques
	AllowL2Active bool         // required for dot1q-subif / dtp-trunk / double-tag
	VLANIDs       []int        // VLAN IDs to try for L2 techniques (empty = target VLAN IDs)
	Rate          int
	Timeout       time.Duration
	Concurrency   int
	Progress      Progress
	Log           *slog.Logger // live log lines go to the UI
}

type SegmentTester interface {
	// Test tries to reach every target with every enabled technique and streams one
	// ReachResult per (target, technique[, vlan]). It MUST restore any system change it
	// makes (routes, sub-interfaces, DTP state) before returning, including on ctx
	// cancellation.
	Test(ctx context.Context, opts SegmentOptions, targets []ReachTarget, out func(model.ReachResult)) error
	// Techniques lists the supported techniques for the UI.
	Techniques() []TechniqueInfo
}

type TechniqueInfo struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	L2Active    bool   `json:"l2_active"` // needs AllowL2Active, may disturb the switch
	OneWay      bool   `json:"one_way"`   // results can only be "sent"
	Default     bool   `json:"default"`   // enabled when Techniques is empty
}

// --------------------------------------------------------------------------- Exports
// (package export)
// ---------------------------------------------------------------------------

type ExportFormat struct {
	ID          string `json:"id"` // json, csv-services, csv-hosts, csv-findings, csv-reach, nmap-xml, gnmap, md, html, xlsx, targets-txt ...
	Title       string `json:"title"`
	Extension   string `json:"extension"`
	ContentType string `json:"content_type"`
}

// Exporter writes a mission (optionally filtered to one network) in a format.
type Exporter interface {
	Formats() []ExportFormat
	// Export writes data in format id to w. networkID 0 = whole mission.
	Export(w ExportWriter, format string, data model.MissionData, networkID int64) error
}

// ExportWriter is an io.Writer (kept as an interface here to avoid importing io in
// signatures used by generated mocks).
type ExportWriter interface {
	Write(p []byte) (n int, err error)
}
