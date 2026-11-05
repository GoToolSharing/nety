// Package model holds the shared domain types of NETY. Every other package
// (engines, store, API, exports) speaks in these types. JSON tags are the
// wire format of the REST API and of the JSON export, keep them stable.
package model

import (
	"encoding/json"
	"time"
)

// ---------------------------------------------------------------------------
// Users & missions
// ---------------------------------------------------------------------------

type Role string

const (
	RoleAdmin    Role = "admin"    // manages users and every mission
	RoleOperator Role = "operator" // runs scans on missions they belong to
	RoleViewer   Role = "viewer"   // read-only on missions they belong to
)

type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	DisplayName  string     `json:"display_name"`
	Role         Role       `json:"role"`
	PasswordHash string     `json:"-"`
	Disabled     bool       `json:"disabled"`
	MustChangePW bool       `json:"must_change_password"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// Mission is one engagement (audit). Users are attached to missions.
type Mission struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Client       string    `json:"client"`
	Description  string    `json:"description"`
	ScopeCIDRs   []string  `json:"scope_cidrs"`   // optional global scope
	ExcludeCIDRs []string  `json:"exclude_cidrs"` // never touched
	Archived     bool      `json:"archived"`
	CreatedBy    int64     `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ---------------------------------------------------------------------------
// Networks (one per VLAN / attachment point)
// ---------------------------------------------------------------------------

// Network is a network segment (usually a VLAN) the operator plugged into.
type Network struct {
	ID           int64     `json:"id"`
	MissionID    int64     `json:"mission_id"`
	Name         string    `json:"name"`
	VLANID       int       `json:"vlan_id"` // 0 = unknown / untagged
	Description  string    `json:"description"`
	Interface    string    `json:"interface"`     // local NIC used when captured
	LocalIP      string    `json:"local_ip"`      // operator IP on this network
	LocalMAC     string    `json:"local_mac"`     //
	Prefixes     []string  `json:"prefixes"`      // CIDRs of the local segment(s)
	Gateway      string    `json:"gateway"`       //
	DNSServers   []string  `json:"dns_servers"`   //
	DomainSearch []string  `json:"domain_search"` //
	DHCPServer   string    `json:"dhcp_server"`   //
	L2           L2Info    `json:"l2"`            // passive L2 recon (CDP/LLDP/DTP/STP)
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type L2Info struct {
	Neighbors     []L2Neighbor `json:"neighbors"`
	DTPSeen       bool         `json:"dtp_seen"`
	DTPMode       string       `json:"dtp_mode,omitempty"` // desirable/auto/on/...
	NativeVLAN    int          `json:"native_vlan,omitempty"`
	VoiceVLAN     int          `json:"voice_vlan,omitempty"`
	ObservedVLANs []int        `json:"observed_vlans,omitempty"` // tags seen on the wire
	STPRootBridge string       `json:"stp_root_bridge,omitempty"`
	CapturedAt    *time.Time   `json:"captured_at,omitempty"`
}

type L2Neighbor struct {
	Protocol     string   `json:"protocol"` // cdp | lldp
	DeviceID     string   `json:"device_id"`
	PortID       string   `json:"port_id"`
	Platform     string   `json:"platform,omitempty"`
	Software     string   `json:"software,omitempty"`
	MgmtAddress  string   `json:"mgmt_address,omitempty"`
	NativeVLAN   int      `json:"native_vlan,omitempty"`
	VoiceVLAN    int      `json:"voice_vlan,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

type ScanKind string

const (
	ScanDiscovery    ScanKind = "discovery"    // full mapping of the current network
	ScanSegmentation ScanKind = "segmentation" // replay other networks' services from here
	ScanL2Probe      ScanKind = "l2probe"      // passive/active L2 recon (CDP/LLDP/DTP/VLAN brute)
	// ScanChecks re-runs detection and the checks over what previous scans
	// already inventoried, without discovering or port-scanning anything.
	ScanChecks ScanKind = "checks"
)

type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanPaused    ScanStatus = "paused"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

// ScanOptions is what the operator configures when launching a scan.
type ScanOptions struct {
	Profile string `json:"profile"` // quick | standard | full | custom

	// Targets. If AutoTargets is true, the local prefixes of the network are
	// added (and, if the mission has a scope, its CIDRs).
	Targets     []string `json:"targets"`
	Excludes    []string `json:"excludes"`
	AutoTargets bool     `json:"auto_targets"`

	TCPPorts string `json:"tcp_ports"` // "top100" | "top1000" | "all" | "22,80,8000-8100"
	UDPPorts string `json:"udp_ports"` // same syntax, "" = none

	Rate        int    `json:"rate"`        // packets per second
	Retries     int    `json:"retries"`     //
	TimeoutMs   int    `json:"timeout_ms"`  // per-probe timeout
	Concurrency int    `json:"concurrency"` // service detection workers
	ScanMode    string `json:"scan_mode"`   // syn | connect | auto

	HostDiscovery      bool `json:"host_discovery"`      // false = treat every target as up
	ServiceDetection   bool `json:"service_detection"`   //
	IdentityCollection bool `json:"identity_collection"` //
	Checks             bool `json:"checks"`              //
	// AllowDefaultCreds enables the only intrusive check family: a short,
	// curated list of vendor default credentials, capped so nothing can be
	// locked out. Off by default and opted into per scan.
	AllowDefaultCreds bool `json:"allow_default_creds"`

	// Segmentation only.
	SourceNetworkIDs []int64  `json:"source_network_ids,omitempty"` // whose services to replay (empty = all others)
	Techniques       []string `json:"techniques,omitempty"`         // see Technique* constants, empty = default set
	AllowL2Active    bool     `json:"allow_l2_active"`              // DTP / double-tag / VLAN subif brute
	VLANRange        string   `json:"vlan_range,omitempty"`         // e.g. "1-4094" for subif brute
}

type ScanStats struct {
	TargetsTotal  int64 `json:"targets_total"`
	HostsUp       int64 `json:"hosts_up"`
	PortsOpen     int64 `json:"ports_open"`
	Services      int64 `json:"services"`
	Findings      int64 `json:"findings"`
	ReachTested   int64 `json:"reach_tested"`
	ReachOK       int64 `json:"reach_ok"`
	NewAssets     int64 `json:"new_assets"`
	MatchedAssets int64 `json:"matched_assets"`
}

// WorkPhase identifies a stage of a scan. A scan is split into persisted work
// units per phase so that it can be paused, stopped, or interrupted by a crash
// and resumed later without losing or redoing work.
type WorkPhase string

const (
	PhaseL2          WorkPhase = "l2"           // passive L2 recon of the current port
	PhaseDiscovery   WorkPhase = "discovery"    // host discovery
	PhasePortsTCP    WorkPhase = "ports-tcp"    // TCP port scan
	PhasePortsUDP    WorkPhase = "ports-udp"    // UDP port scan
	PhaseFingerprint WorkPhase = "fingerprint"  // service/version detection
	PhaseIdentity    WorkPhase = "identity"     // identity evidence + asset correlation
	PhaseChecks      WorkPhase = "checks"       // light misconfiguration checks
	PhaseSegment     WorkPhase = "segmentation" // inter-network reachability tests
)

// AllPhases is the canonical order phases run in.
var AllPhases = []WorkPhase{
	PhaseL2, PhaseDiscovery, PhasePortsTCP, PhasePortsUDP,
	PhaseFingerprint, PhaseIdentity, PhaseChecks, PhaseSegment,
}

type WorkStatus string

const (
	WorkPending WorkStatus = "pending"
	WorkRunning WorkStatus = "running"
	WorkDone    WorkStatus = "done"
	WorkFailed  WorkStatus = "failed"
)

// WorkUnit is one resumable chunk of a scan (a slice of targets, a batch of
// host/port probes, one service to fingerprint, one reachability test...).
// Payload is a phase-specific JSON document interpreted by the runner.
type WorkUnit struct {
	ID       int64           `json:"id"`
	ScanID   int64           `json:"scan_id"`
	Phase    WorkPhase       `json:"phase"`
	Seq      int64           `json:"seq"`
	Payload  json.RawMessage `json:"payload"`
	Status   WorkStatus      `json:"status"`
	Attempts int             `json:"attempts"`
	Error    string          `json:"error,omitempty"`
	LeasedAt *time.Time      `json:"leased_at,omitempty"`
	DoneAt   *time.Time      `json:"done_at,omitempty"`
}

// PhaseProgress is the live progress of one phase of a scan.
type PhaseProgress struct {
	Phase   WorkPhase `json:"phase"`
	Total   int64     `json:"total"`
	Done    int64     `json:"done"`
	Failed  int64     `json:"failed"`
	Active  int64     `json:"active"`
	Started bool      `json:"started"`
}

type Scan struct {
	ID        int64           `json:"id"`
	MissionID int64           `json:"mission_id"`
	NetworkID int64           `json:"network_id"` // network the operator is plugged into
	Kind      ScanKind        `json:"kind"`
	Status    ScanStatus      `json:"status"`
	Options   ScanOptions     `json:"options"`
	Phase     string          `json:"phase"`    // human readable current phase
	Progress  float64         `json:"progress"` // 0..1 over the whole scan
	Phases    []PhaseProgress `json:"phases"`
	Stats     ScanStats       `json:"stats"`
	// Resumable is false once a scan reached a terminal state it cannot be
	// continued from (completed, or failed before any work unit was created).
	Resumable  bool       `json:"resumable"`
	PausedAt   *time.Time `json:"paused_at,omitempty"`
	ETASeconds int64      `json:"eta_seconds,omitempty"`
	Error      string     `json:"error,omitempty"`
	CreatedBy  int64      `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Hosts & services
// ---------------------------------------------------------------------------

// Host is an IP seen alive on a given network. The (MissionID, NetworkID, IP)
// triple is unique; AssetID links it to a long-lived physical/logical machine.
type Host struct {
	ID           int64    `json:"id"`
	MissionID    int64    `json:"mission_id"`
	NetworkID    int64    `json:"network_id"`
	AssetID      int64    `json:"asset_id,omitempty"` // 0 = not correlated yet
	IP           string   `json:"ip"`
	MAC          string   `json:"mac,omitempty"`
	Vendor       string   `json:"vendor,omitempty"` // OUI vendor
	Hostname     string   `json:"hostname,omitempty"`
	Hostnames    []string `json:"hostnames,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	OS           string   `json:"os,omitempty"`
	TTL          int      `json:"ttl,omitempty"`
	DiscoveredBy []string `json:"discovered_by,omitempty"` // arp, icmp-echo, tcp-syn:443 ...
	// Triage is the operator's pass over this address. Skipping it is how a
	// machine that must not be touched is parked: its services, its findings
	// and the segmentation tests aimed at it drop out of the working views
	// without anything being deleted. Owned by the operator, never written by
	// a scan.
	Triage     Triage    `json:"triage"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID int64     `json:"last_scan_id"`
}

type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

type PortState string

const (
	PortOpen         PortState = "open"
	PortClosed       PortState = "closed"
	PortFiltered     PortState = "filtered"
	PortOpenFiltered PortState = "open|filtered"
)

// TriageStatus is where the operator is with a service, a finding, a host or
// an asset. NETY finds what is exposed; going through each one by hand is
// still the operator's job, and this is how that pass is tracked so nothing is
// forgotten and a re-scan does not erase the work.
type TriageStatus string

const (
	TriageTodo       TriageStatus = "todo"        // not looked at yet (the default)
	TriageInProgress TriageStatus = "in_progress" // being tested right now
	TriageDone       TriageStatus = "done"        // tested, nothing worth reporting
	TriageFlagged    TriageStatus = "flagged"     // tested, something to report
	TriageSkipped    TriageStatus = "skipped"     // out of scope or not worth testing
)

// AllTriageStatuses is the canonical order, used by the UI and the exports.
var AllTriageStatuses = []TriageStatus{
	TriageTodo, TriageInProgress, TriageDone, TriageFlagged, TriageSkipped,
}

// ValidTriageStatus reports whether s is a known status.
func ValidTriageStatus(s TriageStatus) bool {
	for _, v := range AllTriageStatuses {
		if v == s {
			return true
		}
	}
	return false
}

// Triage is the operator's own record against a service, a finding, a host or
// an asset: where they are with it and what they found. It is never written by
// a scan.
type Triage struct {
	Status        TriageStatus `json:"status"`
	Note          string       `json:"note,omitempty"`
	UpdatedBy     int64        `json:"updated_by,omitempty"`
	UpdatedByName string       `json:"updated_by_name,omitempty"`
	UpdatedAt     *time.Time   `json:"updated_at,omitempty"`
}

type Service struct {
	ID         int64             `json:"id"`
	MissionID  int64             `json:"mission_id"`
	NetworkID  int64             `json:"network_id"`
	HostID     int64             `json:"host_id"`
	IP         string            `json:"ip"`
	Port       int               `json:"port"`
	Protocol   Protocol          `json:"protocol"`
	State      PortState         `json:"state"`
	Reason     string            `json:"reason,omitempty"` // syn-ack, udp-response ...
	Name       string            `json:"name,omitempty"`   // http, ssh, microsoft-ds ...
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	ExtraInfo  string            `json:"extra_info,omitempty"`
	OSType     string            `json:"os_type,omitempty"`
	CPEs       []string          `json:"cpes,omitempty"`
	Tunnel     string            `json:"tunnel,omitempty"` // "ssl" when wrapped in TLS
	Banner     string            `json:"banner,omitempty"` // printable, truncated raw banner
	TLS        *TLSInfo          `json:"tls,omitempty"`
	HTTP       *HTTPInfo         `json:"http,omitempty"`
	SSH        *SSHInfo          `json:"ssh,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`  // protocol specific facts
	Confidence int               `json:"confidence"`       // 0..100
	Method     string            `json:"method,omitempty"` // probe-match | port-table | fingerprintx ...
	// Triage is the operator's manual pass over this service. Owned by the
	// operator, never written by a scan.
	Triage     Triage    `json:"triage"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID int64     `json:"last_scan_id"`
}

type TLSInfo struct {
	Version     string    `json:"version"`
	CipherSuite string    `json:"cipher_suite"`
	ALPN        string    `json:"alpn,omitempty"`
	SubjectCN   string    `json:"subject_cn"`
	Subject     string    `json:"subject"`
	SANs        []string  `json:"sans,omitempty"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	SelfSigned  bool      `json:"self_signed"`
	Expired     bool      `json:"expired"`
	KeyAlgo     string    `json:"key_algo"`
	KeyBits     int       `json:"key_bits"`
	SigAlgo     string    `json:"sig_algo"`
	SHA256      string    `json:"sha256"` // leaf cert fingerprint, hex
	JARM        string    `json:"jarm,omitempty"`
}

type HTTPInfo struct {
	Scheme        string            `json:"scheme"`
	URL           string            `json:"url"`
	StatusCode    int               `json:"status_code"`
	Title         string            `json:"title,omitempty"`
	Server        string            `json:"server,omitempty"`
	PoweredBy     string            `json:"powered_by,omitempty"`
	Location      string            `json:"location,omitempty"`
	ContentType   string            `json:"content_type,omitempty"`
	ContentLength int64             `json:"content_length"`
	Headers       map[string]string `json:"headers,omitempty"`
	Technologies  []string          `json:"technologies,omitempty"`
	AuthSchemes   []string          `json:"auth_schemes,omitempty"` // Basic, NTLM, Negotiate ...
	FaviconMMH3   string            `json:"favicon_mmh3,omitempty"` // shodan style favicon hash
	BodySHA256    string            `json:"body_sha256,omitempty"`
}

type SSHInfo struct {
	Banner   string       `json:"banner"`
	HostKeys []SSHHostKey `json:"host_keys,omitempty"`
	KexAlgos []string     `json:"kex_algos,omitempty"`
	Ciphers  []string     `json:"ciphers,omitempty"`
	MACs     []string     `json:"macs,omitempty"`
	AuthMeth []string     `json:"auth_methods,omitempty"`
}

type SSHHostKey struct {
	Type   string `json:"type"`
	SHA256 string `json:"sha256"` // OpenSSH style "SHA256:base64"
}

// ---------------------------------------------------------------------------
// Identity & assets: keep track of the same machine across days / IPs / VLANs
// ---------------------------------------------------------------------------

type EvidenceKind string

const (
	EvHostname      EvidenceKind = "hostname"        // short hostname (NetBIOS / NTLM / mDNS / reverse DNS)
	EvFQDN          EvidenceKind = "fqdn"            // DNS computer name
	EvDomain        EvidenceKind = "domain"          // AD / DNS domain
	EvNetBIOSName   EvidenceKind = "netbios-name"    //
	EvNetBIOSDomain EvidenceKind = "netbios-domain"  //
	EvMAC           EvidenceKind = "mac"             // only meaningful on the same L2
	EvSMBGUID       EvidenceKind = "smb-server-guid" // SMB2 NEGOTIATE ServerGuid (very stable)
	EvSSHHostKey    EvidenceKind = "ssh-hostkey"     // SHA256 fingerprint
	EvTLSCert       EvidenceKind = "tls-cert"        // SHA256 of a non-shared leaf cert
	EvOSVersion     EvidenceKind = "os-version"      // e.g. NTLM "10.0.19041"
	EvSNMPSysName   EvidenceKind = "snmp-sysname"    //
	EvSNMPEngineID  EvidenceKind = "snmp-engineid"   // SNMPv3 engine ID (very stable)
	EvReverseDNS    EvidenceKind = "rdns"            //
	EvHTTPFavicon   EvidenceKind = "http-favicon"    // weak
	EvMDNSName      EvidenceKind = "mdns-name"       //
	EvVendor        EvidenceKind = "vendor"          // weak
)

type IdentityEvidence struct {
	Kind       EvidenceKind      `json:"kind"`
	Value      string            `json:"value"`
	Source     string            `json:"source"`     // e.g. "smb-ntlm/445", "rdp-ntlm/3389", "nbns/137"
	Confidence int               `json:"confidence"` // 0..100, how unique / stable this key is
	Attributes map[string]string `json:"attributes,omitempty"`
}

type AssetKind string

const (
	AssetUnknown     AssetKind = "unknown"
	AssetWorkstation AssetKind = "workstation"
	AssetServer      AssetKind = "server"
	AssetDC          AssetKind = "domain-controller"
	AssetNetwork     AssetKind = "network-device"
	AssetPrinter     AssetKind = "printer"
	AssetIoT         AssetKind = "iot"
	AssetPhone       AssetKind = "voip"
	AssetHypervisor  AssetKind = "hypervisor"
	AssetStorage     AssetKind = "storage"
)

// Asset is a machine with a stable identity, independent of its IP.
type Asset struct {
	ID        int64      `json:"id"`
	MissionID int64      `json:"mission_id"`
	Label     string     `json:"label"` // best human name (FQDN > hostname > IP)
	Hostname  string     `json:"hostname,omitempty"`
	Domain    string     `json:"domain,omitempty"`
	OS        string     `json:"os,omitempty"`
	Kind      AssetKind  `json:"kind"`
	Keys      []AssetKey `json:"keys"`
	IPs       []AssetIP  `json:"ips"`
	Tags      []string   `json:"tags,omitempty"`
	Notes     string     `json:"notes,omitempty"`
	// Triage is the operator's pass over the machine itself, not over one of
	// its addresses: setting it applies the same status to every host attached
	// to this asset, and a host the correlator attaches later to a skipped
	// asset is skipped too. Owned by the operator, never written by a scan.
	Triage    Triage    `json:"triage"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type AssetKey struct {
	Kind       EvidenceKind `json:"kind"`
	Value      string       `json:"value"`
	Source     string       `json:"source"`
	Confidence int          `json:"confidence"`
	FirstSeen  time.Time    `json:"first_seen"`
	LastSeen   time.Time    `json:"last_seen"`
}

type AssetIP struct {
	IP        string    `json:"ip"`
	NetworkID int64     `json:"network_id"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// HostObservation is everything learned about one host during one scan,
// fed to the correlator to decide which asset it belongs to.
type HostObservation struct {
	MissionID int64              `json:"mission_id"`
	NetworkID int64              `json:"network_id"`
	SameL2    bool               `json:"same_l2"` // MAC is the host's own MAC, not the gateway's
	Host      Host               `json:"host"`
	Services  []Service          `json:"services"`
	Evidence  []IdentityEvidence `json:"evidence"`
	SeenAt    time.Time          `json:"seen_at"`
}

// AssetDecision is the correlator output.
type AssetDecision struct {
	Matched bool     `json:"matched"` // true = Asset is an existing asset (Asset.ID != 0)
	Score   int      `json:"score"`   // 0..100
	Reasons []string `json:"reasons"` // human readable, e.g. "smb-server-guid match"
	Asset   Asset    `json:"asset"`   // merged/updated asset (new one if !Matched, ID=0)
	// Conflicts lists other existing asset IDs that also partially matched
	// (e.g. same hostname, different SSH key) so the UI can flag them.
	Conflicts []int64 `json:"conflicts,omitempty"`
}

// ---------------------------------------------------------------------------
// Findings (light checks)
// ---------------------------------------------------------------------------

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

type Finding struct {
	ID          int64    `json:"id"`
	MissionID   int64    `json:"mission_id"`
	NetworkID   int64    `json:"network_id"`
	HostID      int64    `json:"host_id"`
	ServiceID   int64    `json:"service_id,omitempty"`
	IP          string   `json:"ip"`
	Port        int      `json:"port,omitempty"`
	Protocol    Protocol `json:"protocol,omitempty"`
	CheckID     string   `json:"check_id"` // stable id, e.g. "smb-signing-not-required"
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references,omitempty"`
	// Triage is the operator's manual pass over this finding: a check firing
	// is not the same as a problem worth reporting, and that verdict is made
	// by hand. Owned by the operator, never written by a scan.
	Triage     Triage    `json:"triage"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastScanID int64     `json:"last_scan_id"`
}

// ---------------------------------------------------------------------------
// Segmentation
// ---------------------------------------------------------------------------

// Techniques used to try reaching a service from another network.
const (
	TechDirect       = "direct"        // plain connection with the current config
	TechSrcPort53    = "src-port-53"   // TCP/UDP with source port 53
	TechSrcPort88    = "src-port-88"   // source port 88 (kerberos)
	TechSrcPort123   = "src-port-123"  // source port 123 (ntp)
	TechSrcPort20    = "src-port-20"   // source port 20 (ftp-data)
	TechSrcPort67    = "src-port-67"   // source port 67 (dhcp)
	TechSrcPort500   = "src-port-500"  // source port 500 (ike)
	TechICMP         = "icmp"          // ICMP echo reachability of the host
	TechIPv6         = "ipv6"          // IPv6 (link-local / SLAAC / known v6 address)
	TechGatewayRoute = "gateway-route" // explicit route via the local gateway when no default route
	TechAltGateway   = "alt-gateway"   // route via another local router / multi-homed host
	TechFragment     = "ip-fragment"   // fragmented SYN
	TechDot1QSubif   = "dot1q-subif"   // 802.1Q sub-interface on a trunk port (L2 active)
	TechDTPTrunk     = "dtp-trunk"     // negotiate trunk via DTP then dot1q-subif (L2 active)
	TechDoubleTag    = "double-tag"    // 802.1Q double tagging, one-way (L2 active)
)

type ReachStatus string

const (
	ReachOpen        ReachStatus = "reachable"   // service answered (SYN-ACK / app reply)
	ReachClosed      ReachStatus = "closed"      // host answered RST: routed but port closed
	ReachFiltered    ReachStatus = "filtered"    // no answer / ICMP admin prohibited
	ReachUnreachable ReachStatus = "unreachable" // no route / ICMP net-unreachable
	ReachSent        ReachStatus = "sent"        // one-way technique, delivery cannot be confirmed
	ReachError       ReachStatus = "error"
)

type ReachResult struct {
	ID              int64       `json:"id"`
	MissionID       int64       `json:"mission_id"`
	ScanID          int64       `json:"scan_id"`
	SourceNetworkID int64       `json:"source_network_id"` // where the operator is plugged
	TargetNetworkID int64       `json:"target_network_id"` // where the service was discovered
	TargetHostID    int64       `json:"target_host_id"`
	TargetServiceID int64       `json:"target_service_id,omitempty"` // 0 for host-level (icmp)
	IP              string      `json:"ip"`
	Port            int         `json:"port,omitempty"`
	Protocol        Protocol    `json:"protocol,omitempty"`
	Technique       string      `json:"technique"`
	VLANID          int         `json:"vlan_id,omitempty"` // for dot1q/double-tag techniques
	Status          ReachStatus `json:"status"`
	Detail          string      `json:"detail,omitempty"`
	RTTMs           float64     `json:"rtt_ms,omitempty"`
	TestedAt        time.Time   `json:"tested_at"`
}

// MatrixCell aggregates reach results: source network -> target network.
type MatrixCell struct {
	SourceNetworkID int64          `json:"source_network_id"`
	TargetNetworkID int64          `json:"target_network_id"`
	Tested          int            `json:"tested"`
	Reachable       int            `json:"reachable"`
	Closed          int            `json:"closed"`
	Filtered        int            `json:"filtered"`
	ByTechnique     map[string]int `json:"by_technique"` // technique -> reachable count
	LastTestedAt    *time.Time     `json:"last_tested_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Live events (websocket) and export bundle
// ---------------------------------------------------------------------------

type EventType string

const (
	EvtScanStatus   EventType = "scan.status"
	EvtScanPhase    EventType = "scan.phase"
	EvtScanProgress EventType = "scan.progress"
	EvtScanLog      EventType = "scan.log"
	EvtHost         EventType = "host"
	EvtService      EventType = "service"
	EvtFinding      EventType = "finding"
	EvtReach        EventType = "reach"
	EvtAsset        EventType = "asset"
	EvtNetwork      EventType = "network"
)

type Event struct {
	Type      EventType `json:"type"`
	MissionID int64     `json:"mission_id"`
	ScanID    int64     `json:"scan_id,omitempty"`
	Time      time.Time `json:"time"`
	Data      any       `json:"data"`
}

type LogLine struct {
	Level   string `json:"level"` // debug | info | warn | error
	Message string `json:"message"`
}

// MissionData is the complete dataset of a mission, used by exports.
type MissionData struct {
	Mission  Mission       `json:"mission"`
	Networks []Network     `json:"networks"`
	Scans    []Scan        `json:"scans"`
	Hosts    []Host        `json:"hosts"`
	Services []Service     `json:"services"`
	Assets   []Asset       `json:"assets"`
	Findings []Finding     `json:"findings"`
	Reach    []ReachResult `json:"reach"`
	Matrix   []MatrixCell  `json:"matrix"`
	// ExportedAt / By are set by the exporter caller.
	ExportedAt time.Time `json:"exported_at"`
	ExportedBy string    `json:"exported_by"`
}
