/**
 * Wire types for the NETY REST API and WebSocket event stream.
 *
 * Hand-written mirror of internal/model/model.go (and the few handler-level
 * shapes documented in docs/API.md). The Go JSON tags are the contract: field
 * names here must match them exactly. Fields tagged `omitempty` in Go are
 * optional here.
 */

// ---------------------------------------------------------------------------
// Users & missions
// ---------------------------------------------------------------------------

export type Role = 'admin' | 'operator' | 'viewer'

export const ROLES: Role[] = ['admin', 'operator', 'viewer']

export interface User {
  id: number
  username: string
  display_name: string
  role: Role
  disabled: boolean
  must_change_password: boolean
  created_at: string
  last_login_at?: string
}

export interface Mission {
  id: number
  name: string
  client: string
  description: string
  scope_cidrs: string[] | null
  exclude_cidrs: string[] | null
  archived: boolean
  created_by: number
  created_at: string
  updated_at: string
}

export interface MissionInput {
  name: string
  client?: string
  description?: string
  scope_cidrs?: string[]
  exclude_cidrs?: string[]
  archived?: boolean
}

/**
 * GET /api/missions/{id}/summary — "counts per network, severity totals,
 * matrix size". The handler is still settling, so every field is optional and
 * the UI degrades gracefully when one is absent.
 */
export interface MissionSummary {
  mission_id?: number
  networks?: NetworkSummary[]
  hosts?: number
  services?: number
  findings?: number
  assets?: number
  scans?: number
  running_scans?: number
  severity?: Partial<Record<Severity, number>>
  matrix?: { networks?: number; cells?: number; tested?: number; reachable?: number }
  last_scan_at?: string
}

export interface NetworkSummary {
  network_id: number
  name?: string
  hosts?: number
  services?: number
  findings?: number
  assets?: number
  scans?: number
  last_scan_at?: string
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

export interface L2Neighbor {
  protocol: string // cdp | lldp
  device_id: string
  port_id: string
  platform?: string
  software?: string
  mgmt_address?: string
  native_vlan?: number
  voice_vlan?: number
  capabilities?: string[]
}

export interface L2Info {
  neighbors: L2Neighbor[] | null
  dtp_seen: boolean
  dtp_mode?: string
  native_vlan?: number
  voice_vlan?: number
  observed_vlans?: number[]
  stp_root_bridge?: string
  captured_at?: string
}

export interface Network {
  id: number
  mission_id: number
  name: string
  vlan_id: number
  description: string
  interface: string
  local_ip: string
  local_mac: string
  prefixes: string[] | null
  gateway: string
  dns_servers: string[] | null
  domain_search: string[] | null
  dhcp_server: string
  l2: L2Info
  created_at: string
  updated_at: string
}

export interface NetworkInput {
  name: string
  vlan_id?: number
  description?: string
  interface?: string
  local_ip?: string
  prefixes?: string[]
  gateway?: string
  dns_servers?: string[]
}

/** engine.InterfaceInfo — GET /api/interfaces */
export interface InterfaceInfo {
  name: string
  mac: string
  up: boolean
  addresses: string[] | null // netip.Prefix marshals to "10.0.0.5/24"
  mtu: number
  is_vlan: boolean
  vlan_id?: number
  parent?: string
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export type ScanKind = 'discovery' | 'segmentation' | 'l2probe'

export const SCAN_KINDS: ScanKind[] = ['discovery', 'segmentation', 'l2probe']

export type ScanStatus =
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'

export type ScanProfile = 'quick' | 'standard' | 'full' | 'custom'

export type ScanMode = 'auto' | 'syn' | 'connect'

export interface ScanOptions {
  profile: string
  targets: string[] | null
  excludes: string[] | null
  auto_targets: boolean
  tcp_ports: string
  udp_ports: string
  rate: number
  retries: number
  timeout_ms: number
  concurrency: number
  scan_mode: string
  host_discovery: boolean
  service_detection: boolean
  identity_collection: boolean
  checks: boolean
  // Segmentation only.
  source_network_ids?: number[]
  techniques?: string[]
  allow_l2_active: boolean
  vlan_range?: string
}

export interface ScanStats {
  targets_total: number
  hosts_up: number
  ports_open: number
  services: number
  findings: number
  probes_sent: number
  reach_tested: number
  reach_ok: number
  new_assets: number
  matched_assets: number
}

export type WorkPhase =
  | 'l2'
  | 'discovery'
  | 'ports-tcp'
  | 'ports-udp'
  | 'fingerprint'
  | 'identity'
  | 'checks'
  | 'segmentation'

/** model.AllPhases — canonical order. */
export const ALL_PHASES: WorkPhase[] = [
  'l2',
  'discovery',
  'ports-tcp',
  'ports-udp',
  'fingerprint',
  'identity',
  'checks',
  'segmentation',
]

export const PHASE_LABELS: Record<WorkPhase, string> = {
  l2: 'L2 recon',
  discovery: 'Host discovery',
  'ports-tcp': 'TCP port scan',
  'ports-udp': 'UDP port scan',
  fingerprint: 'Service fingerprinting',
  identity: 'Identity & assets',
  checks: 'Checks',
  segmentation: 'Segmentation',
}

export interface PhaseProgress {
  phase: WorkPhase
  total: number
  done: number
  failed: number
  active: number
  started: boolean
}

export interface Scan {
  id: number
  mission_id: number
  network_id: number
  kind: ScanKind
  status: ScanStatus
  options: ScanOptions
  phase: string
  progress: number
  phases: PhaseProgress[] | null
  stats: ScanStats
  resumable: boolean
  paused_at?: string
  eta_seconds?: number
  error?: string
  created_by: number
  created_at: string
  started_at?: string
  finished_at?: string
}

export interface ScanInput {
  network_id: number
  kind: ScanKind
  options: ScanOptions
}

/** GET /api/scan-profiles */
export interface ScanProfileInfo {
  id: string
  title?: string
  description?: string
  options?: Partial<ScanOptions>
}

/** engine.TechniqueInfo — GET /api/techniques */
export interface TechniqueInfo {
  id: string
  title: string
  description: string
  l2_active: boolean
  one_way: boolean
  default: boolean
}

/** engine.CheckInfo — GET /api/checks */
export interface CheckInfo {
  id: string
  title: string
  severity: Severity
  services: string[] | null
  intrusive: boolean
  description: string
}

/** GET /api/scans/{id}/logs — a log line with its cursor id. */
export interface ScanLogLine {
  id: number
  scan_id?: number
  time: string
  level: string // debug | info | warn | error
  message: string
  phase?: string
}

// ---------------------------------------------------------------------------
// Hosts & services
// ---------------------------------------------------------------------------

export interface Host {
  id: number
  mission_id: number
  network_id: number
  asset_id?: number
  ip: string
  mac?: string
  vendor?: string
  hostname?: string
  hostnames?: string[]
  domain?: string
  os?: string
  ttl?: number
  discovered_by?: string[]
  first_seen: string
  last_seen: string
  last_scan_id: number
}

export type Protocol = 'tcp' | 'udp'

export type PortState = 'open' | 'closed' | 'filtered' | 'open|filtered'

export interface TLSInfo {
  version: string
  cipher_suite: string
  alpn?: string
  subject_cn: string
  subject: string
  sans?: string[]
  issuer: string
  serial: string
  not_before: string
  not_after: string
  self_signed: boolean
  expired: boolean
  key_algo: string
  key_bits: number
  sig_algo: string
  sha256: string
  jarm?: string
}

export interface HTTPInfo {
  scheme: string
  url: string
  status_code: number
  title?: string
  server?: string
  powered_by?: string
  location?: string
  content_type?: string
  content_length: number
  headers?: Record<string, string>
  technologies?: string[]
  auth_schemes?: string[]
  favicon_mmh3?: string
  body_sha256?: string
}

export interface SSHHostKey {
  type: string
  sha256: string
}

export interface SSHInfo {
  banner: string
  host_keys?: SSHHostKey[]
  kex_algos?: string[]
  ciphers?: string[]
  macs?: string[]
  auth_methods?: string[]
}

export interface Service {
  id: number
  mission_id: number
  network_id: number
  host_id: number
  ip: string
  port: number
  protocol: Protocol
  state: PortState
  reason?: string
  name?: string
  product?: string
  version?: string
  extra_info?: string
  os_type?: string
  cpes?: string[]
  tunnel?: string
  banner?: string
  tls?: TLSInfo
  http?: HTTPInfo
  ssh?: SSHInfo
  extra?: Record<string, string>
  confidence: number
  method?: string
  first_seen: string
  last_seen: string
  last_scan_id: number
}

/** GET /api/hosts/{id} — host plus its services. */
export interface HostDetail {
  host: Host
  services: Service[] | null
}

/** Paginated service listing. The handler may also return a bare array. */
export interface ServicePage {
  items: Service[] | null
  total?: number
  limit?: number
  offset?: number
}

// ---------------------------------------------------------------------------
// Identity & assets
// ---------------------------------------------------------------------------

export type EvidenceKind =
  | 'hostname'
  | 'fqdn'
  | 'domain'
  | 'netbios-name'
  | 'netbios-domain'
  | 'mac'
  | 'smb-server-guid'
  | 'ssh-hostkey'
  | 'tls-cert'
  | 'os-version'
  | 'snmp-sysname'
  | 'snmp-engineid'
  | 'rdns'
  | 'http-favicon'
  | 'mdns-name'
  | 'vendor'

export type AssetKind =
  | 'unknown'
  | 'workstation'
  | 'server'
  | 'domain-controller'
  | 'network-device'
  | 'printer'
  | 'iot'
  | 'voip'
  | 'hypervisor'
  | 'storage'

export const ASSET_KINDS: AssetKind[] = [
  'unknown',
  'workstation',
  'server',
  'domain-controller',
  'network-device',
  'printer',
  'iot',
  'voip',
  'hypervisor',
  'storage',
]

export interface AssetKey {
  kind: EvidenceKind
  value: string
  source: string
  confidence: number
  first_seen: string
  last_seen: string
}

export interface AssetIP {
  ip: string
  network_id: number
  first_seen: string
  last_seen: string
}

export interface Asset {
  id: number
  mission_id: number
  label: string
  hostname?: string
  domain?: string
  os?: string
  kind: AssetKind
  keys: AssetKey[] | null
  ips: AssetIP[] | null
  tags?: string[]
  notes?: string
  first_seen: string
  last_seen: string
}

export interface AssetPatch {
  label?: string
  notes?: string
  tags?: string[]
  kind?: AssetKind
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

/** Most severe first — the order findings are presented in. */
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

export interface Finding {
  id: number
  mission_id: number
  network_id: number
  host_id: number
  service_id?: number
  ip: string
  port?: number
  protocol?: Protocol
  check_id: string
  title: string
  severity: Severity
  description: string
  evidence: string
  remediation: string
  references?: string[]
  first_seen: string
  last_seen: string
  last_scan_id: number
}

// ---------------------------------------------------------------------------
// Segmentation
// ---------------------------------------------------------------------------

/** model.Tech* constants. */
export const TECHNIQUES = {
  direct: 'direct',
  srcPort53: 'src-port-53',
  srcPort88: 'src-port-88',
  srcPort123: 'src-port-123',
  srcPort20: 'src-port-20',
  srcPort67: 'src-port-67',
  srcPort500: 'src-port-500',
  icmp: 'icmp',
  ipv6: 'ipv6',
  gatewayRoute: 'gateway-route',
  altGateway: 'alt-gateway',
  fragment: 'ip-fragment',
  dot1qSubif: 'dot1q-subif',
  dtpTrunk: 'dtp-trunk',
  doubleTag: 'double-tag',
} as const

/** Techniques that are not plain routing — a hit through one of these is a
 * segmentation bypass, not normal connectivity. */
export const BYPASS_TECHNIQUES = new Set<string>([
  'src-port-53',
  'src-port-88',
  'src-port-123',
  'src-port-20',
  'src-port-67',
  'src-port-500',
  'ipv6',
  'gateway-route',
  'alt-gateway',
  'ip-fragment',
  'dot1q-subif',
  'dtp-trunk',
  'double-tag',
])

export type ReachStatus =
  | 'reachable'
  | 'closed'
  | 'filtered'
  | 'unreachable'
  | 'sent'
  | 'error'

export interface ReachResult {
  id: number
  mission_id: number
  scan_id: number
  source_network_id: number
  target_network_id: number
  target_host_id: number
  target_service_id?: number
  ip: string
  port?: number
  protocol?: Protocol
  technique: string
  vlan_id?: number
  status: ReachStatus
  detail?: string
  rtt_ms?: number
  tested_at: string
}

export interface MatrixCell {
  source_network_id: number
  target_network_id: number
  tested: number
  reachable: number
  closed: number
  filtered: number
  by_technique: Record<string, number> | null
  last_tested_at?: string
}

/** GET /api/missions/{id}/matrix */
export interface Matrix {
  networks: Network[] | null
  cells: MatrixCell[] | null
  techniques: TechniqueInfo[] | null
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

/** engine.ExportFormat — GET /api/export-formats */
export interface ExportFormat {
  id: string
  title: string
  extension: string
  content_type: string
}

// ---------------------------------------------------------------------------
// Status & audit
// ---------------------------------------------------------------------------

export interface ServerStatus {
  version?: string
  commit?: string
  build_date?: string
  uptime_seconds?: number
  started_at?: string
  privileged?: boolean
  raw_sockets?: boolean
  running_scans?: number
  counters?: Record<string, number>
}

/** Audit trail entry (admin view). Field names are permissive: the handler is
 * owned by another package and only the common subset is relied upon. */
export interface AuditEntry {
  id: number
  time?: string
  created_at?: string
  user_id?: number
  username?: string
  action: string
  target?: string
  mission_id?: number
  detail?: string
  ip?: string
  status?: string
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface SessionInfo {
  user: User
  csrf_token: string
}

export interface ApiErrorBody {
  error: string
  code?: string
}

// ---------------------------------------------------------------------------
// Live events (WebSocket)
// ---------------------------------------------------------------------------

export type EventType =
  | 'scan.status'
  | 'scan.phase'
  | 'scan.progress'
  | 'scan.log'
  | 'host'
  | 'service'
  | 'finding'
  | 'reach'
  | 'asset'
  | 'network'

export interface LogLine {
  level: string
  message: string
}

export interface EventEnvelope<T = unknown> {
  type: EventType
  mission_id: number
  scan_id?: number
  time: string
  data: T
}

/** Discriminated union of everything the bus can push. */
export type LiveEvent =
  | (EventEnvelope<Scan> & { type: 'scan.status' | 'scan.phase' | 'scan.progress' })
  | (EventEnvelope<LogLine> & { type: 'scan.log' })
  | (EventEnvelope<Host> & { type: 'host' })
  | (EventEnvelope<Service> & { type: 'service' })
  | (EventEnvelope<Finding> & { type: 'finding' })
  | (EventEnvelope<ReachResult> & { type: 'reach' })
  | (EventEnvelope<Asset> & { type: 'asset' })
  | (EventEnvelope<Network> & { type: 'network' })
