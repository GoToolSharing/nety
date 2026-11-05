import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  useCreateScan,
  useNetworks,
  useScanProfiles,
  useTechniques,
} from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardBody, CardHeader, PageHeader } from '@/components/ui/Card'
import { Button, LinkButton } from '@/components/ui/Button'
import { Checkbox, SelectField, TextAreaField, TextField, Toggle } from '@/components/ui/Field'
import { EmptyState, InlineAlert, Skeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import { humanizeId } from '@/lib/format'
import {
  AlertIcon,
  FindingIcon,
  MatrixIcon,
  NetworkIcon,
  ScanIcon,
  TrunkIcon,
} from '@/components/icons'
import type { ScanKind, ScanOptions, TechniqueInfo } from '@/types/api'

// ---------------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------------

const PROFILE_DEFAULTS: Record<string, Partial<ScanOptions>> = {
  quick: {
    tcp_ports: 'top100',
    udp_ports: '',
    rate: 5000,
    retries: 1,
    timeout_ms: 2000,
    concurrency: 64,
    scan_mode: 'auto',
    host_discovery: true,
    service_detection: true,
    identity_collection: false,
    checks: false,
  },
  standard: {
    tcp_ports: 'top1000',
    udp_ports: 'top20',
    rate: 5000,
    retries: 1,
    timeout_ms: 3000,
    concurrency: 64,
    scan_mode: 'auto',
    host_discovery: true,
    service_detection: true,
    identity_collection: true,
    checks: true,
  },
  full: {
    tcp_ports: 'all',
    udp_ports: 'top100',
    rate: 10000,
    retries: 2,
    timeout_ms: 4000,
    concurrency: 128,
    scan_mode: 'auto',
    host_discovery: true,
    service_detection: true,
    identity_collection: true,
    checks: true,
  },
}

const PROFILE_BLURB: Record<string, string> = {
  quick: 'Top 100 TCP ports, no UDP, no checks. A few minutes on a /24.',
  standard: 'Top 1000 TCP + top 20 UDP, fingerprinting, identity and light checks.',
  full: 'All 65535 TCP ports, wide UDP, everything enabled. Long, loud, thorough.',
  custom: 'Every knob exposed below.',
}

const KINDS: { id: ScanKind; title: string; blurb: string; icon: React.ReactNode }[] = [
  {
    id: 'discovery',
    title: 'Discovery',
    blurb:
      'Map the network you are plugged into: hosts, ports, services, identities, light checks.',
    icon: <ScanIcon width={18} height={18} />,
  },
  {
    id: 'segmentation',
    title: 'Segmentation',
    blurb:
      'From here, replay the services discovered on the other networks and fill the reachability matrix.',
    icon: <MatrixIcon width={18} height={18} />,
  },
  {
    id: 'l2probe',
    title: 'L2 probe',
    blurb:
      'Listen for CDP/LLDP/DTP/STP and 802.1Q tags on this port. Passive by default, silent.',
    icon: <TrunkIcon width={18} height={18} />,
  },
  {
    id: 'checks',
    title: 'Checks only',
    blurb:
      'Re-run detection and the checks over what is already inventoried here. No discovery, no port scan.',
    icon: <FindingIcon width={18} height={18} />,
  },
]

function techniqueGroup(t: TechniqueInfo): string {
  if (t.l2_active) return 'Layer-2 active'
  if (t.id.startsWith('src-port-')) return 'Source-port tricks'
  if (t.id === 'gateway-route' || t.id === 'alt-gateway') return 'Routing'
  return 'Protocol & baseline'
}

const GROUP_ORDER = ['Protocol & baseline', 'Source-port tricks', 'Routing', 'Layer-2 active']

function splitList(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function defaultOptions(profile: string): ScanOptions {
  const base = PROFILE_DEFAULTS[profile] ?? PROFILE_DEFAULTS.standard
  return {
    profile,
    targets: [],
    excludes: [],
    auto_targets: true,
    tcp_ports: 'top1000',
    udp_ports: 'top20',
    rate: 5000,
    retries: 1,
    timeout_ms: 3000,
    concurrency: 64,
    scan_mode: 'auto',
    host_discovery: true,
    service_detection: true,
    identity_collection: true,
    checks: true,
    allow_default_creds: false,
    source_network_ids: [],
    techniques: [],
    allow_l2_active: false,
    vlan_range: '',
    ...base,
  }
}

// ---------------------------------------------------------------------------

export default function ScanLauncherPage() {
  const missionId = useMissionId()
  const navigate = useNavigate()
  const toast = useToast()
  const { canWrite } = useAuth()
  const [searchParams] = useSearchParams()

  const networks = useNetworks(missionId)
  const profiles = useScanProfiles()
  const techniques = useTechniques()
  const createScan = useCreateScan(missionId)

  const [kind, setKind] = useState<ScanKind>('discovery')
  const [networkId, setNetworkId] = useState<number>(0)
  const [profile, setProfile] = useState<string>('standard')
  const [opts, setOpts] = useState<ScanOptions>(() => defaultOptions('standard'))
  const [targetsText, setTargetsText] = useState('')
  const [excludesText, setExcludesText] = useState('')
  const [vlanRange, setVlanRange] = useState('')
  const [error, setError] = useState<string | null>(null)

  const nets = networks.data ?? []

  // Preselect the network from ?network=, else the first one.
  useEffect(() => {
    if (networkId || nets.length === 0) return
    const fromQuery = Number(searchParams.get('network'))
    const match = nets.find((n) => n.id === fromQuery)
    setNetworkId(match?.id ?? nets[0].id)
  }, [nets, networkId, searchParams])

  useEffect(() => {
    const kindFromQuery = searchParams.get('kind')
    if (
      kindFromQuery === 'segmentation' ||
      kindFromQuery === 'l2probe' ||
      kindFromQuery === 'checks'
    ) {
      setKind(kindFromQuery)
    }
  }, [searchParams])

  const profileIds = useMemo(() => {
    const fromApi = (profiles.data ?? []).map((p) => p.id)
    const ids = fromApi.length > 0 ? fromApi : ['quick', 'standard', 'full']
    return ids.includes('custom') ? ids : [...ids, 'custom']
  }, [profiles.data])

  const applyProfile = (id: string) => {
    setProfile(id)
    if (id === 'custom') {
      setOpts((o) => ({ ...o, profile: 'custom' }))
      return
    }
    const fromApi = (profiles.data ?? []).find((p) => p.id === id)?.options
    setOpts((o) => ({ ...o, ...defaultOptions(id), ...(fromApi ?? {}), profile: id }))
  }

  const custom = profile === 'custom'
  const set = <K extends keyof ScanOptions>(key: K, value: ScanOptions[K]) =>
    setOpts((o) => ({ ...o, [key]: value }))

  const selectedNetwork = nets.find((n) => n.id === networkId)
  const otherNetworks = nets.filter((n) => n.id !== networkId)

  const groupedTechniques = useMemo(() => {
    const groups = new Map<string, TechniqueInfo[]>()
    for (const t of techniques.data ?? []) {
      const g = techniqueGroup(t)
      const arr = groups.get(g) ?? []
      arr.push(t)
      groups.set(g, arr)
    }
    return GROUP_ORDER.filter((g) => groups.has(g)).map((g) => [g, groups.get(g)!] as const)
  }, [techniques.data])

  const selectedTechniques = opts.techniques ?? []
  const toggleTechnique = (id: string, on: boolean) =>
    set(
      'techniques',
      on ? [...new Set([...selectedTechniques, id])] : selectedTechniques.filter((t) => t !== id),
    )

  const sourceIds = opts.source_network_ids ?? []
  const toggleSource = (id: number, on: boolean) =>
    set(
      'source_network_ids',
      on ? [...new Set([...sourceIds, id])] : sourceIds.filter((x) => x !== id),
    )

  const l2Selected = (techniques.data ?? []).filter(
    (t) => t.l2_active && selectedTechniques.includes(t.id),
  )

  const submit = async (startNow: boolean) => {
    setError(null)
    if (!networkId) {
      setError('Choose the network you are plugged into.')
      return
    }
    const targets = splitList(targetsText)
    const payloadOptions: ScanOptions = {
      ...opts,
      profile,
      targets,
      excludes: splitList(excludesText),
      vlan_range: vlanRange.trim(),
      source_network_ids: kind === 'segmentation' ? sourceIds : [],
      techniques: kind === 'segmentation' ? selectedTechniques : [],
      allow_l2_active: kind === 'segmentation' ? opts.allow_l2_active : false,
    }
    if (
      kind === 'discovery' &&
      !payloadOptions.auto_targets &&
      targets.length === 0
    ) {
      setError(
        'With auto-targets off you must list at least one target CIDR or address.',
      )
      return
    }

    try {
      // The API creates and starts in one request, so a launch cannot leave
      // a scan created-but-not-running.
      const scan = await createScan.mutateAsync({
        network_id: networkId,
        kind,
        options: payloadOptions,
        start: startNow,
      })
      if (startNow && scan.error) {
        toast.error('The scan was created but could not be started', scan.error)
      } else {
        toast.success(startNow ? 'Scan launched' : 'Scan created')
      }
      navigate(`../scans/${scan.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the scan.')
    }
  }

  if (!canWrite) {
    return (
      <PageContainer>
        <EmptyState
          title="Read-only account"
          description="Your role does not allow launching scans on this mission."
          action={
            <LinkButton to="../scans" variant="secondary">
              Back to the scan list
            </LinkButton>
          }
        />
      </PageContainer>
    )
  }

  if (networks.isLoading) {
    return (
      <PageContainer>
        <Skeleton className="h-8 w-48" />
        <div className="mt-6 space-y-4">
          <Skeleton className="h-32" />
          <Skeleton className="h-64" />
        </div>
      </PageContainer>
    )
  }

  if (nets.length === 0) {
    return (
      <PageContainer>
        <Card>
          <EmptyState
            icon={<NetworkIcon width={20} height={20} />}
            title="Create a network for the VLAN you are plugged into"
            description="A scan always runs from a network: it tells NETY which interface to use, which prefixes are local and what the switch port looks like."
            action={
              <LinkButton to="../networks" variant="primary">
                Create a network
              </LinkButton>
            }
          />
        </Card>
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title="New scan"
        description="Results stream in from the first second - you never wait for the end of a scan to see what is on the wire."
        actions={
          <LinkButton to="../scans" variant="ghost">
            Cancel
          </LinkButton>
        }
      />

      <div className="mt-5 space-y-4 pb-24">
        {error && <InlineAlert tone="crit">{error}</InlineAlert>}

        {/* ---------------- kind ---------------- */}
        <Card>
          <CardHeader title="What do you want to run?" />
          <CardBody className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {KINDS.map((k) => (
              <button
                key={k.id}
                type="button"
                aria-pressed={kind === k.id}
                onClick={() => setKind(k.id)}
                className={cn(
                  'rounded-lg border p-3.5 text-left transition-colors',
                  kind === k.id
                    ? 'border-accent bg-accent/10'
                    : 'border-border bg-elevated hover:border-border-strong',
                )}
              >
                <span
                  className={cn(
                    'inline-flex items-center gap-2 text-sm font-semibold',
                    kind === k.id ? 'text-fg' : 'text-muted',
                  )}
                >
                  <span className={kind === k.id ? 'text-accent' : 'text-faint'}>{k.icon}</span>
                  {k.title}
                </span>
                <p className="mt-1.5 text-xs text-muted">{k.blurb}</p>
              </button>
            ))}
          </CardBody>
        </Card>

        {/* ---------------- network ---------------- */}
        <Card>
          <CardHeader
            title="Where are you plugged in?"
            description="The network whose interface NETY will send from."
          />
          <CardBody className="grid gap-4 sm:grid-cols-2">
            <SelectField
              label="Source network"
              required
              value={networkId || ''}
              onChange={(e) => setNetworkId(Number(e.target.value))}
            >
              {nets.map((n) => (
                <option key={n.id} value={n.id}>
                  {n.name}
                  {n.vlan_id ? ` (VLAN ${n.vlan_id})` : ''}
                  {n.interface ? ` - ${n.interface}` : ''}
                </option>
              ))}
            </SelectField>
            {selectedNetwork && (
              <div className="rounded-md border border-border bg-elevated px-3 py-2 text-xs">
                <div className="text-muted">
                  Local{' '}
                  <span className="font-mono text-fg">{selectedNetwork.local_ip || '-'}</span> ·
                  gateway{' '}
                  <span className="font-mono text-fg">{selectedNetwork.gateway || '-'}</span>
                </div>
                <div className="mt-1 text-muted">
                  Prefixes{' '}
                  <span className="font-mono text-fg">
                    {(selectedNetwork.prefixes ?? []).join(', ') || '-'}
                  </span>
                </div>
                {selectedNetwork.l2?.dtp_seen && (
                  <div className="mt-1.5 flex items-center gap-1.5 text-crit">
                    <TrunkIcon width={12} height={12} />
                    This port negotiates trunking
                  </div>
                )}
              </div>
            )}
          </CardBody>
        </Card>

        {/* ---------------- profile ---------------- */}
        {kind !== 'l2probe' && kind !== 'checks' && (
          <Card>
            <CardHeader
              title="Profile"
              description="A starting point for the scan parameters. Pick custom to control everything."
            />
            <CardBody className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {profileIds.map((id) => {
                const info = (profiles.data ?? []).find((p) => p.id === id)
                return (
                  <button
                    key={id}
                    type="button"
                    aria-pressed={profile === id}
                    onClick={() => applyProfile(id)}
                    className={cn(
                      'rounded-lg border p-3 text-left transition-colors',
                      profile === id
                        ? 'border-accent bg-accent/10'
                        : 'border-border bg-elevated hover:border-border-strong',
                    )}
                  >
                    {/* The server already provides a human title such as
                        "Low and slow"; capitalising every word mangles it. The
                        fallback is the bare id, so only that needs a capital. */}
                    <span className={cn('text-sm font-semibold', !info?.title && 'capitalize')}>
                      {info?.title ?? id}
                    </span>
                    <p className="mt-1 text-xs text-muted">
                      {info?.description ?? PROFILE_BLURB[id] ?? ''}
                    </p>
                  </button>
                )
              })}
            </CardBody>
          </Card>
        )}

        {/* ---------------- targets & options ---------------- */}
        {kind !== 'l2probe' && kind !== 'checks' && (
          <Card>
            <CardHeader
              title="Targets and parameters"
              description={
                custom
                  ? 'Every option of the scan engine.'
                  : 'Derived from the profile. Switch to custom to edit them.'
              }
            />
            <CardBody className="space-y-5">
              <div className="grid gap-4 lg:grid-cols-2">
                <TextAreaField
                  label="Targets"
                  rows={3}
                  spellCheck={false}
                  className="font-mono text-[12.5px]"
                  placeholder="10.20.0.0/24 10.20.5.17"
                  hint="Space- or comma-separated CIDRs and addresses. Leave empty to rely on auto-targets."
                  value={targetsText}
                  onChange={(e) => setTargetsText(e.target.value)}
                />
                <TextAreaField
                  label="Exclusions"
                  rows={3}
                  spellCheck={false}
                  className="font-mono text-[12.5px]"
                  placeholder="10.20.0.1 10.20.0.250/32"
                  hint="Never probed. The mission-level exclusions always apply on top of these."
                  value={excludesText}
                  onChange={(e) => setExcludesText(e.target.value)}
                />
              </div>

              <Checkbox
                label="Auto-targets"
                hint="Add the local prefixes of the selected network, plus the mission scope if one is set."
                checked={opts.auto_targets}
                onChange={(e) => set('auto_targets', e.target.checked)}
              />

              <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                <TextField
                  label="TCP ports"
                  disabled={!custom}
                  className="font-mono text-[12.5px]"
                  hint='"top100", "top1000", "all" or "22,80,8000-8100"'
                  value={opts.tcp_ports}
                  onChange={(e) => set('tcp_ports', e.target.value)}
                />
                <TextField
                  label="UDP ports"
                  disabled={!custom}
                  className="font-mono text-[12.5px]"
                  hint="Empty disables UDP scanning."
                  value={opts.udp_ports}
                  onChange={(e) => set('udp_ports', e.target.value)}
                />
                <SelectField
                  label="Scan mode"
                  disabled={!custom}
                  hint="Auto uses SYN when the server has raw sockets."
                  value={opts.scan_mode}
                  onChange={(e) => set('scan_mode', e.target.value)}
                >
                  <option value="auto">auto</option>
                  <option value="syn">syn (raw, stateless)</option>
                  <option value="connect">connect (no privileges)</option>
                </SelectField>
                <TextField
                  label="Rate (pps)"
                  type="number"
                  min={1}
                  disabled={!custom}
                  hint="Packets per second across the whole scan."
                  value={opts.rate}
                  onChange={(e) => set('rate', Number(e.target.value))}
                />
                <TextField
                  label="Retries"
                  type="number"
                  min={0}
                  max={10}
                  disabled={!custom}
                  value={opts.retries}
                  onChange={(e) => set('retries', Number(e.target.value))}
                />
                <TextField
                  label="Probe timeout (ms)"
                  type="number"
                  min={100}
                  step={100}
                  disabled={!custom}
                  value={opts.timeout_ms}
                  onChange={(e) => set('timeout_ms', Number(e.target.value))}
                />
                <TextField
                  label="Concurrency"
                  type="number"
                  min={1}
                  disabled={!custom}
                  hint="Service-detection workers."
                  value={opts.concurrency}
                  onChange={(e) => set('concurrency', Number(e.target.value))}
                />
              </div>

              <fieldset className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <legend className="field-label">Phases</legend>
                <Checkbox
                  label="Host discovery"
                  hint="Off: every target is treated as up."
                  disabled={!custom}
                  checked={opts.host_discovery}
                  onChange={(e) => set('host_discovery', e.target.checked)}
                />
                <Checkbox
                  label="Service detection"
                  hint="Banner, TLS, HTTP and SSH fingerprinting."
                  disabled={!custom}
                  checked={opts.service_detection}
                  onChange={(e) => set('service_detection', e.target.checked)}
                />
                <Checkbox
                  label="Identity collection"
                  hint="SMB/NTLM, NetBIOS, SNMP, SSH keys → asset correlation."
                  disabled={!custom}
                  checked={opts.identity_collection}
                  onChange={(e) => set('identity_collection', e.target.checked)}
                />
                <Checkbox
                  label="Light checks"
                  hint="Misconfiguration checks that produce findings."
                  disabled={!custom}
                  checked={opts.checks}
                  onChange={(e) => set('checks', e.target.checked)}
                />
              </fieldset>

              <div className="rounded-md border border-warn/50 bg-warn/5 p-3">
                <Toggle
                  danger
                  disabled={!opts.checks}
                  checked={opts.allow_default_creds}
                  onChange={(v) => set('allow_default_creds', v)}
                  label={
                    <span className="flex items-center gap-2">
                      Try vendor default credentials
                      <Badge tone="warn">
                        <AlertIcon width={11} height={11} />
                        intrusive
                      </Badge>
                    </span>
                  }
                  hint={
                    opts.checks
                      ? "The only check family that authenticates. A short, capped list of vendor defaults is tried, so nothing gets locked out - but these are real login attempts and they land in the target's logs. Off by default; agree it with the client."
                      : 'Turn on Light checks above to enable this: it is one of the checks, so it has nothing to run in.'
                  }
                />
              </div>
            </CardBody>
          </Card>
        )}

        {/* ---------------- segmentation ---------------- */}
        {kind === 'segmentation' && (
          <Card>
            <CardHeader
              title="Segmentation"
              description="Which networks' services to replay from here, and how to try reaching them."
            />
            <CardBody className="space-y-6">
              <div>
                <span className="field-label">Source networks to replay</span>
                <p className="mb-2 text-xs text-faint">
                  The services discovered on these networks are retried from your current
                  position. Select none to test every other network.
                </p>
                {otherNetworks.length === 0 ? (
                  <InlineAlert tone="warn">
                    This mission has only one network. Discover at least one other VLAN before
                    testing segmentation.
                  </InlineAlert>
                ) : (
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {otherNetworks.map((n) => (
                      <Checkbox
                        key={n.id}
                        label={n.name}
                        hint={
                          n.vlan_id
                            ? `VLAN ${n.vlan_id} · ${(n.prefixes ?? []).join(', ')}`
                            : (n.prefixes ?? []).join(', ')
                        }
                        checked={sourceIds.includes(n.id)}
                        onChange={(e) => toggleSource(n.id, e.target.checked)}
                      />
                    ))}
                  </div>
                )}
              </div>

              <div>
                <span className="field-label">Techniques</span>
                {techniques.isLoading ? (
                  <Skeleton className="h-20" />
                ) : groupedTechniques.length === 0 ? (
                  <p className="text-xs text-muted">
                    The technique catalog is unavailable; the server will use its default set.
                  </p>
                ) : (
                  <div className="space-y-4">
                    {groupedTechniques.map(([group, items]) => {
                      const l2Group = group === 'Layer-2 active'
                      return (
                        <div
                          key={group}
                          className={cn(
                            'rounded-md border p-3',
                            l2Group ? 'border-warn/50 bg-warn/5' : 'border-border bg-elevated/50',
                          )}
                        >
                          <div className="mb-2 flex items-center gap-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
                              {group}
                            </h4>
                            {l2Group && (
                              <Badge tone="warn">
                                <AlertIcon width={11} height={11} />
                                may disturb the switch
                              </Badge>
                            )}
                          </div>

                          {l2Group && (
                            <div className="mb-3">
                              <Toggle
                                danger
                                checked={opts.allow_l2_active}
                                onChange={(v) => {
                                  set('allow_l2_active', v)
                                  if (!v) {
                                    set(
                                      'techniques',
                                      selectedTechniques.filter(
                                        (id) =>
                                          !(techniques.data ?? []).some(
                                            (t) => t.id === id && t.l2_active,
                                          ),
                                      ),
                                    )
                                  }
                                }}
                                label="Allow layer-2 active techniques"
                                hint={
                                  <>
                                    These techniques <strong>send DTP frames, create 802.1Q
                                    sub-interfaces or double-tagged packets</strong>. They can
                                    flap the switch port, trigger port-security or BPDU guard and
                                    cut your own link. Agree it with the client first, and never
                                    run them on production access ports without a window.
                                  </>
                                }
                              />
                            </div>
                          )}

                          <div className="grid gap-2 sm:grid-cols-2">
                            {items.map((t) => (
                              <Checkbox
                                key={t.id}
                                disabled={t.l2_active && !opts.allow_l2_active}
                                checked={selectedTechniques.includes(t.id)}
                                onChange={(e) => toggleTechnique(t.id, e.target.checked)}
                                label={
                                  <span className="flex flex-wrap items-center gap-1.5">
                                    {t.title || humanizeId(t.id)}
                                    {t.default && <Badge tone="neutral">default</Badge>}
                                    {t.one_way && (
                                      <Badge
                                        tone="info"
                                        title="Delivery cannot be confirmed: results are reported as 'sent'."
                                      >
                                        one-way
                                      </Badge>
                                    )}
                                  </span>
                                }
                                hint={t.description}
                              />
                            ))}
                          </div>
                        </div>
                      )
                    })}
                    <p className="text-xs text-faint">
                      Nothing selected = the server's default set (the techniques marked
                      “default”, never the layer-2 active ones).
                    </p>
                  </div>
                )}
              </div>

              {opts.allow_l2_active && l2Selected.length > 0 && (
                <InlineAlert tone="warn" title="Layer-2 active techniques are armed">
                  {l2Selected.map((t) => t.title || t.id).join(', ')}. NETY restores every route
                  and sub-interface it creates, including on cancellation - but the switch may
                  still react. Make sure you can physically reach the port.
                </InlineAlert>
              )}

              <TextField
                label="VLAN range for sub-interface brute force"
                className="font-mono text-[12.5px]"
                placeholder="1-4094"
                hint="Only used by the dot1q / double-tag techniques. Empty = the VLAN IDs of the target networks."
                disabled={!opts.allow_l2_active}
                value={vlanRange}
                onChange={(e) => setVlanRange(e.target.value)}
              />
            </CardBody>
          </Card>
        )}

        {kind === 'checks' && (
          <Card>
            <CardHeader
              title="Checks only"
              description="Works from the hosts and services already stored for this network."
            />
            <CardBody className="space-y-5">
              <InlineAlert tone="info">
                Nothing is discovered and no port is scanned. The scan walks the inventory this
                network already has and runs the phases you pick below. Run it when the mapping
                was done with the checks switched off, or to pick up checks added since.
                <br />
                <br />
                Running it twice changes nothing twice: hosts, services and findings are keyed on
                what identifies them, so a second pass refreshes the rows that are there instead
                of adding more, and it leaves your statuses and notes alone.
              </InlineAlert>

              <fieldset className="grid gap-3 sm:grid-cols-3">
                <legend className="field-label">Phases</legend>
                <Checkbox
                  label="Service detection"
                  hint="Re-identify each known service. Off keeps the versions you already have."
                  checked={opts.service_detection}
                  onChange={(e) => set('service_detection', e.target.checked)}
                />
                <Checkbox
                  label="Identity collection"
                  hint="Refresh the evidence that ties an address to a machine."
                  checked={opts.identity_collection}
                  onChange={(e) => set('identity_collection', e.target.checked)}
                />
                <Checkbox
                  label="Checks"
                  hint="The misconfiguration checks that produce findings."
                  checked={opts.checks}
                  onChange={(e) => set('checks', e.target.checked)}
                />
              </fieldset>

              <div className="rounded-md border border-warn/50 bg-warn/5 p-3">
                <Toggle
                  danger
                  disabled={!opts.checks}
                  checked={opts.allow_default_creds}
                  onChange={(v) => set('allow_default_creds', v)}
                  label={
                    <span className="flex items-center gap-2">
                      Try vendor default credentials
                      <Badge tone="warn">
                        <AlertIcon width={11} height={11} />
                        intrusive
                      </Badge>
                    </span>
                  }
                  hint={
                    opts.checks
                      ? "The only check family that authenticates. A short, capped list of vendor defaults is tried, so nothing gets locked out - but these are real login attempts and they land in the target's logs. Off by default; agree it with the client."
                      : 'Turn on Checks above to enable this: it is one of the checks, so it has nothing to run in.'
                  }
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <TextField
                  label="Timeout (ms)"
                  type="number"
                  min={100}
                  value={opts.timeout_ms}
                  onChange={(e) => set('timeout_ms', Number(e.target.value))}
                />
                <TextField
                  label="Concurrency"
                  type="number"
                  min={1}
                  hint="Workers running checks in parallel."
                  value={opts.concurrency}
                  onChange={(e) => set('concurrency', Number(e.target.value))}
                />
              </div>
            </CardBody>
          </Card>
        )}

        {kind === 'l2probe' && (
          <Card>
            <CardHeader
              title="Layer-2 probe"
              description="Passive capture of CDP, LLDP, DTP, STP and 802.1Q tags on the selected network's interface."
            />
            <CardBody className="space-y-3">
              <InlineAlert tone="info">
                A passive probe sends nothing. It listens for about a minute and updates the
                network's L2 panel with the neighbours, the native and voice VLANs, the tags seen
                on the wire and whether the port offers trunk negotiation.
              </InlineAlert>
              <Toggle
                danger
                checked={opts.allow_l2_active}
                onChange={(v) => set('allow_l2_active', v)}
                label="Also try active VLAN discovery"
                hint="Sends DTP frames and brings up 802.1Q sub-interfaces to find carried VLANs. May disturb the switch; off by default."
              />
              {opts.allow_l2_active && (
                <TextField
                  label="VLAN range to probe"
                  className="font-mono text-[12.5px]"
                  placeholder="1-4094"
                  value={vlanRange}
                  onChange={(e) => setVlanRange(e.target.value)}
                />
              )}
            </CardBody>
          </Card>
        )}
      </div>

      {/* ---------------- sticky action bar ---------------- */}
      <div className="sticky bottom-0 -mx-6 border-t border-border bg-surface/95 px-6 py-3 backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-muted">
            {kind === 'segmentation'
              ? 'Segmentation results fill the matrix live, cell by cell.'
              : 'You can pause the scan at any time and resume it later without losing work.'}
          </p>
          <div className="flex items-center gap-2">
            <Button onClick={() => void submit(false)} loading={createScan.isPending}>
              Create without starting
            </Button>
            <Button
              variant="primary"
              size="lg"
              icon={<ScanIcon />}
              loading={createScan.isPending}
              onClick={() => void submit(true)}
            >
              Launch scan
            </Button>
          </div>
        </div>
      </div>
    </PageContainer>
  )
}
