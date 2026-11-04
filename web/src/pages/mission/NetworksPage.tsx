import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '@/lib/api'
import {
  useCreateNetwork,
  useDeleteNetwork,
  useHosts,
  useInterfaces,
  useNetworks,
  usePatchNetwork,
} from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, KeyValue, PageHeader } from '@/components/ui/Card'
import { Button, IconButton, LinkButton } from '@/components/ui/Button'
import { Modal, ConfirmDialog } from '@/components/ui/Modal'
import { SelectField, TextAreaField, TextField } from '@/components/ui/Field'
import { CardSkeleton, EmptyState, ErrorState, InlineAlert } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { Mono, RelativeTime } from '@/components/common'
import { useToast } from '@/components/ui/Toast'
import { formatNumber } from '@/lib/format'
import {
  BoltIcon,
  EditIcon,
  NetworkIcon,
  PlusIcon,
  ScanIcon,
  TrashIcon,
  TrunkIcon,
} from '@/components/icons'
import type { InterfaceInfo, Network, NetworkInput } from '@/types/api'

function splitList(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

const emptyForm = {
  name: '',
  vlan_id: '',
  description: '',
  interface: '',
  local_ip: '',
  prefixes: '',
  gateway: '',
  dns_servers: '',
}

type FormState = typeof emptyForm

function formFromNetwork(n: Network): FormState {
  return {
    name: n.name,
    vlan_id: n.vlan_id ? String(n.vlan_id) : '',
    description: n.description,
    interface: n.interface,
    local_ip: n.local_ip,
    prefixes: (n.prefixes ?? []).join(' '),
    gateway: n.gateway,
    dns_servers: (n.dns_servers ?? []).join(' '),
  }
}

function toInput(f: FormState): NetworkInput {
  return {
    name: f.name.trim(),
    vlan_id: f.vlan_id ? Number(f.vlan_id) : 0,
    description: f.description.trim(),
    interface: f.interface.trim(),
    local_ip: f.local_ip.trim(),
    prefixes: splitList(f.prefixes),
    gateway: f.gateway.trim(),
    dns_servers: splitList(f.dns_servers),
  }
}

function InterfaceOption({ i }: { i: InterfaceInfo }) {
  const addrs = (i.addresses ?? []).join(', ')
  return (
    <option value={i.name}>
      {i.name}
      {i.is_vlan ? ` (vlan ${i.vlan_id})` : ''}
      {addrs ? ` — ${addrs}` : i.up ? ' — up, no address' : ' — down'}
    </option>
  )
}

function NetworkFormModal({
  open,
  onClose,
  existing,
}: {
  open: boolean
  onClose: () => void
  existing?: Network | null
}) {
  const missionId = useMissionId()
  const toast = useToast()
  const create = useCreateNetwork(missionId)
  const patch = usePatchNetwork(missionId)
  const interfaces = useInterfaces(open)

  const [form, setForm] = useState<FormState>(emptyForm)
  const [detectIface, setDetectIface] = useState('')
  const [detecting, setDetecting] = useState(false)
  const [detected, setDetected] = useState<Network | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setForm(existing ? formFromNetwork(existing) : emptyForm)
    setDetected(null)
    setError(null)
    setDetectIface(existing?.interface ?? '')
  }, [open, existing])

  const set = (k: keyof FormState) => (v: string) => setForm((f) => ({ ...f, [k]: v }))

  const runDetect = async () => {
    setDetecting(true)
    setError(null)
    try {
      const draft = await api.detectNetwork(detectIface || undefined)
      setDetected(draft)
      setForm((f) => ({
        ...f,
        name:
          f.name ||
          (draft.vlan_id ? `VLAN ${draft.vlan_id}` : draft.interface || 'Detected network'),
        vlan_id: draft.vlan_id ? String(draft.vlan_id) : f.vlan_id,
        interface: draft.interface || f.interface,
        local_ip: draft.local_ip || f.local_ip,
        prefixes: (draft.prefixes ?? []).join(' ') || f.prefixes,
        gateway: draft.gateway || f.gateway,
        dns_servers: (draft.dns_servers ?? []).join(' ') || f.dns_servers,
      }))
      toast.success('Interface detected', draft.interface)
    } catch (err) {
      setError(
        err instanceof Error
          ? `Auto-detect failed: ${err.message}`
          : 'Auto-detect failed.',
      )
    } finally {
      setDetecting(false)
    }
  }

  const submit = async () => {
    setError(null)
    const body = toInput(form)
    if (!body.name) {
      setError('Give the network a name — "VLAN 20 — Servers" reads well in the report.')
      return
    }
    try {
      if (existing) {
        await patch.mutateAsync({ id: existing.id, body })
        toast.success('Network updated')
      } else {
        await create.mutateAsync(body)
        toast.success('Network created')
      }
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not save the network.')
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={existing ? `Edit ${existing.name}` : 'New network'}
      description="One network per VLAN or attachment point you plug into."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            onClick={submit}
            loading={create.isPending || patch.isPending}
          >
            {existing ? 'Save changes' : 'Create network'}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        {error && <InlineAlert tone="crit">{error}</InlineAlert>}

        <section className="rounded-md border border-border bg-elevated/60 p-3.5">
          <h3 className="flex items-center gap-2 text-sm font-semibold">
            <BoltIcon className="text-accent" />
            Auto-detect from an interface
          </h3>
          <p className="mt-1 text-xs text-muted">
            NETY reads the addressing, gateway, DNS and DHCP lease of the chosen NIC and
            pre-fills the form. Nothing is saved until you press create.
          </p>
          <div className="mt-3 flex flex-wrap items-end gap-2">
            <SelectField
              label="Interface"
              wrapperClassName="min-w-[260px] flex-1"
              value={detectIface}
              onChange={(e) => setDetectIface(e.target.value)}
            >
              <option value="">Interface holding the default route</option>
              {(interfaces.data ?? []).map((i) => (
                <InterfaceOption key={i.name} i={i} />
              ))}
            </SelectField>
            <Button onClick={runDetect} loading={detecting} icon={<BoltIcon />}>
              Detect
            </Button>
          </div>
          {detected && (
            <div className="mt-3 rounded border border-border bg-surface px-3 py-2 text-xs">
              <div className="mb-1 font-medium text-fg">Detected</div>
              <dl className="grid grid-cols-2 gap-x-6">
                <KeyValue label="Interface" mono>
                  {detected.interface || '—'}
                </KeyValue>
                <KeyValue label="Local IP / MAC" mono>
                  {detected.local_ip || '—'} {detected.local_mac ? `· ${detected.local_mac}` : ''}
                </KeyValue>
                <KeyValue label="Gateway" mono>
                  {detected.gateway || '—'}
                </KeyValue>
                <KeyValue label="DHCP server" mono>
                  {detected.dhcp_server || '—'}
                </KeyValue>
                <KeyValue label="Domain search">
                  {(detected.domain_search ?? []).join(', ') || '—'}
                </KeyValue>
                <KeyValue label="VLAN">{detected.vlan_id || 'untagged'}</KeyValue>
              </dl>
            </div>
          )}
          {interfaces.isError && (
            <p className="mt-2 text-xs text-warn">
              The interface list is unavailable (the server may lack the privileges to enumerate
              NICs). Fill the fields by hand.
            </p>
          )}
        </section>

        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            label="Name"
            required
            placeholder="VLAN 20 — Servers"
            value={form.name}
            onChange={(e) => set('name')(e.target.value)}
          />
          <TextField
            label="VLAN ID"
            type="number"
            min={0}
            max={4094}
            placeholder="0 = untagged / unknown"
            value={form.vlan_id}
            onChange={(e) => set('vlan_id')(e.target.value)}
          />
          <TextField
            label="Interface"
            placeholder="eth0"
            className="font-mono text-[12.5px]"
            value={form.interface}
            onChange={(e) => set('interface')(e.target.value)}
          />
          <TextField
            label="Local IP"
            placeholder="10.20.0.37"
            className="font-mono text-[12.5px]"
            value={form.local_ip}
            onChange={(e) => set('local_ip')(e.target.value)}
          />
          <TextField
            label="Prefixes"
            placeholder="10.20.0.0/24"
            hint="Space-separated CIDRs of the local segment."
            className="font-mono text-[12.5px]"
            value={form.prefixes}
            onChange={(e) => set('prefixes')(e.target.value)}
          />
          <TextField
            label="Gateway"
            placeholder="10.20.0.1"
            className="font-mono text-[12.5px]"
            value={form.gateway}
            onChange={(e) => set('gateway')(e.target.value)}
          />
          <TextField
            label="DNS servers"
            placeholder="10.20.0.10 10.20.0.11"
            className="font-mono text-[12.5px]"
            wrapperClassName="sm:col-span-2"
            value={form.dns_servers}
            onChange={(e) => set('dns_servers')(e.target.value)}
          />
          <TextAreaField
            label="Description"
            rows={2}
            wrapperClassName="sm:col-span-2"
            placeholder="Patch panel port B12, meeting room, access port…"
            value={form.description}
            onChange={(e) => set('description')(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  )
}

/** The L2 panel: what the switch port told us without sending a frame. */
function L2Panel({ network }: { network: Network }) {
  const l2 = network.l2 ?? {
    neighbors: [],
    dtp_seen: false,
  }
  const neighbors = l2.neighbors ?? []
  const observed = l2.observed_vlans ?? []
  const nothing =
    neighbors.length === 0 &&
    !l2.dtp_seen &&
    !l2.native_vlan &&
    !l2.voice_vlan &&
    observed.length === 0 &&
    !l2.stp_root_bridge

  return (
    <div className="border-t border-border">
      {l2.dtp_seen && (
        <div className="flex items-start gap-3 border-b border-crit/40 bg-crit/10 px-4 py-3">
          <TrunkIcon className="mt-0.5 shrink-0 text-crit" width={18} height={18} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-crit">
                This port negotiates trunking
              </span>
              {l2.dtp_mode && <Badge tone="crit">DTP mode: {l2.dtp_mode}</Badge>}
            </div>
            <p className="mt-1 text-xs text-fg/90">
              DTP frames were seen on this access port. Anyone plugging in here can negotiate a
              trunk and gain access to every VLAN the port carries — VLAN segmentation is void
              at this location. Report it as a finding on its own, and use the L2-active
              segmentation techniques to demonstrate it.
            </p>
          </div>
        </div>
      )}

      <div className="grid gap-x-8 gap-y-1 px-4 py-3 sm:grid-cols-2">
        <KeyValue label="Native VLAN">
          {l2.native_vlan ? (
            <span className="tabular">{l2.native_vlan}</span>
          ) : (
            <span className="text-faint">—</span>
          )}
        </KeyValue>
        <KeyValue label="Voice VLAN">
          {l2.voice_vlan ? (
            <Badge tone="info">VLAN {l2.voice_vlan}</Badge>
          ) : (
            <span className="text-faint">—</span>
          )}
        </KeyValue>
        <KeyValue label="Observed 802.1Q tags">
          {observed.length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {observed.map((v) => (
                <Badge key={v} tone="accent">
                  {v}
                </Badge>
              ))}
            </span>
          ) : (
            <span className="text-faint">none seen on the wire</span>
          )}
        </KeyValue>
        <KeyValue label="STP root bridge" mono>
          {l2.stp_root_bridge || <span className="text-faint">—</span>}
        </KeyValue>
        <KeyValue label="Captured">
          {l2.captured_at ? (
            <RelativeTime value={l2.captured_at} />
          ) : (
            <span className="text-faint">never — run an l2probe scan</span>
          )}
        </KeyValue>
      </div>

      {neighbors.length > 0 ? (
        <div className="table-scroll border-t border-border">
          <table className="data-table">
            <thead>
              <tr>
                <th>Proto</th>
                <th>Device</th>
                <th>Port</th>
                <th>Platform</th>
                <th>Mgmt address</th>
                <th>Native / voice</th>
                <th>Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {neighbors.map((n, i) => (
                <tr key={`${n.protocol}-${n.device_id}-${i}`}>
                  <td>
                    <Badge tone={n.protocol === 'cdp' ? 'info' : 'accent'}>
                      {n.protocol.toUpperCase()}
                    </Badge>
                  </td>
                  <td className="font-medium">{n.device_id || '—'}</td>
                  <td>
                    <Mono>{n.port_id || '—'}</Mono>
                  </td>
                  <td
                    className="max-w-[260px] truncate text-muted"
                    title={[n.platform, n.software].filter(Boolean).join(' · ')}
                  >
                    {n.platform || '—'}
                  </td>
                  <td>
                    <Mono>{n.mgmt_address || '—'}</Mono>
                  </td>
                  <td className="tabular text-muted">
                    {n.native_vlan || '—'} / {n.voice_vlan || '—'}
                  </td>
                  <td className="text-muted">{(n.capabilities ?? []).join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        nothing && (
          <div className="border-t border-border px-4 py-3 text-xs text-muted">
            No CDP, LLDP, DTP or STP frame captured on this port yet. Launch an{' '}
            <strong className="text-fg">l2probe</strong> scan to listen passively for a minute —
            it is silent and tells you who the switch is, which VLANs it carries and whether the
            port offers trunking.
          </div>
        )
      )}
    </div>
  )
}

function NetworkCard({
  network,
  hostCount,
  onEdit,
  onDelete,
  canWrite,
}: {
  network: Network
  hostCount: number
  onEdit: () => void
  onDelete: () => void
  canWrite: boolean
}) {
  return (
    <Card
      id={`network-${network.id}`}
      className={network.l2?.dtp_seen ? 'border-crit/50' : undefined}
    >
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            {network.name}
            {network.vlan_id > 0 && <Badge tone="accent">VLAN {network.vlan_id}</Badge>}
            {network.l2?.dtp_seen && (
              <Badge tone="crit">
                <TrunkIcon width={11} height={11} />
                Trunk negotiable
              </Badge>
            )}
          </span>
        }
        description={network.description || undefined}
        actions={
          <>
            <LinkButton
              to={`../scans/new?network=${network.id}`}
              size="sm"
              icon={<ScanIcon width={13} height={13} />}
            >
              Scan
            </LinkButton>
            {canWrite && (
              <>
                <IconButton label={`Edit ${network.name}`} onClick={onEdit}>
                  <EditIcon />
                </IconButton>
                <IconButton label={`Delete ${network.name}`} onClick={onDelete}>
                  <TrashIcon />
                </IconButton>
              </>
            )}
          </>
        }
      />

      <div className="grid gap-x-8 gap-y-1 px-4 py-3 sm:grid-cols-2">
        <KeyValue label="Interface" mono>
          {network.interface || <span className="text-faint">—</span>}
        </KeyValue>
        <KeyValue label="Local IP / MAC" mono>
          {network.local_ip || '—'}
          {network.local_mac ? <span className="text-muted"> · {network.local_mac}</span> : null}
        </KeyValue>
        <KeyValue label="Prefixes" mono>
          {(network.prefixes ?? []).join(', ') || <span className="text-faint">—</span>}
        </KeyValue>
        <KeyValue label="Gateway" mono>
          {network.gateway || <span className="text-faint">—</span>}
        </KeyValue>
        <KeyValue label="DNS" mono>
          {(network.dns_servers ?? []).join(', ') || <span className="text-faint">—</span>}
          {(network.domain_search ?? []).length > 0 && (
            <span className="text-muted"> · search {(network.domain_search ?? []).join(' ')}</span>
          )}
        </KeyValue>
        <KeyValue label="DHCP server" mono>
          {network.dhcp_server || <span className="text-faint">—</span>}
        </KeyValue>
        <KeyValue label="Hosts found">
          <Link to="../hosts" className="tabular hover:underline">
            {formatNumber(hostCount)}
          </Link>
        </KeyValue>
        <KeyValue label="Created">
          <RelativeTime value={network.created_at} />
        </KeyValue>
      </div>

      <L2Panel network={network} />
    </Card>
  )
}

export default function NetworksPage() {
  const missionId = useMissionId()
  const { canWrite } = useAuth()
  const toast = useToast()
  const networks = useNetworks(missionId)
  const hosts = useHosts(missionId)
  const remove = useDeleteNetwork(missionId)

  const [formOpen, setFormOpen] = useState(false)
  const [editing, setEditing] = useState<Network | null>(null)
  const [deleting, setDeleting] = useState<Network | null>(null)

  const hostCounts = useMemo(() => {
    const m = new Map<number, number>()
    for (const h of hosts.data ?? []) m.set(h.network_id, (m.get(h.network_id) ?? 0) + 1)
    return m
  }, [hosts.data])

  const list = networks.data ?? []
  const trunking = list.filter((n) => n.l2?.dtp_seen)

  // Deep link from the overview: /networks#network-12
  useEffect(() => {
    if (!window.location.hash || list.length === 0) return
    const el = document.querySelector(window.location.hash)
    el?.scrollIntoView({ block: 'start' })
  }, [list.length])

  return (
    <PageContainer>
      <PageHeader
        title="Networks"
        description="The VLANs and attachment points of this mission, with the passive L2 recon of each switch port."
        actions={
          canWrite && (
            <Button
              variant="primary"
              icon={<PlusIcon />}
              onClick={() => {
                setEditing(null)
                setFormOpen(true)
              }}
            >
              New network
            </Button>
          )
        }
      />

      {trunking.length > 0 && (
        <InlineAlert
          tone="crit"
          className="mt-4"
          icon={<TrunkIcon />}
          title="Trunk negotiation offered on an access port"
        >
          {trunking.map((n) => n.name).join(', ')} — the switch answers DTP here. Enable the
          L2-active techniques in a segmentation scan to prove how far a trunk would reach.
        </InlineAlert>
      )}

      <div className="mt-5 space-y-4">
        {networks.isLoading ? (
          <>
            <CardSkeleton />
            <CardSkeleton />
          </>
        ) : networks.isError ? (
          <ErrorState
            title="Could not load the networks"
            error={networks.error}
            retry={() => void networks.refetch()}
          />
        ) : list.length === 0 ? (
          <Card>
            <EmptyState
              icon={<NetworkIcon width={20} height={20} />}
              title="Create a network for the VLAN you are plugged into"
              description="Plug into the segment, then let NETY auto-detect the interface: it reads the addressing, gateway, DNS and DHCP lease and pre-fills everything. Repeat for each VLAN you visit."
              action={
                canWrite && (
                  <Button
                    variant="primary"
                    icon={<PlusIcon />}
                    onClick={() => {
                      setEditing(null)
                      setFormOpen(true)
                    }}
                  >
                    Create a network
                  </Button>
                )
              }
            />
          </Card>
        ) : (
          list.map((n) => (
            <NetworkCard
              key={n.id}
              network={n}
              hostCount={hostCounts.get(n.id) ?? 0}
              canWrite={canWrite}
              onEdit={() => {
                setEditing(n)
                setFormOpen(true)
              }}
              onDelete={() => setDeleting(n)}
            />
          ))
        )}
      </div>

      <NetworkFormModal
        open={formOpen}
        existing={editing}
        onClose={() => {
          setFormOpen(false)
          setEditing(null)
        }}
      />

      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        destructive
        title={`Delete ${deleting?.name ?? 'network'}?`}
        confirmLabel="Delete network"
        busy={remove.isPending}
        body={
          <>
            The hosts, services and findings collected on this network are deleted with it. Scans
            that targeted it keep their history but lose their results. This cannot be undone.
          </>
        }
        onConfirm={async () => {
          if (!deleting) return
          try {
            await remove.mutateAsync(deleting.id)
            toast.success('Network deleted')
            setDeleting(null)
          } catch (err) {
            toast.error('Could not delete the network', err)
          }
        }}
      />
    </PageContainer>
  )
}
