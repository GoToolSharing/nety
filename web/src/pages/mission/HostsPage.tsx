import { useCallback, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useHost, useHosts, useNetworks } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, KeyValue, PageHeader } from '@/components/ui/Card'
import { Drawer } from '@/components/ui/Modal'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, PortStateBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import {
  CopyButton,
  Mono,
  RelativeTime,
  SearchInput,
  SortHeader,
  useSort,
} from '@/components/common'
import ServiceDetail from '@/components/ServiceDetail'
import { SKIPPED_ROW_CLASS, TriageNote, TriageSelect } from '@/components/Triage'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import { compareIP, formatNumber } from '@/lib/format'
import { HostIcon } from '@/components/icons'
import type { Host, Service, TriageStatus } from '@/types/api'

type SortKey = 'ip' | 'hostname' | 'os' | 'mac' | 'status' | 'network' | 'last_seen'

function HostDrawer({
  host,
  networkName,
  onClose,
  onTriage,
  busy,
}: {
  host: Host | null
  networkName: string
  onClose: () => void
  onTriage: (host: Host, body: { status?: TriageStatus; note?: string }) => void
  busy: boolean
}) {
  const detail = useHost(host?.id ?? 0)
  const [openService, setOpenService] = useState<Service | null>(null)
  const services = detail.data?.services ?? []

  return (
    <>
      <Drawer
        open={!!host}
        onClose={onClose}
        width="lg"
        title={host?.ip ?? ''}
        subtitle={
          host ? (
            <span className="flex flex-wrap items-center gap-2">
              {networkName}
              {host.hostname && <span>· {host.hostname}</span>}
              {host.asset_id ? (
                <Link to="../assets" className="text-accent hover:underline">
                  asset #{host.asset_id}
                </Link>
              ) : null}
            </span>
          ) : undefined
        }
      >
        {host && (
          <>
            {/* The operator's own pass comes first: this pane is where an
                address is taken out of scope, and where it comes back. */}
            <section className="mb-4">
              <h3 className="panel-title mb-1.5">Your review</h3>
              <div className="flex flex-wrap items-start gap-4 rounded-md border border-border bg-elevated/50 px-3 py-2">
                <div className="w-44 shrink-0">
                  <div className="mb-1 text-[11px] text-muted">Status</div>
                  <TriageSelect
                    value={host.triage?.status}
                    busy={busy}
                    onChange={(status) => onTriage(host, { status })}
                  />
                  {host.triage?.updated_at && (
                    <div className="mt-1.5 text-[11px] text-faint">
                      {host.triage.updated_by_name ? `${host.triage.updated_by_name}, ` : ''}
                      <RelativeTime value={host.triage.updated_at} />
                    </div>
                  )}
                </div>
                <div className="min-w-[260px] flex-1">
                  <div className="mb-1 text-[11px] text-muted">Notes</div>
                  <TriageNote
                    value={host.triage?.note ?? ''}
                    onSave={(note) => onTriage(host, { note })}
                    placeholder="Why is this address skipped, or what is left to test on it?"
                  />
                </div>
              </div>
              {host.triage?.status === 'skipped' && (
                <p className="mt-1.5 text-xs text-muted">
                  This address is out of the way: its services, its findings and the
                  segmentation tests aimed at it are hidden from the other screens. Nothing
                  was deleted, and nothing written on them was touched.
                </p>
              )}
            </section>

            <dl className="rounded-md border border-border bg-elevated/50 px-3 py-2">
              <KeyValue label="IP" mono>
                <span className="flex items-center gap-1">
                  {host.ip}
                  <CopyButton value={host.ip} />
                </span>
              </KeyValue>
              <KeyValue label="MAC / vendor" mono>
                {host.mac || '-'}
                {host.vendor ? <span className="text-muted"> · {host.vendor}</span> : null}
              </KeyValue>
              <KeyValue label="Hostname">
                {host.hostname || '-'}
                {(host.hostnames ?? []).length > 1 && (
                  <span className="text-muted"> ({(host.hostnames ?? []).join(', ')})</span>
                )}
              </KeyValue>
              <KeyValue label="Domain">{host.domain || '-'}</KeyValue>
              <KeyValue label="OS">{host.os || '-'}</KeyValue>
              <KeyValue label="TTL">{host.ttl || '-'}</KeyValue>
              <KeyValue label="Discovered by">
                {(host.discovered_by ?? []).length === 0 ? (
                  '-'
                ) : (
                  <span className="flex flex-wrap gap-1">
                    {(host.discovered_by ?? []).map((m) => (
                      <Badge key={m} tone="neutral">
                        {m}
                      </Badge>
                    ))}
                  </span>
                )}
              </KeyValue>
              <KeyValue label="Seen">
                <RelativeTime value={host.last_seen} /> · first{' '}
                <RelativeTime value={host.first_seen} />
              </KeyValue>
            </dl>

            <h3 className="mb-1.5 mt-4 text-xs font-semibold uppercase tracking-wider text-muted">
              Services ({services.length})
            </h3>
            {detail.isLoading ? (
              <TableSkeleton rows={4} columns={4} />
            ) : services.length === 0 ? (
              <p className="rounded-md border border-border bg-elevated/50 px-3 py-4 text-sm text-muted">
                No service recorded on this host yet.
              </p>
            ) : (
              <div className="table-scroll rounded-md border border-border">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>State</th>
                      <th>Service</th>
                      <th>Product</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {[...services]
                      .sort((a, b) => a.port - b.port)
                      .map((s) => (
                        <tr key={s.id}>
                          <td className="tabular">
                            {s.port}/{s.protocol}
                          </td>
                          <td>
                            <PortStateBadge state={s.state} />
                          </td>
                          <td>
                            {s.name || '-'}
                            {s.tunnel ? (
                              <Badge tone="info" className="ml-1">
                                {s.tunnel}
                              </Badge>
                            ) : null}
                          </td>
                          <td className="max-w-[220px] truncate text-muted">
                            {[s.product, s.version].filter(Boolean).join(' ') || '-'}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="rounded text-xs text-accent hover:underline"
                              onClick={() => setOpenService(s)}
                            >
                              Details
                            </button>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </Drawer>

      <Drawer
        open={!!openService}
        onClose={() => setOpenService(null)}
        title={openService ? `${openService.ip}:${openService.port}/${openService.protocol}` : ''}
        subtitle={openService?.name}
      >
        {openService && <ServiceDetail service={openService} />}
      </Drawer>
    </>
  )
}

export default function HostsPage() {
  const missionId = useMissionId()
  const networks = useNetworks(missionId)
  const [networkId, setNetworkId] = useState<number>(0)
  const hosts = useHosts(missionId, networkId || undefined)
  const [query, setQuery] = useState('')
  const { sort, onSort } = useSort<SortKey>('ip')
  const [selected, setSelected] = useState<Host | null>(null)
  const [picked, setPicked] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState<number | null>(null)

  const qc = useQueryClient()
  const toast = useToast()

  // Skipping an address changes every table keyed on it, so the refresh is
  // deliberately wide rather than one cache at a time.
  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: qk.hostsRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.servicesRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.findingsRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.reachRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.matrix(missionId) })
    void qc.invalidateQueries({ queryKey: qk.triageSummaryRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.summary(missionId) })
  }, [qc, missionId])

  const setStatus = useCallback(
    async (host: Host, body: { status?: TriageStatus; note?: string }) => {
      setBusy(host.id)
      try {
        const updated = await api.triageHost(host.id, body)
        setSelected((open) => (open && open.id === updated.id ? updated : open))
        refresh()
      } catch (e) {
        toast.error(e instanceof Error ? e.message : 'Could not update the status')
      } finally {
        setBusy(null)
      }
    },
    [refresh, toast],
  )

  const setSelectionStatus = useCallback(
    async (status: TriageStatus) => {
      const ids = [...picked]
      if (ids.length === 0) return
      try {
        const res = await api.triageHostsBulk(missionId, ids, status)
        setPicked(new Set())
        refresh()
        toast.success(`${res.updated} hosts marked ${status.replace('_', ' ')}`)
      } catch (e) {
        toast.error(e instanceof Error ? e.message : 'Could not update the selection')
      }
    },
    [missionId, picked, refresh, toast],
  )

  const togglePicked = (id: number) =>
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = (hosts.data ?? []).filter((h) => {
      if (!q) return true
      return (
        h.ip.includes(q) ||
        (h.hostname ?? '').toLowerCase().includes(q) ||
        (h.mac ?? '').toLowerCase().includes(q) ||
        (h.vendor ?? '').toLowerCase().includes(q) ||
        (h.os ?? '').toLowerCase().includes(q) ||
        (h.domain ?? '').toLowerCase().includes(q)
      )
    })
    const dir = sort.dir === 'asc' ? 1 : -1
    return filtered.sort((a, b) => {
      switch (sort.key) {
        case 'ip':
          return dir * compareIP(a.ip, b.ip)
        case 'hostname':
          return dir * (a.hostname ?? '').localeCompare(b.hostname ?? '')
        case 'os':
          return dir * (a.os ?? '').localeCompare(b.os ?? '')
        case 'mac':
          return dir * (a.mac ?? '').localeCompare(b.mac ?? '')
        case 'status':
          return dir * (a.triage?.status ?? 'todo').localeCompare(b.triage?.status ?? 'todo')
        case 'network':
          return dir * (netName.get(a.network_id) ?? '').localeCompare(netName.get(b.network_id) ?? '')
        case 'last_seen':
          return dir * a.last_seen.localeCompare(b.last_seen)
      }
    })
  }, [hosts.data, query, sort, netName])

  return (
    <PageContainer wide>
      <PageHeader
        title="Hosts"
        description="Every IP seen alive, per network. Open a row for its services and identity."
      />

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="IP, hostname, MAC, vendor, OS…"
          className="w-full max-w-sm"
        />
        <label className="flex items-center gap-2 text-xs text-muted">
          <span>Network</span>
          <select
            value={networkId}
            onChange={(e) => setNetworkId(Number(e.target.value))}
            className="select-base"
          >
            <option value={0}>All networks</option>
            {(networks.data ?? []).map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>
        </label>
        <span className="tabular text-xs text-faint">
          {formatNumber(rows.length)} host{rows.length === 1 ? '' : 's'}
        </span>
      </div>

      {picked.size > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="text-xs font-medium text-fg">{picked.size} selected</span>
          <span className="text-xs text-muted">Mark as</span>
          {(['done', 'flagged', 'skipped', 'in_progress', 'todo'] as TriageStatus[]).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => void setSelectionStatus(s)}
              className="rounded border border-border bg-surface px-2 py-0.5 text-[11px] text-fg hover:border-border-strong"
            >
              {s.replace('_', ' ')}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setPicked(new Set())}
            className="ml-auto text-[11px] text-muted hover:text-fg"
          >
            Clear selection
          </button>
        </div>
      )}

      <Card className="mt-4">
        {hosts.isLoading ? (
          <TableSkeleton rows={10} columns={6} />
        ) : hosts.isError ? (
          <ErrorState
            title="Could not load the hosts"
            error={hosts.error}
            retry={() => void hosts.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<HostIcon width={20} height={20} />}
            title={query ? 'No host matches that filter' : 'No host discovered yet'}
            description={
              query
                ? 'Clear the search or pick another network.'
                : 'Launch a discovery scan on one of your networks - hosts appear here as soon as they answer, without waiting for the scan to finish.'
            }
            action={
              !query && (
                <LinkButton to="../scans/new" variant="primary">
                  Launch a discovery scan
                </LinkButton>
              )
            }
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th className="w-px">
                    <input
                      type="checkbox"
                      aria-label="Select every host shown"
                      checked={rows.length > 0 && rows.every((h) => picked.has(h.id))}
                      onChange={() =>
                        setPicked(
                          rows.every((h) => picked.has(h.id))
                            ? new Set()
                            : new Set(rows.map((h) => h.id)),
                        )
                      }
                      className="h-3.5 w-3.5 cursor-pointer align-middle accent-[rgb(var(--c-accent))]"
                    />
                  </th>
                  <SortHeader column="status" label="Status" sort={sort} onSort={onSort} />
                  <SortHeader column="ip" label="IP" sort={sort} onSort={onSort} />
                  <SortHeader column="mac" label="MAC / vendor" sort={sort} onSort={onSort} />
                  <SortHeader column="hostname" label="Hostname" sort={sort} onSort={onSort} />
                  <SortHeader column="os" label="OS" sort={sort} onSort={onSort} />
                  <SortHeader column="network" label="Network" sort={sort} onSort={onSort} />
                  <th>Discovered by</th>
                  <SortHeader column="last_seen" label="Last seen" sort={sort} onSort={onSort} />
                </tr>
              </thead>
              <tbody>
                {rows.map((h) => (
                  <tr
                    key={h.id}
                    onClick={() => setSelected(h)}
                    // A skipped host stays on this screen, because this is
                    // where it gets put back in scope, but it is recessed so
                    // it is never mistaken for one still in play.
                    className={cn(
                      'cursor-pointer',
                      h.triage?.status === 'skipped' && SKIPPED_ROW_CLASS,
                    )}
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelected(h)
                      }
                    }}
                  >
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${h.ip}`}
                        checked={picked.has(h.id)}
                        onChange={() => togglePicked(h.id)}
                        className="h-3.5 w-3.5 cursor-pointer align-middle accent-[rgb(var(--c-accent))]"
                      />
                    </td>
                    <td className="w-[122px]" onClick={(e) => e.stopPropagation()}>
                      <TriageSelect
                        value={h.triage?.status}
                        busy={busy === h.id}
                        onChange={(status) => void setStatus(h, { status })}
                      />
                    </td>
                    <td>
                      <Mono className="font-medium">{h.ip}</Mono>
                    </td>
                    <td className="text-muted">
                      {h.mac ? <Mono>{h.mac}</Mono> : '-'}
                      {h.vendor && (
                        <span className="ml-1.5 text-faint" title={h.vendor}>
                          {h.vendor}
                        </span>
                      )}
                    </td>
                    <td>
                      {h.hostname || <span className="text-faint">-</span>}
                      {h.domain && <span className="text-faint">.{h.domain}</span>}
                    </td>
                    <td className="max-w-[220px] truncate text-muted" title={h.os}>
                      {h.os || '-'}
                    </td>
                    <td className="text-muted">{netName.get(h.network_id) ?? h.network_id}</td>
                    <td className="max-w-[240px] truncate text-xs text-muted">
                      {(h.discovered_by ?? []).join(', ') || '-'}
                    </td>
                    <td className="text-muted">
                      <RelativeTime value={h.last_seen} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <HostDrawer
        host={selected}
        networkName={selected ? (netName.get(selected.network_id) ?? '') : ''}
        onClose={() => setSelected(null)}
        onTriage={(host, body) => void setStatus(host, body)}
        busy={!!selected && busy === selected.id}
      />
    </PageContainer>
  )
}
