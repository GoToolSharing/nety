import { useCallback, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useHost, useHosts, useNetworks } from '@/lib/queries'
import { useDebounced, useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, KeyValue, PageHeader } from '@/components/ui/Card'
import { Drawer } from '@/components/ui/Modal'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, PortStateBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import {
  AddressFilterInput,
  CopyButton,
  Mono,
  RelativeTime,
  SearchInput,
  SortHeader,
  useSort,
} from '@/components/common'
import ServiceDetail from '@/components/ServiceDetail'
import { SKIPPED_ROW_CLASS, SkipToggle, TriageNote } from '@/components/Triage'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import { formatNumber, isAddressOrPrefix } from '@/lib/format'
import { HostIcon } from '@/components/icons'
import type { Host, Service, TriageStatus } from '@/types/api'

/**
 * The columns the hosts table can be sorted by. Each one is a key the server
 * knows (see hostSorts in internal/store/results.go): the order is decided in
 * SQL so it covers the whole listing.
 */
type SortKey = 'ip' | 'hostname' | 'os' | 'mac' | 'status' | 'network' | 'last_seen'

function HostDrawer({
  host,
  networkName,
  onClose,
  onTriage,
}: {
  host: Host | null
  networkName: string
  onClose: () => void
  onTriage: (host: Host, body: { status?: TriageStatus; note?: string }) => void
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
            {/* Notes only. In or out of scope is set on the row this pane
                opened from, so there is one control for it, not two. */}
            <section className="mb-4">
              <h3 className="panel-title mb-1.5">Your notes</h3>
              <TriageNote
                value={host.triage?.note ?? ''}
                onSave={(note) => onTriage(host, { note })}
                placeholder="Why is this address skipped, or what is left to test on it?"
              />
              {host.triage?.updated_at && (
                <p className="mt-1.5 text-[11px] text-faint">
                  Last changed by {host.triage.updated_by_name || 'someone'},{' '}
                  <RelativeTime value={host.triage.updated_at} />
                </p>
              )}
              {host.triage?.status === 'skipped' && (
                <p className="mt-1.5 text-xs text-muted">
                  This address is out of the way: its services, its findings and the
                  segmentation tests aimed at it are hidden from the other screens.
                  Nothing was deleted, and nothing written on them was touched.
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
                {host.vendor ? (
                  <span className="text-muted"> · {host.vendor}</span>
                ) : null}
              </KeyValue>
              <KeyValue label="Hostname">
                {host.hostname || '-'}
                {(host.hostnames ?? []).length > 1 && (
                  <span className="text-muted">
                    {' '}
                    ({(host.hostnames ?? []).join(', ')})
                  </span>
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
        title={
          openService
            ? `${openService.ip}:${openService.port}/${openService.protocol}`
            : ''
        }
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
  const [query, setQuery] = useState('')
  const [address, setAddress] = useState('')
  const { sort, onSort } = useSort<SortKey>('ip')
  const debouncedAddress = useDebounced(address, 300)
  // Half a typed subnet is not a filter yet, so it is not sent: the table
  // keeps showing what it had instead of emptying at every keystroke.
  const hosts = useHosts(missionId, {
    network_id: networkId || undefined,
    ip: isAddressOrPrefix(debouncedAddress) ? debouncedAddress.trim() : undefined,
    sort: sort.key,
    dir: sort.dir,
  })
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
        toast.success(
          status === 'skipped'
            ? `${res.updated} addresses skipped`
            : `${res.updated} addresses back in scope`,
        )
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

  // The rows arrive filtered by address and already in the order the header
  // asks for; the search box narrows what is on screen without going back to
  // the server, because the hosts of a mission are not paged.
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return hosts.data ?? []
    return (hosts.data ?? []).filter(
      (h) =>
        h.ip.includes(q) ||
        (h.hostname ?? '').toLowerCase().includes(q) ||
        (h.mac ?? '').toLowerCase().includes(q) ||
        (h.vendor ?? '').toLowerCase().includes(q) ||
        (h.os ?? '').toLowerCase().includes(q) ||
        (h.domain ?? '').toLowerCase().includes(q),
    )
  }, [hosts.data, query])

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
        <AddressFilterInput value={address} onChange={setAddress} />
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
          <button
            type="button"
            onClick={() => void setSelectionStatus('skipped')}
            className="rounded border border-border bg-surface px-2 py-0.5 text-[11px] text-fg hover:border-border-strong"
          >
            Skip
          </button>
          <button
            type="button"
            onClick={() => void setSelectionStatus('todo')}
            className="rounded border border-border bg-surface px-2 py-0.5 text-[11px] text-fg hover:border-border-strong"
          >
            Bring back in scope
          </button>
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
            title={
              query || address ? 'No host matches that filter' : 'No host discovered yet'
            }
            description={
              query || address
                ? 'Clear the search, widen the address filter or pick another network.'
                : 'Launch a discovery scan on one of your networks: hosts appear here as soon as they answer, without waiting for the scan to finish.'
            }
            action={
              !query &&
              !address && (
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
                  <SortHeader column="status" label="Scope" sort={sort} onSort={onSort} />
                  <SortHeader column="ip" label="IP" sort={sort} onSort={onSort} />
                  <SortHeader
                    column="mac"
                    label="MAC / vendor"
                    sort={sort}
                    onSort={onSort}
                  />
                  <SortHeader
                    column="hostname"
                    label="Hostname"
                    sort={sort}
                    onSort={onSort}
                  />
                  <SortHeader column="os" label="OS" sort={sort} onSort={onSort} />
                  <SortHeader
                    column="network"
                    label="Network"
                    sort={sort}
                    onSort={onSort}
                  />
                  <th>Discovered by</th>
                  <SortHeader
                    column="last_seen"
                    label="Last seen"
                    sort={sort}
                    onSort={onSort}
                  />
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
                    <td className="w-[112px]" onClick={(e) => e.stopPropagation()}>
                      <SkipToggle
                        status={h.triage?.status}
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
                    <td className="text-muted">
                      {netName.get(h.network_id) ?? h.network_id}
                    </td>
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
      />
    </PageContainer>
  )
}
