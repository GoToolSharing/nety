import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useHosts, useNetworks, useServices, useTriageSummary } from '@/lib/queries'
import { useDebounced, useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, PortStateBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import { Mono, Pagination, RelativeTime, SearchInput } from '@/components/common'
import ServiceDetail from '@/components/ServiceDetail'
import { formatNumber } from '@/lib/format'
import { ChevronDownIcon, ChevronRightIcon, ServiceIcon } from '@/components/icons'
import {
  SKIPPED_ROW_CLASS,
  SkippedHostsBanner,
  TriageProgress,
  TriageSelect,
} from '@/components/Triage'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import type { Service, TriageStatus } from '@/types/api'

const PAGE_SIZE = 50

export default function ServicesPage() {
  const missionId = useMissionId()
  const networks = useNetworks(missionId)

  const [query, setQuery] = useState('')
  const [networkId, setNetworkId] = useState(0)
  const [protocol, setProtocol] = useState('')
  const [port, setPort] = useState('')
  const [offset, setOffset] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [triage, setTriage] = useState<TriageStatus[]>([])
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState<number | null>(null)
  // The services of a skipped host are out of the way by default. This is the
  // operator asking to see them anyway.
  const [showSkipped, setShowSkipped] = useState(false)

  const qc = useQueryClient()
  const toast = useToast()

  const summary = useTriageSummary(missionId, networkId)

  // Only needed to recess the rows of a skipped host, so it is not fetched
  // until those rows are on screen.
  const hosts = useHosts(missionId, networkId || undefined, showSkipped)
  const skippedHosts = useMemo(() => {
    const ids = new Set<number>()
    for (const h of hosts.data ?? []) {
      if (h.triage?.status === 'skipped') ids.add(h.id)
    }
    return ids
  }, [hosts.data])

  const debouncedQuery = useDebounced(query, 300)
  const debouncedPort = useDebounced(port, 300)

  // Any filter change restarts the pagination window.
  useEffect(() => {
    setOffset(0)
    setSelected(new Set())
  }, [debouncedQuery, networkId, protocol, debouncedPort, triage, showSkipped])

  const params = useMemo(
    () => ({
      q: debouncedQuery.trim() || undefined,
      network_id: networkId || undefined,
      protocol: protocol || undefined,
      port: debouncedPort ? Number(debouncedPort) : undefined,
      triage: triage.length ? triage.join(',') : undefined,
      include_skipped: showSkipped || undefined,
      limit: PAGE_SIZE,
      offset,
    }),
    [debouncedQuery, networkId, protocol, debouncedPort, triage, showSkipped, offset],
  )

  const services = useServices(missionId, params)
  const items = services.data?.items ?? []
  const hasMore = services.data?.has_more ?? false

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const describe = (s: Service) => [s.product, s.version].filter(Boolean).join(' ')

  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: qk.servicesRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.triageSummaryRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.summary(missionId) })
  }, [qc, missionId])

  const setStatus = useCallback(
    async (service: Service, status: TriageStatus) => {
      setBusy(service.id)
      try {
        await api.triageService(service.id, { status })
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
      const ids = [...selected]
      if (ids.length === 0) return
      try {
        const res = await api.triageBulk(missionId, ids, status)
        setSelected(new Set())
        refresh()
        toast.success(`${res.updated} services marked ${status.replace('_', ' ')}`)
      } catch (e) {
        toast.error(e instanceof Error ? e.message : 'Could not update the selection')
      }
    },
    [missionId, selected, refresh, toast],
  )

  const toggleSelected = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const allOnPageSelected = items.length > 0 && items.every((s) => selected.has(s.id))

  return (
    <PageContainer wide>
      <PageHeader
        title="Services"
        description="Open ports and what answers on them. Expand a row for the banner, the TLS certificate, the HTTP response and the SSH algorithms."
      />

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Search service, product, banner…"
          className="w-full max-w-sm"
        />
        <label className="flex items-center gap-2 text-xs text-muted">
          <span>Network</span>
          <select
            value={networkId}
            onChange={(e) => setNetworkId(Number(e.target.value))}
            className="select-base"
          >
            <option value={0}>All</option>
            {(networks.data ?? []).map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs text-muted">
          <span>Protocol</span>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            className="select-base"
          >
            <option value="">Any</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs text-muted">
          <span>Port</span>
          <input
            type="number"
            min={1}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="any"
            className="input-base h-9 w-24 py-0 font-mono text-[12.5px]"
          />
        </label>
        <span className="tabular text-xs text-faint">
          {formatNumber(items.length)} shown{hasMore ? '+' : ''}
        </span>
      </div>

      {summary.data && (
        <div className="mt-4">
          <TriageProgress
            counts={summary.data.counts}
            total={summary.data.total}
            active={triage}
            onPick={(status) =>
              setTriage((prev) =>
                status === null
                  ? []
                  : prev.includes(status)
                    ? prev.filter((s) => s !== status)
                    : [...prev, status],
              )
            }
          />
        </div>
      )}

      <SkippedHostsBanner
        hidden={summary.data?.hidden}
        showing={showSkipped}
        onToggle={() => setShowSkipped((v) => !v)}
        noun="services"
        className="mt-3"
      />

      {selected.size > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="text-xs font-medium text-fg">
            {selected.size} selected
          </span>
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
            onClick={() => setSelected(new Set())}
            className="ml-auto text-[11px] text-muted hover:text-fg"
          >
            Clear selection
          </button>
        </div>
      )}

      <Card className="mt-4">
        {services.isLoading ? (
          <TableSkeleton rows={10} columns={9} />
        ) : services.isError ? (
          <ErrorState
            title="Could not load the services"
            error={services.error}
            retry={() => void services.refetch()}
          />
        ) : items.length === 0 ? (
          <EmptyState
            icon={<ServiceIcon width={20} height={20} />}
            title={
              query || networkId || protocol || port
                ? 'No service matches those filters'
                : 'No service discovered yet'
            }
            description={
              query || networkId || protocol || port
                ? 'Relax the filters: the search covers the service name, product, version and banner.'
                : 'Run a discovery scan with service detection enabled - services appear here as each port is fingerprinted.'
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
          <>
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th className="w-px" />
                    <th className="w-px">
                      <input
                        type="checkbox"
                        aria-label="Select every service on this page"
                        checked={allOnPageSelected}
                        onChange={() =>
                          setSelected(
                            allOnPageSelected ? new Set() : new Set(items.map((s) => s.id)),
                          )
                        }
                        className="h-3.5 w-3.5 cursor-pointer align-middle accent-[rgb(var(--c-accent))]"
                      />
                    </th>
                    <th className="w-[122px]">Status</th>
                    <th>Address</th>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Product / version</th>
                    <th>Details</th>
                    <th>Network</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((s) => {
                    const open = expanded === s.id
                    return (
                      <Fragment key={s.id}>
                        <tr
                          // A row only on screen because the operator asked to
                          // see a skipped host is recessed, so it is never
                          // mistaken for something still in scope.
                          className={cn(
                            'cursor-pointer',
                            skippedHosts.has(s.host_id) && SKIPPED_ROW_CLASS,
                          )}
                          onClick={() => setExpanded(open ? null : s.id)}
                        >
                          <td>
                            <button
                              type="button"
                              aria-expanded={open}
                              aria-label={open ? 'Collapse details' : 'Expand details'}
                              className="rounded p-0.5 text-faint hover:text-fg"
                              onClick={(e) => {
                                e.stopPropagation()
                                setExpanded(open ? null : s.id)
                              }}
                            >
                              {open ? <ChevronDownIcon /> : <ChevronRightIcon />}
                            </button>
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              aria-label={`Select ${s.ip} port ${s.port}`}
                              checked={selected.has(s.id)}
                              onChange={() => toggleSelected(s.id)}
                              className="h-3.5 w-3.5 cursor-pointer align-middle accent-[rgb(var(--c-accent))]"
                            />
                          </td>
                          <td onClick={(e) => e.stopPropagation()}>
                            <TriageSelect
                              value={s.triage?.status}
                              busy={busy === s.id}
                              onChange={(next) => void setStatus(s, next)}
                            />
                          </td>
                          <td>
                            <Mono className="font-medium">{s.ip}</Mono>
                          </td>
                          <td className="tabular">
                            {s.port}
                            <span className="text-faint">/{s.protocol}</span>
                          </td>
                          <td>
                            <PortStateBadge state={s.state} />
                          </td>
                          <td>
                            <span className="flex items-center gap-1.5">
                              {s.name || <span className="text-faint">unknown</span>}
                              {s.tunnel && <Badge tone="info">{s.tunnel}</Badge>}
                            </span>
                          </td>
                          <td className="max-w-[240px] truncate text-muted" title={describe(s)}>
                            {describe(s) || '-'}
                          </td>
                          <td className="max-w-[280px] truncate text-xs text-muted" title={s.triage?.note || undefined}>
                            {s.triage?.note
                              ? s.triage.note
                              : s.http?.title
                              ? s.http.title
                              : s.tls?.subject_cn
                                ? `CN=${s.tls.subject_cn}`
                                : s.ssh?.banner
                                  ? s.ssh.banner
                                  : s.banner
                                    ? s.banner.slice(0, 60)
                                    : '-'}
                          </td>
                          <td className="text-muted">
                            {netName.get(s.network_id) ?? s.network_id}
                          </td>
                          <td className="text-muted">
                            <RelativeTime value={s.last_seen} />
                          </td>
                        </tr>
                        {open && (
                          <tr>
                            <td colSpan={11} className="whitespace-normal bg-bg/60 p-4">
                              <ServiceDetail service={s} onTriaged={refresh} />
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <div className="border-t border-border">
              <Pagination
                offset={offset}
                limit={PAGE_SIZE}
                count={items.length}
                hasMore={hasMore}
                onChange={(o) => {
                  setExpanded(null)
                  setOffset(o)
                }}
              />
            </div>
          </>
        )}
      </Card>
    </PageContainer>
  )
}
