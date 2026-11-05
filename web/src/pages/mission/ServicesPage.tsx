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
import {
  AddressFilterInput,
  Mono,
  Pagination,
  RelativeTime,
  SearchInput,
  SelectAllCheckbox,
  SortHeader,
  useSort,
} from '@/components/common'
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
import { isAddressOrPrefix } from '@/lib/format'
import type { Service, TriageStatus } from '@/types/api'

const PAGE_SIZE = 50

/** The ceiling the server puts on one listing and on one bulk triage call. */
const SERVER_MAX = 5000

/**
 * The columns the services table can be sorted by. Each one is a key the
 * server knows (see serviceSorts in internal/store/results.go): the sort runs
 * in SQL over the whole listing, not over the fifty rows on screen.
 */
type SortKey =
  | 'ip'
  | 'port'
  | 'state'
  | 'service'
  | 'product'
  | 'status'
  | 'network'
  | 'last_seen'

export default function ServicesPage() {
  const missionId = useMissionId()
  const networks = useNetworks(missionId)

  const [query, setQuery] = useState('')
  const [address, setAddress] = useState('')
  const [networkId, setNetworkId] = useState(0)
  const [protocol, setProtocol] = useState('')
  const [port, setPort] = useState('')
  const { sort, onSort } = useSort<SortKey>('ip')
  const [offset, setOffset] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const [triage, setTriage] = useState<TriageStatus[]>([])
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [selectingAll, setSelectingAll] = useState(false)
  const [busy, setBusy] = useState<number | null>(null)
  // The services of a skipped host are out of the way by default. This is the
  // operator asking to see them anyway.
  const [showSkipped, setShowSkipped] = useState(false)

  const qc = useQueryClient()
  const toast = useToast()

  const summary = useTriageSummary(missionId, networkId)

  // Only needed to recess the rows of a skipped host, so it is not fetched
  // until those rows are on screen.
  const hosts = useHosts(missionId, { network_id: networkId || undefined }, showSkipped)
  const skippedHosts = useMemo(() => {
    const ids = new Set<number>()
    for (const h of hosts.data ?? []) {
      if (h.triage?.status === 'skipped') ids.add(h.id)
    }
    return ids
  }, [hosts.data])

  const debouncedQuery = useDebounced(query, 300)
  const debouncedPort = useDebounced(port, 300)
  const debouncedAddress = useDebounced(address, 300)
  // Half a typed subnet is not a filter yet, so it is not sent: the table
  // keeps showing what it had instead of emptying at every keystroke.
  const ip = isAddressOrPrefix(debouncedAddress) ? debouncedAddress.trim() : undefined

  // Any filter change restarts the pagination window, and so does a sort: the
  // rows of page three are not the same rows once the order changes.
  useEffect(() => {
    setOffset(0)
    setSelected(new Set())
  }, [debouncedQuery, ip, networkId, protocol, debouncedPort, triage, showSkipped, sort])

  const params = useMemo(
    () => ({
      q: debouncedQuery.trim() || undefined,
      ip,
      network_id: networkId || undefined,
      protocol: protocol || undefined,
      port: debouncedPort ? Number(debouncedPort) : undefined,
      triage: triage.length ? triage.join(',') : undefined,
      include_skipped: showSkipped || undefined,
      sort: sort.key,
      dir: sort.dir,
      limit: PAGE_SIZE,
      offset,
    }),
    [
      debouncedQuery,
      ip,
      networkId,
      protocol,
      debouncedPort,
      triage,
      showSkipped,
      sort,
      offset,
    ],
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

  /**
   * Pull every service the current filter matches, not just the page on
   * screen, and select all of it. Narrowing to one port and ticking the box
   * at the head of the table reads as "all of these", and selecting fifty of
   * three hundred would be the wrong answer told confidently.
   */
  const selectEverythingMatching = useCallback(async () => {
    setSelectingAll(true)
    try {
      const page = await api.services(missionId, {
        ...params,
        limit: SERVER_MAX,
        offset: 0,
      })
      setSelected(new Set(page.items.map((s) => s.id)))
      if (page.has_more) {
        toast.error(
          `This filter matches more than ${formatNumber(SERVER_MAX)} services. ` +
            `The first ${formatNumber(SERVER_MAX)} are selected; narrow the filter for the rest.`,
        )
      } else {
        toast.success(`${formatNumber(page.items.length)} services selected`)
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not extend the selection')
    } finally {
      setSelectingAll(false)
    }
  }, [missionId, params, toast])

  const setSelectionStatus = useCallback(
    async (status: TriageStatus) => {
      const ids = [...selected]
      if (ids.length === 0) return
      try {
        // Batched: a filter-wide selection goes past what one call accepts.
        const BATCH = 2000
        let updated = 0
        for (let i = 0; i < ids.length; i += BATCH) {
          const res = await api.triageBulk(missionId, ids.slice(i, i + BATCH), status)
          updated += res.updated
        }
        setSelected(new Set())
        refresh()
        toast.success(
          `${formatNumber(updated)} services marked ${status.replace('_', ' ')}`,
        )
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

  const selectedOnPage = items.reduce((n, s) => (selected.has(s.id) ? n + 1 : n), 0)
  const allOnPageSelected = items.length > 0 && selectedOnPage === items.length
  // Offered only while the selection is still just this page: once it covers
  // the whole filter there is nothing left to extend.
  const canSelectBeyondPage =
    allOnPageSelected && hasMore && selected.size <= items.length

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
        <AddressFilterInput value={address} onChange={setAddress} />
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
            {formatNumber(selected.size)} selected
          </span>
          {/* The box at the head of the table reaches one page. This reaches
              the filter, which is what the operator meant when they narrowed
              the list to one port and ticked the box. */}
          {canSelectBeyondPage && (
            <button
              type="button"
              onClick={() => void selectEverythingMatching()}
              disabled={selectingAll}
              className="rounded border border-accent/50 bg-accent/10 px-2 py-0.5 text-[11px] font-medium text-accent hover:bg-accent/20 disabled:opacity-60"
            >
              {selectingAll ? 'Selecting…' : 'Select every service matching this filter'}
            </button>
          )}
          <span className="text-xs text-muted">Mark as</span>
          {(
            [
              'done',
              'flagged',
              'false_positive',
              'skipped',
              'in_progress',
              'todo',
            ] as TriageStatus[]
          ).map((s) => (
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
              query || address || networkId || protocol || port
                ? 'No service matches those filters'
                : 'No service discovered yet'
            }
            description={
              query || address || networkId || protocol || port
                ? 'Relax the filters: the search covers the service name, product, version and banner, and the address box takes a single address or a CIDR prefix.'
                : 'Run a discovery scan with service detection enabled: services appear here as each port is fingerprinted.'
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
                      <SelectAllCheckbox
                        noun="services on this page"
                        total={items.length}
                        selected={selectedOnPage}
                        onChange={(selectAll) =>
                          setSelected(
                            selectAll ? new Set(items.map((s) => s.id)) : new Set(),
                          )
                        }
                      />
                    </th>
                    <SortHeader
                      column="status"
                      label="Status"
                      sort={sort}
                      onSort={onSort}
                      className="w-[122px]"
                    />
                    <SortHeader column="ip" label="Address" sort={sort} onSort={onSort} />
                    <SortHeader column="port" label="Port" sort={sort} onSort={onSort} />
                    <SortHeader
                      column="state"
                      label="State"
                      sort={sort}
                      onSort={onSort}
                    />
                    <SortHeader
                      column="service"
                      label="Service"
                      sort={sort}
                      onSort={onSort}
                    />
                    <SortHeader
                      column="product"
                      label="Product / version"
                      sort={sort}
                      onSort={onSort}
                    />
                    <th>Details</th>
                    <SortHeader
                      column="network"
                      label="Network"
                      sort={sort}
                      onSort={onSort}
                    />
                    <SortHeader
                      column="last_seen"
                      label="Last seen"
                      sort={sort}
                      onSort={onSort}
                    />
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
                          <td
                            className="max-w-[240px] truncate text-muted"
                            title={describe(s)}
                          >
                            {describe(s) || '-'}
                          </td>
                          <td
                            className="max-w-[280px] truncate text-xs text-muted"
                            title={s.triage?.note || undefined}
                          >
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
