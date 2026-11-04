import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMatrix, useNetworks, useReach } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, PageHeader } from '@/components/ui/Card'
import { Drawer } from '@/components/ui/Modal'
import { EmptyState, ErrorState, InlineAlert, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, ReachBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import { Mono, RelativeTime, SearchInput, Tabs } from '@/components/common'
import {
  TechniqueBadge,
  TechniqueDetail,
  TechniqueFlags,
  TechniqueHelpLink,
} from '@/components/TechniqueDetail'
import { techniqueHelpHref, useTechniqueGuides } from '@/lib/techniques'
import { cn } from '@/lib/cn'
import { compareIP, formatMs, formatNumber } from '@/lib/format'
import { BoltIcon, MatrixIcon } from '@/components/icons'
import {
  BYPASS_TECHNIQUES,
  type MatrixCell,
  type Network,
  type ReachResult,
  type ReachStatus,
} from '@/types/api'

type View = 'network' | 'service'

/** Colour + label for a network-to-network cell. Never colour alone. */
function cellStyle(cell: MatrixCell | undefined): {
  className: string
  label: string
  tone: 'crit' | 'warn' | 'ok' | 'neutral'
} {
  if (!cell || cell.tested === 0) {
    return { className: 'bg-elevated text-faint', label: 'not tested', tone: 'neutral' }
  }
  if (cell.reachable > 0) {
    const ratio = cell.reachable / Math.max(1, cell.tested)
    return {
      className: cn(
        'text-crit',
        ratio > 0.5 ? 'bg-crit/25' : ratio > 0.15 ? 'bg-crit/15' : 'bg-crit/10',
      ),
      label: 'reachable',
      tone: 'crit',
    }
  }
  if (cell.closed > 0) {
    return { className: 'bg-warn/12 text-warn', label: 'routed, ports closed', tone: 'warn' }
  }
  return { className: 'bg-ok/12 text-ok', label: 'filtered', tone: 'ok' }
}

const STATUS_RANK: Record<ReachStatus, number> = {
  reachable: 5,
  closed: 4,
  sent: 3,
  filtered: 2,
  unreachable: 1,
  error: 0,
}

export default function MatrixPage() {
  const missionId = useMissionId()
  const matrix = useMatrix(missionId)
  const networksQuery = useNetworks(missionId)
  const reach = useReach(missionId)
  const [view, setView] = useState<View>('network')
  const [drill, setDrill] = useState<{ source: number; target: number } | null>(null)
  const [explained, setExplained] = useState<number | null>(null)
  const [query, setQuery] = useState('')
  const guides = useTechniqueGuides()

  const networks: Network[] = useMemo(() => {
    const fromMatrix = matrix.data?.networks ?? []
    return fromMatrix.length > 0 ? fromMatrix : (networksQuery.data ?? [])
  }, [matrix.data, networksQuery.data])

  const netName = (id: number) => networks.find((n) => n.id === id)?.name ?? `network ${id}`

  const cells = matrix.data?.cells ?? []
  const cellOf = (source: number, target: number) =>
    cells.find((c) => c.source_network_id === source && c.target_network_id === target)

  const results = reach.data ?? []

  const drillResults = useMemo(() => {
    if (!drill) return []
    return results
      .filter(
        (r) =>
          r.source_network_id === drill.source && r.target_network_id === drill.target,
      )
      .sort((a, b) => {
        const d = STATUS_RANK[b.status] - STATUS_RANK[a.status]
        if (d !== 0) return d
        const ip = compareIP(a.ip, b.ip)
        return ip !== 0 ? ip : (a.port ?? 0) - (b.port ?? 0)
      })
  }, [results, drill])

  // --- service level ------------------------------------------------------
  interface ServiceRow {
    key: string
    ip: string
    port?: number
    protocol?: string
    targetNetworkId: number
    bySource: Map<number, ReachResult[]>
  }

  const serviceRows = useMemo<ServiceRow[]>(() => {
    const map = new Map<string, ServiceRow>()
    for (const r of results) {
      const key = `${r.target_network_id}|${r.ip}|${r.port ?? 0}|${r.protocol ?? ''}`
      let row = map.get(key)
      if (!row) {
        row = {
          key,
          ip: r.ip,
          port: r.port,
          protocol: r.protocol,
          targetNetworkId: r.target_network_id,
          bySource: new Map(),
        }
        map.set(key, row)
      }
      const list = row.bySource.get(r.source_network_id) ?? []
      list.push(r)
      row.bySource.set(r.source_network_id, list)
    }
    const q = query.trim().toLowerCase()
    return [...map.values()]
      .filter(
        (row) =>
          !q ||
          row.ip.includes(q) ||
          String(row.port ?? '').includes(q) ||
          netName(row.targetNetworkId).toLowerCase().includes(q),
      )
      .sort((a, b) => {
        if (a.targetNetworkId !== b.targetNetworkId) return a.targetNetworkId - b.targetNetworkId
        const ip = compareIP(a.ip, b.ip)
        return ip !== 0 ? ip : (a.port ?? 0) - (b.port ?? 0)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [results, query, networks])

  const sourceNetworks = useMemo(() => {
    const ids = new Set(results.map((r) => r.source_network_id))
    const fromResults = networks.filter((n) => ids.has(n.id))
    return fromResults.length > 0 ? fromResults : networks
  }, [results, networks])

  const bestOf = (list: ReachResult[] | undefined): ReachResult | undefined => {
    if (!list || list.length === 0) return undefined
    return [...list].sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status])[0]
  }

  const totalReachable = cells.reduce((n, c) => n + c.reachable, 0)
  const totalTested = cells.reduce((n, c) => n + c.tested, 0)
  const bypassHits = results.filter(
    (r) => r.status === 'reachable' && BYPASS_TECHNIQUES.has(r.technique),
  )

  const loading = matrix.isLoading || networksQuery.isLoading

  return (
    <PageContainer wide>
      <PageHeader
        title="Segmentation matrix"
        description="Which networks can reach which, measured - not assumed. Each cell counts the services retried from the source network against the target network."
        actions={
          <LinkButton to="../exports" variant="secondary">
            Export the matrix
          </LinkButton>
        }
      />

      {loading ? (
        <Card className="mt-5">
          <TableSkeleton rows={6} columns={6} />
        </Card>
      ) : matrix.isError ? (
        <Card className="mt-5">
          <ErrorState
            title="Could not load the matrix"
            error={matrix.error}
            retry={() => void matrix.refetch()}
          />
        </Card>
      ) : networks.length === 0 || totalTested === 0 ? (
        <Card className="mt-5">
          <EmptyState
            icon={<MatrixIcon width={20} height={20} />}
            title="No segmentation result yet"
            description="Plug into one VLAN, declare it as a network, then launch a segmentation scan: NETY replays every service discovered on the other networks from where you stand and fills this grid live."
            action={
              <LinkButton to="../scans/new?kind=segmentation" variant="primary">
                Launch a segmentation scan
              </LinkButton>
            }
          />
        </Card>
      ) : (
        <>
          <div className="mt-5 grid gap-3 sm:grid-cols-3">
            <div className="card px-4 py-3">
              <div className="panel-title">Tested</div>
              <div className="tabular mt-1 text-2xl font-semibold">
                {formatNumber(totalTested)}
              </div>
              <div className="text-xs text-muted">service × technique attempts</div>
            </div>
            <div className="card px-4 py-3">
              <div className="panel-title">Reachable across a boundary</div>
              <div
                className={cn(
                  'tabular mt-1 text-2xl font-semibold',
                  totalReachable > 0 ? 'text-crit' : 'text-ok',
                )}
              >
                {formatNumber(totalReachable)}
              </div>
              <div className="text-xs text-muted">
                {totalTested > 0
                  ? `${((totalReachable / totalTested) * 100).toFixed(1)}% of attempts`
                  : '-'}
              </div>
            </div>
            <div className="card px-4 py-3">
              <div className="panel-title">Through a bypass technique</div>
              <div
                className={cn(
                  'tabular mt-1 text-2xl font-semibold',
                  bypassHits.length > 0 ? 'text-warn' : 'text-ok',
                )}
              >
                {formatNumber(bypassHits.length)}
              </div>
              <div className="text-xs text-muted">
                source-port, fragment, IPv6, alternate route or 802.1Q -{' '}
                <Link to="/help" className="text-accent underline-offset-2 hover:underline">
                  what these are
                </Link>
              </div>
            </div>
          </div>

          {bypassHits.length > 0 && (
            <InlineAlert tone="warn" className="mt-4" icon={<BoltIcon />} title="Filtering bypassed">
              {bypassHits.length} result{bypassHits.length > 1 ? 's were' : ' was'} obtained with
              a technique other than plain routing - the filtering exists but can be walked
              around. Every detail view names the technique that got through; click it to read
              what it does and how to reproduce it by hand, or browse{' '}
              <Link to="/help" className="underline underline-offset-2">
                the technique reference
              </Link>
              .
            </InlineAlert>
          )}

          <div className="mt-5">
            <Tabs<View>
              active={view}
              onChange={setView}
              tabs={[
                { id: 'network', label: 'Network × network' },
                { id: 'service', label: 'Service × source network', count: serviceRows.length },
              ]}
            />
          </div>

          {view === 'network' ? (
            <Card className="mt-4">
              <CardHeader
                title="Source network → target network"
                description="Rows: where you were plugged in. Columns: the network whose services were retried. Click a cell for the individual results."
              />
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th className="sticky left-0 z-20 bg-surface">From ↓ / To →</th>
                      {networks.map((n) => (
                        <th key={n.id} className="min-w-[150px]">
                          {n.name}
                          {n.vlan_id ? (
                            <span className="ml-1 font-normal text-faint">
                              VLAN {n.vlan_id}
                            </span>
                          ) : null}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {networks.map((src) => (
                      <tr key={src.id}>
                        <th
                          scope="row"
                          className="sticky left-0 z-10 whitespace-nowrap border-b border-border bg-surface px-3 py-2 text-left text-sm font-medium"
                        >
                          {src.name}
                          {src.vlan_id ? (
                            <span className="ml-1 text-xs font-normal text-faint">
                              VLAN {src.vlan_id}
                            </span>
                          ) : null}
                        </th>
                        {networks.map((dst) => {
                          if (src.id === dst.id) {
                            return (
                              <td
                                key={dst.id}
                                className="bg-bg/60 text-center text-xs text-faint"
                              >
                                same network
                              </td>
                            )
                          }
                          const cell = cellOf(src.id, dst.id)
                          const style = cellStyle(cell)
                          const used = Object.entries(cell?.by_technique ?? {}).filter(
                            ([, v]) => v > 0,
                          )
                          const bypassUsed = used
                            .filter(([t]) => BYPASS_TECHNIQUES.has(t))
                            .map(([t]) => guides.byId(t).title)
                          const viaBypass = bypassUsed.length > 0
                          return (
                            <td key={dst.id} className="p-0">
                              <button
                                type="button"
                                disabled={!cell || cell.tested === 0}
                                onClick={() => {
                                  setExplained(null)
                                  setDrill({ source: src.id, target: dst.id })
                                }}
                                className={cn(
                                  'h-full w-full px-3 py-2 text-left transition-colors',
                                  style.className,
                                  cell && cell.tested > 0
                                    ? 'cursor-pointer hover:brightness-125'
                                    : 'cursor-default',
                                )}
                                title={
                                  cell
                                    ? `${cell.reachable} reachable, ${cell.closed} closed, ${cell.filtered} filtered of ${cell.tested} tested` +
                                      (viaBypass
                                        ? `. Crossed with: ${bypassUsed.join(', ')}`
                                        : '')
                                    : 'Not tested'
                                }
                              >
                                {!cell || cell.tested === 0 ? (
                                  <span className="text-xs">not tested</span>
                                ) : (
                                  <>
                                    <span className="tabular block text-sm font-semibold">
                                      {formatNumber(cell.reachable)} / {formatNumber(cell.tested)}
                                    </span>
                                    <span className="block text-[11px] font-medium">
                                      {style.label}
                                    </span>
                                    <span className="mt-0.5 block text-[11px] text-muted">
                                      {formatNumber(cell.closed)} closed ·{' '}
                                      {formatNumber(cell.filtered)} filtered
                                    </span>
                                    {viaBypass && (
                                      <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-warn">
                                        <BoltIcon width={9} height={9} />
                                        via {bypassUsed[0]}
                                        {bypassUsed.length > 1
                                          ? ` +${bypassUsed.length - 1}`
                                          : ''}
                                      </span>
                                    )}
                                  </>
                                )}
                              </button>
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="flex flex-wrap items-center gap-4 border-t border-border px-4 py-2.5 text-xs text-muted">
                <span className="font-medium">Legend:</span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-crit/25" aria-hidden="true" />
                  reachable - segmentation does not hold
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-warn/20" aria-hidden="true" />
                  routed but closed - packets cross, ports are shut
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-ok/20" aria-hidden="true" />
                  filtered - blocked
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm bg-elevated" aria-hidden="true" />
                  not tested
                </span>
              </div>
            </Card>
          ) : (
            <Card className="mt-4">
              <CardHeader
                title="Service × source network"
                description="One row per service discovered on another VLAN; one column per position you tested from."
                actions={
                  <SearchInput
                    value={query}
                    onChange={setQuery}
                    placeholder="IP, port, network…"
                    className="w-56"
                  />
                }
              />
              {serviceRows.length === 0 ? (
                <EmptyState
                  title="No individual result"
                  description="Run a segmentation scan to populate this view."
                />
              ) : (
                <div className="table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th className="sticky left-0 z-20 bg-surface">Service</th>
                        <th>Target network</th>
                        {sourceNetworks.map((n) => (
                          <th key={n.id} className="min-w-[130px]">
                            from {n.name}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {serviceRows.slice(0, 500).map((row) => (
                        <tr key={row.key}>
                          <td className="sticky left-0 z-10 bg-surface">
                            <Mono className="font-medium">
                              {row.ip}
                              {row.port ? `:${row.port}` : ''}
                            </Mono>
                            {row.protocol && (
                              <span className="ml-1 text-xs text-faint">/{row.protocol}</span>
                            )}
                          </td>
                          <td className="text-muted">{netName(row.targetNetworkId)}</td>
                          {sourceNetworks.map((n) => {
                            const list = row.bySource.get(n.id)
                            const best = bestOf(list)
                            if (!best) {
                              return (
                                <td key={n.id} className="text-xs text-faint">
                                  not tested
                                </td>
                              )
                            }
                            const bypass = BYPASS_TECHNIQUES.has(best.technique)
                            const t = guides.byId(best.technique)
                            return (
                              <td key={n.id}>
                                <span className="flex flex-wrap items-center gap-1">
                                  <ReachBadge status={best.status} />
                                  {bypass && best.status === 'reachable' && (
                                    <Link
                                      to={techniqueHelpHref(t.id)}
                                      title={`Reached with the ${t.title} technique, not plain routing. ${t.notes?.short ?? ''} Click to read how it works.`}
                                    >
                                      <TechniqueBadge t={t} />
                                    </Link>
                                  )}
                                </span>
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {serviceRows.length > 500 && (
                    <p className="px-4 py-2 text-xs text-faint">
                      Showing the first 500 of {formatNumber(serviceRows.length)} rows - narrow
                      the search to see the rest.
                    </p>
                  )}
                </div>
              )}
            </Card>
          )}
        </>
      )}

      <Drawer
        open={!!drill}
        onClose={() => {
          setDrill(null)
          setExplained(null)
        }}
        width="lg"
        title={
          drill ? `${netName(drill.source)} → ${netName(drill.target)}` : ''
        }
        subtitle={`${drillResults.length} individual results - click a technique to see how that flow got through`}
      >
        {drillResults.length === 0 ? (
          <p className="text-sm text-muted">
            No individual result stored for this pair. The aggregate counters come from the
            matrix endpoint; the detailed results may have been pruned.
          </p>
        ) : (
          <div className="table-scroll rounded-md border border-border">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Port</th>
                  <th>How it was obtained</th>
                  <th>Status</th>
                  <th>RTT</th>
                  <th>Detail</th>
                  <th>Tested</th>
                </tr>
              </thead>
              <tbody>
                {drillResults.map((r) => {
                  const t = guides.byId(r.technique)
                  const open = explained === r.id
                  return (
                    <Fragment key={r.id}>
                      <tr>
                        <td>
                          <Mono>{r.ip}</Mono>
                        </td>
                        <td className="tabular">
                          {r.port ? `${r.port}/${r.protocol ?? 'tcp'}` : '-'}
                        </td>
                        <td>
                          <span className="flex items-center gap-1.5">
                            <TechniqueBadge
                              t={t}
                              expanded={open}
                              onToggle={() => setExplained(open ? null : r.id)}
                            />
                            {r.vlan_id ? <Badge tone="accent">vlan {r.vlan_id}</Badge> : null}
                          </span>
                        </td>
                        <td>
                          <ReachBadge status={r.status} />
                        </td>
                        <td className="tabular text-muted">
                          {r.rtt_ms ? formatMs(r.rtt_ms) : '-'}
                        </td>
                        <td className="max-w-[220px] truncate text-muted" title={r.detail}>
                          {r.detail || '-'}
                        </td>
                        <td className="text-muted">
                          <RelativeTime value={r.tested_at} />
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={7} className="whitespace-normal bg-elevated p-0">
                            {/* Pinned to the left and capped: the table is
                                wider than the drawer, and prose must not run
                                off the side of it. */}
                            <div className="sticky left-0 max-w-[40rem] space-y-3 px-4 py-3">
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <h4 className="whitespace-normal text-sm font-semibold text-fg">
                                  How this crossed: {t.title}{' '}
                                  <Mono className="ml-1 font-normal text-faint">{t.id}</Mono>
                                </h4>
                                <TechniqueFlags t={t} />
                              </div>
                              <p className="whitespace-normal text-sm">
                                <span className="text-muted">On the wire: </span>
                                <Mono>
                                  {netName(r.source_network_id)} -&gt; {r.ip}
                                  {r.port ? `:${r.port}/${r.protocol ?? 'tcp'}` : ''}
                                </Mono>{' '}
                                <span className="text-muted">
                                  answered {r.status}
                                  {r.rtt_ms ? ` in ${formatMs(r.rtt_ms)}` : ''}
                                  {r.detail ? `, ${r.detail}` : ''}.
                                </span>
                              </p>
                              <TechniqueDetail t={t} />
                              <TechniqueHelpLink t={t} />
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Drawer>
    </PageContainer>
  )
}
