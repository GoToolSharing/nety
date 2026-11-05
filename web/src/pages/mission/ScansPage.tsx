import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useDeleteScan, useNetworks, useScans } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, PageHeader } from '@/components/ui/Card'
import { IconButton, LinkButton } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/Modal'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { ScanStatusBadge } from '@/components/ui/Badge'
import { FilterChips, ProgressBar, RelativeTime, SearchInput } from '@/components/common'
import ScanControls from '@/components/scan/ScanControls'
import { useToast } from '@/components/ui/Toast'
import { formatDuration, formatNumber, formatPercent } from '@/lib/format'
import { PlusIcon, ScanIcon, TrashIcon } from '@/components/icons'
import type { Scan, ScanStatus } from '@/types/api'

type StatusFilter = 'all' | 'active' | ScanStatus

/**
 * What the scan is busy with. It used to sit under the status badge, where it
 * repeated what the row already says under the scan number and stretched the
 * column. It is the progress bar's tooltip now, and the detail page shows the
 * phases in full.
 */
function progressTitle(s: Scan): string {
  const pct = `${formatPercent(s.progress)} done`
  if (s.status !== 'running' && s.status !== 'paused') return pct
  const parts = [s.phase || s.status]
  if (s.status === 'running' && s.eta_seconds) parts.push(`ETA ${formatDuration(s.eta_seconds)}`)
  return `${pct} · ${parts.join(' · ')}`
}

export default function ScansPage() {
  const missionId = useMissionId()
  const navigate = useNavigate()
  const { canWrite } = useAuth()
  const toast = useToast()
  const scans = useScans(missionId)
  const networks = useNetworks(missionId)
  const remove = useDeleteScan(missionId)

  const [filter, setFilter] = useState<StatusFilter>('all')
  const [query, setQuery] = useState('')
  const [deleting, setDeleting] = useState<Scan | null>(null)

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const list = scans.data ?? []

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: list.length, active: 0 }
    for (const s of list) {
      c[s.status] = (c[s.status] ?? 0) + 1
      if (s.status === 'running' || s.status === 'queued' || s.status === 'paused') c.active++
    }
    return c
  }, [list])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return list
      .filter((s) => {
        if (filter === 'all') return true
        if (filter === 'active')
          return s.status === 'running' || s.status === 'queued' || s.status === 'paused'
        return s.status === filter
      })
      .filter((s) => {
        if (!q) return true
        return (
          String(s.id).includes(q) ||
          s.kind.includes(q) ||
          (netName.get(s.network_id) ?? '').toLowerCase().includes(q) ||
          (s.options?.profile ?? '').toLowerCase().includes(q)
        )
      })
      .sort((a, b) => b.id - a.id)
  }, [list, filter, query, netName])

  return (
    <PageContainer>
      <PageHeader
        title="Scans"
        description="Every scan is resumable: pausing keeps the work units, and the server picks up exactly where it stopped - even after a crash."
        actions={
          canWrite && (
            <LinkButton to="../scans/new" variant="primary" icon={<PlusIcon />}>
              New scan
            </LinkButton>
          )
        }
      />

      <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
        <FilterChips<StatusFilter>
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: 'All', count: counts.all },
            { value: 'active', label: 'Active', count: counts.active },
            { value: 'paused', label: 'Paused', count: counts.paused ?? 0 },
            { value: 'completed', label: 'Completed', count: counts.completed ?? 0 },
            { value: 'failed', label: 'Failed', count: counts.failed ?? 0 },
            { value: 'cancelled', label: 'Stopped', count: counts.cancelled ?? 0 },
          ]}
        />
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Filter by id, kind, network…"
          className="w-full max-w-xs"
        />
      </div>

      <Card className="mt-4">
        {scans.isLoading ? (
          <TableSkeleton rows={6} columns={6} />
        ) : scans.isError ? (
          <ErrorState
            title="Could not load the scans"
            error={scans.error}
            retry={() => void scans.refetch()}
          />
        ) : visible.length === 0 ? (
          <EmptyState
            icon={<ScanIcon width={20} height={20} />}
            title={list.length === 0 ? 'No scan yet' : 'No scan matches that filter'}
            description={
              list.length === 0
                ? 'Start with a discovery scan on the network you are plugged into: host discovery, port scan, service fingerprinting, identity collection and light checks, all streaming live.'
                : 'Change the status filter or clear the search.'
            }
            action={
              list.length === 0 &&
              canWrite && (
                <LinkButton to="../scans/new" variant="primary" icon={<PlusIcon />}>
                  Launch the first scan
                </LinkButton>
              )
            }
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Network</th>
                  <th>Status</th>
                  <th className="w-[170px]">Progress</th>
                  <th className="text-right">Hosts</th>
                  <th className="text-right">Services</th>
                  <th className="text-right">Findings</th>
                  <th>Started</th>
                  {/* Three labelled buttons used to live here and the column
                      had to be pinned to the right edge to stay reachable,
                      which cropped the column before it. Icons fit, so the
                      column travels with the table again. */}
                  <th className="w-px text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((s) => (
                  <tr
                    key={s.id}
                    // The whole row opens the scan. The number stays a real
                    // link so middle click and "open in a new tab" still work,
                    // and the actions cell stops the click before it gets
                    // here.
                    onClick={() => navigate(`../scans/${s.id}`)}
                    className="cursor-pointer"
                  >
                    <td>
                      <Link
                        to={`../scans/${s.id}`}
                        className="font-medium hover:underline"
                        title={`Profile: ${s.options?.profile ?? '-'}`}
                        onClick={(e) => e.stopPropagation()}
                      >
                        #{s.id}
                      </Link>
                      <div className="text-xs capitalize text-muted">
                        {s.kind}
                        {s.options?.profile ? ` · ${s.options.profile}` : ''}
                      </div>
                    </td>
                    <td className="text-muted">
                      {netName.get(s.network_id) ?? `network ${s.network_id}`}
                    </td>
                    <td>
                      {/* One badge, never two. "resumable" said what the
                          Resume control next to it already says, and the
                          second badge was what made this column wide. */}
                      <ScanStatusBadge status={s.status} />
                      {s.error && (
                        <div
                          className="mt-0.5 max-w-[200px] truncate text-xs text-crit"
                          title={s.error}
                        >
                          {s.error}
                        </div>
                      )}
                    </td>
                    <td className="align-middle" title={progressTitle(s)}>
                      {/* One line, vertically centred: bar and percentage and
                          nothing else, so the bar lines up with the status
                          badge and the counts on either side of it. */}
                      <div className="flex w-[150px] items-center gap-2">
                        <ProgressBar
                          value={s.progress}
                          height="h-1.5"
                          className="min-w-0 flex-1"
                          striped={s.status === 'running'}
                          tone={
                            s.status === 'running'
                              ? 'accent'
                              : s.status === 'paused'
                                ? 'warn'
                                : s.status === 'completed'
                                  ? 'ok'
                                  : s.status === 'failed'
                                    ? 'crit'
                                    : 'muted'
                          }
                          label={`Scan ${s.id}`}
                        />
                        <span className="tabular w-9 shrink-0 text-right text-[11px] text-muted">
                          {formatPercent(s.progress)}
                        </span>
                      </div>
                    </td>
                    <td className="tabular text-center">{formatNumber(s.stats?.hosts_up ?? 0)}</td>
                    <td className="tabular text-center">{formatNumber(s.stats?.services ?? 0)}</td>
                    <td className="tabular text-center">
                      {formatNumber(s.stats?.findings ?? 0)}
                    </td>
                    <td className="text-muted">
                      <RelativeTime value={s.started_at ?? s.created_at} />
                    </td>
                    {/* A click on a control must not also open the scan. */}
                    <td onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        {canWrite && (
                          <ScanControls
                            scan={s}
                            missionId={missionId}
                            compact
                            showRetry={false}
                          />
                        )}
                        {/* The bin keeps its slot on a running scan, where it
                            is not offered, so it stays in one column down the
                            whole table. */}
                        <div className="w-8 shrink-0">
                          {canWrite && s.status !== 'running' && (
                            <IconButton
                              label={`Delete scan ${s.id}`}
                              className="hover:bg-crit/15 hover:text-crit"
                              onClick={() => setDeleting(s)}
                            >
                              <TrashIcon />
                            </IconButton>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        destructive
        title={`Delete scan #${deleting?.id}?`}
        confirmLabel="Delete scan"
        busy={remove.isPending}
        body="The scan, its work units and its log are removed. Hosts, services and findings it produced stay in the mission."
        onConfirm={async () => {
          if (!deleting) return
          try {
            await remove.mutateAsync(deleting.id)
            toast.success('Scan deleted')
            setDeleting(null)
          } catch (err) {
            toast.error('Could not delete the scan', err)
          }
        }}
      />

      {visible.length > 0 && (
        <p className="mt-3 text-xs text-faint">
          Tip: click a row to open the scan.
          {canWrite && (
            <>
              {' '}
              A paused scan offers <strong className="text-muted">Resume</strong>, never a
              restart - it replays only the pending work units.
            </>
          )}
        </p>
      )}
    </PageContainer>
  )
}
