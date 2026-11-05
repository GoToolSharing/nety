import { useMemo, useState, type ReactNode } from 'react'
import { useScanDiff, useScans } from '@/lib/queries'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/Feedback'
import { SelectField } from '@/components/ui/Field'
import { Mono, RelativeTime } from '@/components/common'
import { formatNumber } from '@/lib/format'
import { cn } from '@/lib/cn'
import type {
  DiffChange,
  Scan,
  ScanDiffFinding,
  ScanDiffHost,
  ScanDiffService,
} from '@/types/api'

const CHANGE_TONE: Record<DiffChange, 'accent' | 'warn' | 'info' | 'neutral'> = {
  added: 'accent',
  removed: 'warn',
  changed: 'info',
  moved: 'info',
  same: 'neutral',
}

/**
 * The same five changes read differently depending on what they happened to:
 * a host appears, a port opens, a finding is raised.
 */
const LABELS: Record<
  'host' | 'service' | 'finding',
  Partial<Record<DiffChange, string>>
> = {
  host: { added: 'new', removed: 'gone', moved: 'moved', same: 'unchanged' },
  service: { added: 'opened', removed: 'closed', changed: 'version changed' },
  finding: { added: 'raised', removed: 'no longer raised' },
}

function ChangeBadge({
  group,
  change,
}: {
  group: 'host' | 'service' | 'finding'
  change: DiffChange
}) {
  return <Badge tone={CHANGE_TONE[change]}>{LABELS[group][change] ?? change}</Badge>
}

/** One collapsible group: its headline count, then its rows on demand. */
function Group({
  title,
  summary,
  rows,
  head,
  children,
  defaultOpen,
}: {
  title: string
  summary: ReactNode
  rows: number
  head: string[]
  children: ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  return (
    <div className="border-b border-border last:border-b-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={rows === 0}
        aria-expanded={open}
        className={cn(
          'flex w-full items-center justify-between gap-3 px-4 py-3 text-left',
          rows > 0 ? 'hover:bg-elevated' : 'cursor-default',
        )}
      >
        <span className="min-w-0">
          <span className="text-sm font-semibold text-fg">{title}</span>
          <span className="ml-2 text-xs text-muted">{summary}</span>
        </span>
        <span className="shrink-0 text-xs text-faint">
          {rows === 0 ? 'nothing to show' : open ? 'hide' : `show ${formatNumber(rows)}`}
        </span>
      </button>
      {open && rows > 0 && (
        <div className="table-scroll max-h-80 overflow-auto border-t border-border">
          <table className="data-table">
            <thead>
              <tr>
                {head.map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>{children}</tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** "10.0.0.11 (was 10.0.0.7)" for a machine that changed address. */
function Address({ ip, previous }: { ip: string; previous?: string }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <Mono>{ip}</Mono>
      {previous && previous !== ip && (
        <span className="text-faint">
          was <Mono className="text-faint">{previous}</Mono>
        </span>
      )}
    </span>
  )
}

function hostRow(h: ScanDiffHost) {
  return (
    <tr key={`${h.change}-${h.host_id}`}>
      <td>
        <ChangeBadge group="host" change={h.change} />
      </td>
      <td>
        <Address ip={h.ip} previous={h.previous_ip} />
      </td>
      <td>{h.hostname || h.asset_label || '-'}</td>
      <td className="text-muted">{h.os || '-'}</td>
      <td className="text-muted">{h.mac ? <Mono>{h.mac}</Mono> : '-'}</td>
    </tr>
  )
}

function serviceRow(s: ScanDiffService) {
  const now = [s.product, s.version].filter(Boolean).join(' ')
  const before = [s.previous_product, s.previous_version].filter(Boolean).join(' ')
  return (
    <tr key={`${s.change}-${s.service_id}-${s.port}`}>
      <td>
        <ChangeBadge group="service" change={s.change} />
      </td>
      <td>
        <Address ip={s.ip} previous={s.previous_ip} />
      </td>
      <td>
        <Mono>
          {s.port}/{s.protocol}
        </Mono>
      </td>
      <td>{s.name || <span className="text-faint">unknown</span>}</td>
      <td className="text-muted">
        {s.change === 'changed' ? (
          <span className="flex flex-wrap items-center gap-1.5">
            <span className="text-faint line-through">{before || 'unknown'}</span>
            <span aria-hidden="true">-&gt;</span>
            <span className="text-fg">{now || 'unknown'}</span>
          </span>
        ) : (
          now || '-'
        )}
      </td>
    </tr>
  )
}

function findingRow(f: ScanDiffFinding) {
  return (
    <tr key={`${f.change}-${f.finding_id}`}>
      <td>
        <ChangeBadge group="finding" change={f.change} />
      </td>
      <td className="capitalize text-muted">{f.severity}</td>
      <td>{f.title}</td>
      <td>
        <Address ip={f.ip} previous={f.previous_ip} />
      </td>
      <td className="text-muted">{f.port ? `${f.port}/${f.protocol ?? 'tcp'}` : '-'}</td>
    </tr>
  )
}

/** "3 new · 1 gone · 24 unchanged" with the zeroes left out. */
function summarise(parts: [number, string][]): string {
  const kept = parts
    .filter(([n]) => n > 0)
    .map(([n, label]) => `${formatNumber(n)} ${label}`)
  return kept.length > 0 ? kept.join(' · ') : 'nothing'
}

/**
 * The second scan of a VLAN only matters next to the first one. This panel is
 * that comparison: what appeared, what went away, and what is not quite the
 * same machine any more.
 */
export default function ScanDiffPanel({
  scan,
  missionId,
}: {
  scan: Scan
  missionId: number
}) {
  const [against, setAgainst] = useState(0)
  const scans = useScans(missionId)
  const diffQuery = useScanDiff(missionId, scan.id, against)

  // Only another scan of the same network has anything in common with this
  // one, so the picker never offers a comparison the server would refuse.
  const candidates = useMemo(
    () =>
      (scans.data ?? [])
        .filter((s) => s.id !== scan.id && s.network_id === scan.network_id)
        .sort((a, b) => b.id - a.id),
    [scans.data, scan.id, scan.network_id],
  )

  const picker = (
    <SelectField
      label="Compare against"
      className="h-8 py-0 text-xs"
      wrapperClassName="w-60"
      value={against || ''}
      onChange={(e) => setAgainst(Number(e.target.value) || 0)}
    >
      <option value="">Previous scan (automatic)</option>
      {candidates.map((s) => (
        <option key={s.id} value={s.id}>
          #{s.id} {s.kind} ({s.status})
        </option>
      ))}
    </SelectField>
  )

  const diff = diffQuery.data
  const counts = diff?.counts

  return (
    <Card>
      <CardHeader
        title="Diff"
        description="What this scan changed against an earlier pass over the same network."
        actions={picker}
      />

      {diffQuery.isLoading && (
        <div className="space-y-2 p-4">
          <Skeleton className="h-5 w-72" />
          <Skeleton className="h-12" />
        </div>
      )}

      {diffQuery.isError && (
        <div className="p-4">
          <ErrorState
            title="Could not compare these scans"
            error={diffQuery.error}
            retry={() => void diffQuery.refetch()}
          />
        </div>
      )}

      {diff && !diff.from && (
        <EmptyState
          title="Nothing to compare with yet"
          description={
            diff.message ||
            'This is the first completed scan of this network. Run it again later and this panel will show what moved.'
          }
          className="py-10"
        />
      )}

      {diff && diff.from && (
        <>
          <p className="border-b border-border px-4 py-2 text-xs text-muted">
            Scan <strong className="text-fg">#{diff.to.id}</strong> read against{' '}
            <strong className="text-fg">#{diff.from.id}</strong>
            {diff.from.finished_at && (
              <>
                {' '}
                (<RelativeTime value={diff.from.finished_at} />)
              </>
            )}
            {diff.from_picked &&
              ' · picked automatically as the last completed scan before this one'}
          </p>

          {!diff.changed ? (
            <EmptyState
              title="Nothing changed"
              description={
                diff.message ||
                `Scan #${diff.to.id} found exactly what scan #${diff.from.id} found: no host, port or finding moved.`
              }
              className="py-10"
            />
          ) : (
            <div>
              <Group
                title="Hosts"
                defaultOpen
                rows={(diff.hosts ?? []).length}
                summary={summarise([
                  [counts?.hosts_added ?? 0, 'new'],
                  [counts?.hosts_removed ?? 0, 'gone'],
                  [counts?.hosts_same ?? 0, 'in both'],
                  [counts?.hosts_moved ?? 0, 'moved'],
                ])}
                head={['Change', 'Address', 'Name', 'OS', 'MAC']}
              >
                {(diff.hosts ?? []).map(hostRow)}
              </Group>

              <Group
                title="Services"
                defaultOpen
                rows={(diff.services ?? []).length}
                summary={summarise([
                  [counts?.ports_opened ?? 0, 'opened'],
                  [counts?.ports_closed ?? 0, 'closed'],
                  [counts?.services_changed ?? 0, 'version changed'],
                ])}
                head={['Change', 'Address', 'Port', 'Service', 'Product']}
              >
                {(diff.services ?? []).map(serviceRow)}
              </Group>

              <Group
                title="Findings"
                defaultOpen
                rows={(diff.findings ?? []).length}
                summary={summarise([
                  [counts?.findings_raised ?? 0, 'raised'],
                  [counts?.findings_cleared ?? 0, 'no longer raised'],
                ])}
                head={['Change', 'Severity', 'Title', 'Address', 'Port']}
              >
                {(diff.findings ?? []).map(findingRow)}
              </Group>
            </div>
          )}

          {(diff.caveats ?? []).length > 0 && (
            <ul className="space-y-1 border-t border-border px-4 py-3 text-xs text-faint">
              {(diff.caveats ?? []).map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  )
}
