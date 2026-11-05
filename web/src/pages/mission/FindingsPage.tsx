import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useFindings, useHosts, useNetworks, useTriageSummary } from '@/lib/queries'
import { useDebounced, useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import {
  AddressFilterInput,
  FilterChips,
  Mono,
  RelativeTime,
  SearchInput,
  SelectAllCheckbox,
  SortButton,
  useSort,
} from '@/components/common'
import {
  SKIPPED_ROW_CLASS,
  SkippedHostsBanner,
  TriageNote,
  TriageProgress,
  TriageSelect,
} from '@/components/Triage'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import { formatNumber, isAddressOrPrefix } from '@/lib/format'
import { ChevronDownIcon, ChevronRightIcon, FindingIcon } from '@/components/icons'
import { SEVERITIES, type Finding, type Severity, type TriageStatus } from '@/types/api'

/**
 * The columns the findings list can be sorted by. Each one is a key the
 * server knows (see findingSorts in internal/store/results.go), severity
 * included: it is ordered by rank there, so critical sorts above low instead
 * of alphabetically between high and medium.
 */
type SortKey = 'severity' | 'ip' | 'check' | 'status' | 'last_seen'

/** The column widths the header strip and the rows below it share. */
const COL = {
  status: 'w-[122px] shrink-0',
  severity: 'w-[86px] shrink-0',
  address: 'w-[136px] shrink-0',
  lastSeen: 'w-[104px] shrink-0',
}

function FindingRow({
  finding,
  networkName,
  expanded,
  onToggle,
  selected,
  onSelect,
  onTriage,
  busy,
  recessed,
}: {
  finding: Finding
  networkName: string
  expanded: boolean
  onToggle: () => void
  selected: boolean
  onSelect: () => void
  onTriage: (body: { status?: TriageStatus; note?: string }) => void
  busy: boolean
  /** True when this row is only here because its host is skipped. */
  recessed?: boolean
}) {
  return (
    <div
      className={cn(
        'border-b border-border last:border-b-0',
        expanded && 'bg-elevated/40',
        recessed && SKIPPED_ROW_CLASS,
      )}
    >
      <div className="flex items-start gap-3 px-4 py-2.5 hover:bg-elevated/60">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={expanded}
          aria-label={expanded ? 'Collapse details' : 'Expand details'}
          className="mt-0.5 shrink-0 rounded p-0.5 text-faint hover:text-fg"
        >
          {expanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
        </button>
        <input
          type="checkbox"
          aria-label={`Select ${finding.title} on ${finding.ip}`}
          checked={selected}
          onChange={onSelect}
          className="mt-1 h-3.5 w-3.5 shrink-0 cursor-pointer accent-[rgb(var(--c-accent))]"
        />
        <div className={COL.status}>
          <TriageSelect
            value={finding.triage?.status}
            busy={busy}
            onChange={(status) => onTriage({ status })}
          />
        </div>
        <div className={COL.severity}>
          <SeverityBadge severity={finding.severity} />
        </div>
        <button type="button" onClick={onToggle} className="min-w-0 flex-1 text-left">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-fg">{finding.title}</span>
            <Badge tone="neutral" title="Check id">
              {finding.check_id}
            </Badge>
          </span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            <span>{networkName}</span>
            {finding.port ? (
              <span className="tabular">
                {finding.port}/{finding.protocol ?? 'tcp'}
              </span>
            ) : null}
            {finding.triage?.note && (
              <span className="truncate text-faint" title={finding.triage.note}>
                {finding.triage.note}
              </span>
            )}
          </span>
        </button>
        <div className={cn(COL.address, 'pt-0.5')}>
          <Mono className="text-muted">{finding.ip}</Mono>
        </div>
        <div className={cn(COL.lastSeen, 'pt-0.5 text-xs text-muted')}>
          <RelativeTime value={finding.last_seen} />
        </div>
      </div>

      {expanded && (
        <div className="space-y-3 border-t border-border px-4 py-3 pl-11 text-sm">
          {/* The operator's own verdict comes first: it is the reason this
              pane is open, and the check's own text is reference under it. */}
          <div>
            <h4 className="panel-title mb-1">Your review</h4>
            <div className="flex flex-wrap items-start gap-4 rounded-md border border-border bg-elevated/50 px-3 py-2">
              <div className="w-44 shrink-0">
                <div className="mb-1 text-[11px] text-muted">Status</div>
                <TriageSelect
                  value={finding.triage?.status}
                  busy={busy}
                  onChange={(status) => onTriage({ status })}
                />
                {finding.triage?.updated_at && (
                  <div className="mt-1.5 text-[11px] text-faint">
                    {finding.triage.updated_by_name ? `${finding.triage.updated_by_name}, ` : ''}
                    <RelativeTime value={finding.triage.updated_at} />
                  </div>
                )}
              </div>
              <div className="min-w-[260px] flex-1">
                <div className="mb-1 text-[11px] text-muted">Notes</div>
                <TriageNote
                  value={finding.triage?.note ?? ''}
                  onSave={(note) => onTriage({ note })}
                  placeholder="Confirmed, exploitable, false positive?"
                />
              </div>
            </div>
          </div>
          {finding.description && (
            <div>
              <h4 className="panel-title mb-1">Description</h4>
              <p className="whitespace-pre-wrap text-fg/90">{finding.description}</p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <h4 className="panel-title mb-1">Evidence</h4>
              <pre className="log-pane max-h-60 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-bg px-3 py-2 text-fg">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <h4 className="panel-title mb-1">Remediation</h4>
              <p className="whitespace-pre-wrap rounded border border-ok/35 bg-ok/5 px-3 py-2 text-fg/90">
                {finding.remediation}
              </p>
            </div>
          )}
          {(finding.references ?? []).length > 0 && (
            <div>
              <h4 className="panel-title mb-1">References</h4>
              <ul className="space-y-0.5">
                {(finding.references ?? []).map((r) => (
                  <li key={r} className="break-all font-mono text-[12px] text-muted">
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-xs text-faint">
            First seen <RelativeTime value={finding.first_seen} /> · last scan #
            {finding.last_scan_id}
          </p>
        </div>
      )}
    </div>
  )
}

export default function FindingsPage() {
  const missionId = useMissionId()
  const networks = useNetworks(missionId)
  const [networkId, setNetworkId] = useState(0)
  const [triage, setTriage] = useState<TriageStatus[]>([])
  // The findings of a skipped host are out of the way by default. This is the
  // operator asking to see them anyway.
  const [showSkipped, setShowSkipped] = useState(false)
  const [address, setAddress] = useState('')
  const { sort, onSort } = useSort<SortKey>('severity')
  const debouncedAddress = useDebounced(address, 300)
  // Half a typed subnet is not a filter yet, so it is not sent: the list
  // keeps showing what it had instead of emptying at every keystroke.
  const findings = useFindings(missionId, {
    network_id: networkId || undefined,
    ip: isAddressOrPrefix(debouncedAddress) ? debouncedAddress.trim() : undefined,
    triage: triage.length ? triage.join(',') : undefined,
    include_skipped: showSkipped || undefined,
    sort: sort.key,
    dir: sort.dir,
  })
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState<number | null>(null)

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

  // A filter change can empty the selection out from under the operator, so
  // drop it rather than act on rows that are no longer on screen. Every
  // filter counts, the ones applied here as much as the ones the server
  // applies: selecting thirty rows and then narrowing the search must not
  // leave twenty-nine of them armed and invisible.
  useEffect(() => {
    setSelected(new Set())
  }, [networkId, triage, showSkipped, debouncedAddress, query, severity])

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const all = useMemo(() => findings.data ?? [], [findings.data])

  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: qk.findingsRoot(missionId) })
    void qc.invalidateQueries({ queryKey: qk.triageSummaryRoot(missionId) })
  }, [qc, missionId])

  const setTriageOn = useCallback(
    async (finding: Finding, body: { status?: TriageStatus; note?: string }) => {
      setBusy(finding.id)
      try {
        await api.triageFinding(finding.id, body)
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
        // The server refuses more than 5,000 ids in one call, and a filter
        // that matches a whole informational check across a /16 goes past
        // that. Send it in batches rather than hand the operator an error
        // for doing exactly what the select-all box invited.
        const BATCH = 2000
        let updated = 0
        for (let i = 0; i < ids.length; i += BATCH) {
          const res = await api.triageFindingsBulk(missionId, ids.slice(i, i + BATCH), status)
          updated += res.updated
        }
        setSelected(new Set())
        refresh()
        toast.success(`${formatNumber(updated)} findings marked ${status.replace('_', ' ')}`)
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

  const counts = useMemo(() => {
    const c: Partial<Record<Severity, number>> = {}
    for (const f of all) c[f.severity] = (c[f.severity] ?? 0) + 1
    return c
  }, [all])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return all.filter((f) => {
      if (severity !== 'all' && f.severity !== severity) return false
      if (!q) return true
      return (
        f.title.toLowerCase().includes(q) ||
        f.check_id.toLowerCase().includes(q) ||
        f.ip.includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.evidence.toLowerCase().includes(q)
      )
    })
  }, [all, query, severity])

  const selectedShown = useMemo(
    () => filtered.reduce((n, f) => (selected.has(f.id) ? n + 1 : n), 0),
    [filtered, selected],
  )

  const toggle = (id: number) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <PageContainer>
      <PageHeader
        title="Findings"
        description="Misconfigurations raised by the light checks, worst first, with the remediation you can paste into the report. Any column header reorders the whole list."
        actions={
          filtered.length > 0 && (
            <button
              type="button"
              onClick={() =>
                setExpanded((prev) =>
                  prev.size > 0 ? new Set() : new Set(filtered.map((f) => f.id)),
                )
              }
              className="rounded border border-border bg-elevated px-3 py-1.5 text-xs hover:border-border-strong"
            >
              {expanded.size > 0 ? 'Collapse all' : 'Expand all'}
            </button>
          )
        }
      />

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Title, check id, IP, evidence…"
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
      </div>

      {summary.data?.findings && (
        <div className="mt-4">
          <TriageProgress
            noun="findings"
            counts={summary.data.findings.counts}
            total={summary.data.findings.total}
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
        noun="findings"
        className="mt-3"
      />

      {selected.size > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-2 rounded-md border border-accent/40 bg-accent/5 px-3 py-2">
          <span className="text-xs font-medium text-fg">{selected.size} selected</span>
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

      <FilterChips<Severity | 'all'>
        className="mt-3"
        value={severity}
        onChange={setSeverity}
        options={[
          { value: 'all', label: 'All severities', count: all.length },
          ...SEVERITIES.map((s) => ({
            value: s as Severity,
            label: <SeverityBadge severity={s} />,
            count: counts[s] ?? 0,
          })),
        ]}
      />

      <div className="mt-4 space-y-4 pb-8">
        {findings.isLoading ? (
          <Card>
            <TableSkeleton rows={8} columns={4} />
          </Card>
        ) : findings.isError ? (
          <Card>
            <ErrorState
              title="Could not load the findings"
              error={findings.error}
              retry={() => void findings.refetch()}
            />
          </Card>
        ) : filtered.length === 0 ? (
          <Card>
            <EmptyState
              icon={<FindingIcon width={20} height={20} />}
              title={all.length === 0 ? 'No finding yet' : 'No finding matches those filters'}
              description={
                all.length === 0 && triage.length === 0 && !address
                  ? 'The light checks run as part of a discovery scan when “Light checks” is enabled. They look for SMB signing, anonymous shares, default credentials, weak TLS, exposed management interfaces and similar quick wins.'
                  : 'Clear the search, widen the address filter, or pick another status or severity.'
              }
              action={
                all.length === 0 &&
                triage.length === 0 &&
                !address && (
                  <LinkButton to="../scans/new" variant="primary">
                    Launch a scan with checks
                  </LinkButton>
                )
              }
            />
          </Card>
        ) : (
          <Card>
            <CardHeader
              title={
                <span className="flex items-center gap-2">
                  <span>Findings</span>
                  <span className="tabular text-muted">{formatNumber(filtered.length)}</span>
                </span>
              }
            />
            {/* The header strip is what sorts the list. The order is worked
                out by the server over every finding of the mission, so it is
                the same whether one check fired or a thousand. */}
            <div className="flex items-center gap-3 border-b border-border px-4 py-2 text-[11px] font-medium uppercase tracking-wider text-muted">
              {/* A spacer for the expand chevron, then the master checkbox
                  sitting exactly over the column of row checkboxes. */}
              <span className="w-5 shrink-0" aria-hidden />
              <SelectAllCheckbox
                className="shrink-0"
                noun="findings"
                total={filtered.length}
                selected={selectedShown}
                onChange={(selectAll) =>
                  setSelected(selectAll ? new Set(filtered.map((f) => f.id)) : new Set())
                }
              />
              <SortButton
                column="status"
                label="Status"
                sort={sort}
                onSort={onSort}
                className={COL.status}
              />
              <SortButton
                column="severity"
                label="Severity"
                sort={sort}
                onSort={onSort}
                className={COL.severity}
              />
              <SortButton
                column="check"
                label="Finding"
                sort={sort}
                onSort={onSort}
                className="min-w-0 flex-1"
              />
              <SortButton
                column="ip"
                label="Address"
                sort={sort}
                onSort={onSort}
                className={COL.address}
              />
              <SortButton
                column="last_seen"
                label="Last seen"
                sort={sort}
                onSort={onSort}
                className={COL.lastSeen}
              />
            </div>
            <div>
              {filtered.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  networkName={netName.get(f.network_id) ?? `network ${f.network_id}`}
                  expanded={expanded.has(f.id)}
                  onToggle={() => toggle(f.id)}
                  selected={selected.has(f.id)}
                  onSelect={() => toggleSelected(f.id)}
                  onTriage={(body) => void setTriageOn(f, body)}
                  busy={busy === f.id}
                  recessed={skippedHosts.has(f.host_id)}
                />
              ))}
            </div>
          </Card>
        )}
      </div>
    </PageContainer>
  )
}
