import { useCallback, useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useFindings, useNetworks } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import { FilterChips, Mono, RelativeTime, SearchInput } from '@/components/common'
import { TriageNote, TriageProgress, TriageSelect } from '@/components/Triage'
import { useToast } from '@/components/ui/Toast'
import { cn } from '@/lib/cn'
import { compareIP, formatNumber } from '@/lib/format'
import { ChevronDownIcon, ChevronRightIcon, FindingIcon } from '@/components/icons'
import { SEVERITIES, type Finding, type Severity, type TriageStatus } from '@/types/api'

function FindingRow({
  finding,
  networkName,
  expanded,
  onToggle,
  selected,
  onSelect,
  onTriage,
  busy,
}: {
  finding: Finding
  networkName: string
  expanded: boolean
  onToggle: () => void
  selected: boolean
  onSelect: () => void
  onTriage: (body: { status?: TriageStatus; note?: string }) => void
  busy: boolean
}) {
  return (
    <div className={cn('border-b border-border last:border-b-0', expanded && 'bg-elevated/40')}>
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
        <div className="w-[122px] shrink-0">
          <TriageSelect
            value={finding.triage?.status}
            busy={busy}
            onChange={(status) => onTriage({ status })}
          />
        </div>
        <button type="button" onClick={onToggle} className="min-w-0 flex-1 text-left">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-fg">{finding.title}</span>
            <Badge tone="neutral" title="Check id">
              {finding.check_id}
            </Badge>
          </span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
            <Mono>{finding.ip}</Mono>
            {finding.port ? (
              <span className="tabular">
                {finding.port}/{finding.protocol ?? 'tcp'}
              </span>
            ) : null}
            <span>{networkName}</span>
            <RelativeTime value={finding.last_seen} />
            {finding.triage?.note && (
              <span className="truncate text-faint" title={finding.triage.note}>
                {finding.triage.note}
              </span>
            )}
          </span>
        </button>
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
  const findings = useFindings(missionId, {
    network_id: networkId || undefined,
    triage: triage.length ? triage.join(',') : undefined,
  })
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState<number | null>(null)

  const qc = useQueryClient()
  const toast = useToast()

  const summary = useQuery({
    queryKey: ['triage-summary', missionId, networkId],
    queryFn: () => api.triageSummary(missionId, networkId || undefined),
    enabled: missionId > 0,
  })

  // A filter change can empty the selection out from under the operator, so
  // drop it rather than act on rows that are no longer on screen.
  useEffect(() => {
    setSelected(new Set())
  }, [networkId, triage])

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const all = useMemo(() => findings.data ?? [], [findings.data])

  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: qk.findingsRoot(missionId) })
    void qc.invalidateQueries({ queryKey: ['triage-summary', missionId] })
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
        const res = await api.triageFindingsBulk(missionId, ids, status)
        setSelected(new Set())
        refresh()
        toast.success(`${res.updated} findings marked ${status.replace('_', ' ')}`)
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

  const grouped = useMemo(() => {
    return SEVERITIES.map((sev) => ({
      severity: sev,
      items: filtered
        .filter((f) => f.severity === sev)
        .sort((a, b) => {
          const byCheck = a.check_id.localeCompare(b.check_id)
          return byCheck !== 0 ? byCheck : compareIP(a.ip, b.ip)
        }),
    })).filter((g) => g.items.length > 0)
  }, [filtered])

  const allSelected = filtered.length > 0 && filtered.every((f) => selected.has(f.id))

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
        description="Misconfigurations raised by the light checks, grouped by severity, with the remediation you can paste into the report."
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
        <button
          type="button"
          onClick={() => setSelected(allSelected ? new Set() : new Set(filtered.map((f) => f.id)))}
          disabled={filtered.length === 0}
          className="rounded border border-border bg-elevated px-2 py-1 text-[11px] text-muted hover:text-fg disabled:opacity-50"
        >
          {allSelected ? 'Clear selection' : 'Select all shown'}
        </button>
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
        ) : grouped.length === 0 ? (
          <Card>
            <EmptyState
              icon={<FindingIcon width={20} height={20} />}
              title={all.length === 0 ? 'No finding yet' : 'No finding matches those filters'}
              description={
                all.length === 0 && triage.length === 0
                  ? 'The light checks run as part of a discovery scan when “Light checks” is enabled. They look for SMB signing, anonymous shares, default credentials, weak TLS, exposed management interfaces and similar quick wins.'
                  : 'Clear the search, the status filter or pick another severity.'
              }
              action={
                all.length === 0 &&
                triage.length === 0 && (
                  <LinkButton to="../scans/new" variant="primary">
                    Launch a scan with checks
                  </LinkButton>
                )
              }
            />
          </Card>
        ) : (
          grouped.map((group) => (
            <Card key={group.severity}>
              <CardHeader
                title={
                  <span className="flex items-center gap-2">
                    <SeverityBadge severity={group.severity} />
                    <span className="tabular text-muted">
                      {formatNumber(group.items.length)}
                    </span>
                  </span>
                }
              />
              <div>
                {group.items.map((f) => (
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
                  />
                ))}
              </div>
            </Card>
          ))
        )}
      </div>
    </PageContainer>
  )
}
