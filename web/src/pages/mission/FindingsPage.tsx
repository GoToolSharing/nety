import { useMemo, useState } from 'react'
import { useFindings, useNetworks } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, TableSkeleton } from '@/components/ui/Feedback'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import { FilterChips, Mono, RelativeTime, SearchInput } from '@/components/common'
import { cn } from '@/lib/cn'
import { compareIP, formatNumber } from '@/lib/format'
import { ChevronDownIcon, ChevronRightIcon, FindingIcon } from '@/components/icons'
import { SEVERITIES, type Finding, type Severity } from '@/types/api'

function FindingRow({
  finding,
  networkName,
  expanded,
  onToggle,
}: {
  finding: Finding
  networkName: string
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <div className={cn('border-b border-border last:border-b-0', expanded && 'bg-elevated/40')}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        className="flex w-full items-start gap-3 px-4 py-2.5 text-left hover:bg-elevated/60"
      >
        <span className="mt-0.5 shrink-0 text-faint">
          {expanded ? <ChevronDownIcon /> : <ChevronRightIcon />}
        </span>
        <span className="min-w-0 flex-1">
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
          </span>
        </span>
      </button>

      {expanded && (
        <div className="space-y-3 border-t border-border px-4 py-3 pl-11 text-sm">
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
  const findings = useFindings(missionId, networkId || undefined)
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<Severity | 'all'>('all')
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const netName = useMemo(() => {
    const m = new Map<number, string>()
    for (const n of networks.data ?? []) m.set(n.id, n.name)
    return m
  }, [networks.data])

  const all = findings.data ?? []

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
      </div>

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
                all.length === 0
                  ? 'The light checks run as part of a discovery scan when “Light checks” is enabled. They look for SMB signing, anonymous shares, default credentials, weak TLS, exposed management interfaces and similar quick wins.'
                  : 'Clear the search or pick another severity.'
              }
              action={
                all.length === 0 && (
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
