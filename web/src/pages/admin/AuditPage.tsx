import { useMemo, useState } from 'react'
import { useAudit } from '@/lib/queries'
import PageContainer from '@/components/layout/PageContainer'
import { Card, PageHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { EmptyState, ErrorState, InlineAlert, TableSkeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { Mono, RelativeTime, SearchInput } from '@/components/common'
import { formatNumber } from '@/lib/format'
import { AuditIcon, RefreshIcon } from '@/components/icons'
import type { AuditEntry } from '@/types/api'

function actionTone(action: string): 'crit' | 'warn' | 'ok' | 'neutral' | 'accent' {
  const a = action.toLowerCase()
  if (a.includes('delete') || a.includes('fail') || a.includes('denied')) return 'crit'
  if (a.includes('login') || a.includes('logout') || a.includes('password')) return 'warn'
  if (a.includes('create')) return 'ok'
  if (a.includes('scan') || a.includes('start') || a.includes('stop')) return 'accent'
  return 'neutral'
}

function entryTime(e: AuditEntry): string | undefined {
  return e.time ?? e.created_at
}

export default function AuditPage() {
  const [limit, setLimit] = useState(200)
  const audit = useAudit(limit)
  const [query, setQuery] = useState('')

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (audit.data ?? [])
      .filter(
        (e) =>
          !q ||
          e.action.toLowerCase().includes(q) ||
          (e.username ?? '').toLowerCase().includes(q) ||
          (e.target ?? '').toLowerCase().includes(q) ||
          (e.detail ?? '').toLowerCase().includes(q) ||
          (e.ip ?? '').includes(q),
      )
      .sort((a, b) => (entryTime(b) ?? '').localeCompare(entryTime(a) ?? ''))
  }, [audit.data, query])

  const unavailable = audit.isError

  return (
    <PageContainer>
      <PageHeader
        title="Audit log"
        description="Who did what on this instance: sign-ins, mission and user changes, scans started, stopped and exported."
        actions={
          <Button icon={<RefreshIcon />} onClick={() => void audit.refetch()} loading={audit.isFetching}>
            Refresh
          </Button>
        }
      />

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Action, user, target, IP…"
          className="w-full max-w-sm"
        />
        <label className="flex items-center gap-2 text-xs text-muted">
          <span>Show</span>
          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="input-base h-9 w-auto py-0"
          >
            {[100, 200, 500, 1000].map((n) => (
              <option key={n} value={n}>
                last {n}
              </option>
            ))}
          </select>
        </label>
        {!unavailable && (
          <span className="tabular text-xs text-faint">{formatNumber(rows.length)} entries</span>
        )}
      </div>

      {unavailable && (
        <InlineAlert tone="info" className="mt-4" title="Audit endpoint not available">
          This NETY server did not answer <Mono>GET /api/audit</Mono>. The audit trail may be
          disabled, or this build predates it.
        </InlineAlert>
      )}

      <Card className="mt-4">
        {audit.isLoading ? (
          <TableSkeleton rows={10} columns={5} />
        ) : unavailable ? (
          <ErrorState
            title="Could not load the audit log"
            error={audit.error}
            retry={() => void audit.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<AuditIcon width={20} height={20} />}
            title={query ? 'No entry matches that filter' : 'The audit log is empty'}
            description={
              query
                ? 'Clear the search to see every entry.'
                : 'Entries appear as soon as somebody signs in or changes something.'
            }
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>When</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Detail</th>
                  <th>Source IP</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id}>
                    <td className="text-muted">
                      <RelativeTime value={entryTime(e)} />
                    </td>
                    <td className="font-medium">
                      {e.username ?? (e.user_id ? `#${e.user_id}` : '—')}
                    </td>
                    <td>
                      <Badge tone={actionTone(e.action)}>{e.action}</Badge>
                      {e.status && <span className="ml-1.5 text-xs text-muted">{e.status}</span>}
                    </td>
                    <td className="text-muted">
                      {e.target ? <Mono>{e.target}</Mono> : '—'}
                      {e.mission_id ? (
                        <span className="ml-1.5 text-xs text-faint">mission #{e.mission_id}</span>
                      ) : null}
                    </td>
                    <td className="max-w-[360px] truncate text-muted" title={e.detail}>
                      {e.detail || '—'}
                    </td>
                    <td className="text-muted">{e.ip ? <Mono>{e.ip}</Mono> : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </PageContainer>
  )
}
