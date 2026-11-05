import { useMemo } from 'react'
import { SeverityBadge } from '@/components/ui/Badge'
import { formatNumber } from '@/lib/format'
import { SEVERITIES, type Finding, type Network, type Severity } from '@/types/api'

/** Fill per severity, straight from the theme tokens so both themes work. */
const FILL: Record<Severity, string> = {
  critical: 'rgb(var(--c-crit))',
  high: 'rgb(var(--c-danger))',
  medium: 'rgb(var(--c-warn))',
  low: 'rgb(var(--c-info))',
  info: 'rgb(var(--c-faint))',
}

const WEIGHT: Record<Severity, number> = {
  critical: 1000,
  high: 100,
  medium: 10,
  low: 2,
  info: 1,
}

interface Row {
  id: number
  name: string
  vlan: number
  counts: Record<Severity, number>
  total: number
  score: number
}

/**
 * Findings per network, stacked by severity, most exposed network first.
 *
 * Severity is carried by three things at once: the position in the stack
 * (always critical first), the count printed inside every segment wide enough
 * to hold it, and the colour. The chart therefore still reads without colour
 * perception, and each bar carries a text alternative for screen readers.
 */
export default function SeverityByNetwork({
  networks,
  findings,
}: {
  networks: Network[]
  findings: Finding[]
}) {
  const rows = useMemo<Row[]>(() => {
    const byId = new Map<number, Row>()
    for (const n of networks) {
      byId.set(n.id, {
        id: n.id,
        name: n.name,
        vlan: n.vlan_id,
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        total: 0,
        score: 0,
      })
    }
    for (const f of findings) {
      const row = byId.get(f.network_id)
      if (!row) continue
      row.counts[f.severity] = (row.counts[f.severity] ?? 0) + 1
      row.total++
      row.score += WEIGHT[f.severity] ?? 0
    }
    return [...byId.values()]
      .filter((r) => r.total > 0)
      .sort((a, b) => b.score - a.score || b.total - a.total)
  }, [networks, findings])

  const max = Math.max(1, ...rows.map((r) => r.total))

  if (rows.length === 0) {
    return (
      <p className="px-4 py-6 text-sm text-muted">
        No finding is attached to a network yet.
      </p>
    )
  }

  return (
    <div className="px-4 py-4">
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <span className="mr-1 text-[10px] font-semibold uppercase tracking-wider text-faint">
          Stacked in this order
        </span>
        {SEVERITIES.map((s) => (
          <SeverityBadge key={s} severity={s} />
        ))}
      </div>

      <ul className="space-y-2">
        {rows.map((row) => {
          // Bars are scaled against the busiest network, so widths compare
          // across rows instead of every row filling the full width.
          const scale = row.total / max
          const label = SEVERITIES.filter((s) => row.counts[s] > 0)
            .map((s) => `${row.counts[s]} ${s}`)
            .join(', ')
          let cursor = 0
          return (
            <li key={row.id} className="flex items-center gap-3">
              <div className="w-40 shrink-0 truncate text-xs" title={row.name}>
                <span className="text-fg">{row.name}</span>
                {row.vlan ? (
                  <span className="ml-1 text-faint">VLAN {row.vlan}</span>
                ) : null}
              </div>
              <div className="min-w-0 flex-1">
                <svg
                  width="100%"
                  height="20"
                  role="img"
                  aria-label={`${row.name}: ${label}`}
                  className="block"
                >
                  <rect
                    x="0"
                    y="0"
                    width="100%"
                    height="20"
                    rx="3"
                    fill="rgb(var(--c-elevated))"
                  />
                  {SEVERITIES.map((s) => {
                    const n = row.counts[s]
                    if (n === 0) return null
                    const share = (n / row.total) * scale * 100
                    const x = cursor
                    cursor += share
                    return (
                      <g key={s}>
                        {/* The hairline in the card colour keeps two
                            neighbouring severities from blurring into one
                            band when their hues are close. */}
                        <rect
                          x={`${x}%`}
                          y="0"
                          width={`${share}%`}
                          height="20"
                          fill={FILL[s]}
                          stroke="rgb(var(--c-surface))"
                          strokeWidth="1"
                          shapeRendering="crispEdges"
                        >
                          <title>{`${row.name}: ${n} ${s}`}</title>
                        </rect>
                        {share >= 7 && (
                          <text
                            x={`${x + share / 2}%`}
                            y="14"
                            textAnchor="middle"
                            fontSize="11"
                            className="tabular"
                            fill="rgb(var(--c-bg))"
                            aria-hidden="true"
                          >
                            {n}
                          </text>
                        )}
                      </g>
                    )
                  })}
                </svg>
              </div>
              <div className="tabular w-10 shrink-0 text-right text-xs text-muted">
                {formatNumber(row.total)}
              </div>
            </li>
          )
        })}
      </ul>
    </div>
  )
}
