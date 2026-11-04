import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import type { PortState, ReachStatus, ScanStatus, Severity } from '@/types/api'

type Tone = 'neutral' | 'accent' | 'ok' | 'warn' | 'danger' | 'crit' | 'info'

const TONES: Record<Tone, string> = {
  neutral: 'bg-elevated text-muted border-border',
  accent: 'bg-accent/15 text-accent border-accent/40',
  ok: 'bg-ok/15 text-ok border-ok/40',
  warn: 'bg-warn/15 text-warn border-warn/40',
  danger: 'bg-danger/15 text-danger border-danger/40',
  crit: 'bg-crit/15 text-crit border-crit/45',
  info: 'bg-info/15 text-info border-info/40',
}

export function Badge({
  tone = 'neutral',
  className,
  children,
  title,
}: {
  tone?: Tone
  className?: string
  children: ReactNode
  title?: string
}) {
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium leading-4',
        TONES[tone],
        className,
      )}
    >
      {children}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'crit',
  high: 'danger',
  medium: 'warn',
  low: 'info',
  info: 'neutral',
}

/** How many of the four steps of the meter are lit, highest first. */
const SEVERITY_STEPS: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

/**
 * A four-step meter drawn in the badge's own colour. The rank is carried by
 * the number of lit bars and by the label, so the badge still reads without
 * colour perception; the colour only reinforces it.
 */
function SeverityMeter({ steps }: { steps: number }) {
  return (
    <svg width="11" height="8" viewBox="0 0 11 8" aria-hidden="true" focusable="false">
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={i * 3}
          y={6.5 - i * 1.7}
          width="2"
          height={1.5 + i * 1.7}
          rx="0.5"
          fill="currentColor"
          fillOpacity={i < steps ? 1 : 0.25}
        />
      ))}
    </svg>
  )
}

/**
 * The severity badge, used everywhere a finding's severity is shown. One
 * shape, one size, one reading order: meter, then word.
 */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  const steps = SEVERITY_STEPS[severity] ?? 0
  return (
    <span
      className={cn(
        'inline-flex select-none items-center gap-1.5 rounded border px-1.5 py-0.5',
        'text-[10px] font-semibold uppercase leading-4 tracking-wide',
        TONES[SEVERITY_TONE[severity] ?? 'neutral'],
        severity === 'critical' && 'border-crit/70 bg-crit/20',
        className,
      )}
    >
      <SeverityMeter steps={steps} />
      {severity}
    </span>
  )
}

export function severityTone(severity: Severity): Tone {
  return SEVERITY_TONE[severity] ?? 'neutral'
}

// ---------------------------------------------------------------------------
// Scan status
// ---------------------------------------------------------------------------

const SCAN_STATUS_TONE: Record<ScanStatus, Tone> = {
  queued: 'neutral',
  running: 'accent',
  paused: 'warn',
  completed: 'ok',
  failed: 'crit',
  cancelled: 'neutral',
}

const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  queued: 'Queued',
  running: 'Running',
  paused: 'Paused',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Stopped',
}

export function ScanStatusBadge({
  status,
  className,
}: {
  status: ScanStatus
  className?: string
}) {
  const running = status === 'running'
  return (
    <Badge tone={SCAN_STATUS_TONE[status] ?? 'neutral'} className={className}>
      <span
        aria-hidden="true"
        className={cn(
          'inline-block h-1.5 w-1.5 rounded-full bg-current',
          running && 'animate-pulse',
        )}
      />
      {SCAN_STATUS_LABEL[status] ?? status}
    </Badge>
  )
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

const REACH_TONE: Record<ReachStatus, Tone> = {
  reachable: 'crit', // reaching across a segment boundary is the bad outcome
  closed: 'warn',
  filtered: 'ok',
  unreachable: 'ok',
  sent: 'info',
  error: 'neutral',
}

const REACH_LABEL: Record<ReachStatus, string> = {
  reachable: 'Reachable',
  closed: 'Closed (routed)',
  filtered: 'Filtered',
  unreachable: 'Unreachable',
  sent: 'Sent (one-way)',
  error: 'Error',
}

export function ReachBadge({
  status,
  className,
}: {
  status: ReachStatus
  className?: string
}) {
  return (
    <Badge
      tone={REACH_TONE[status] ?? 'neutral'}
      className={className}
      title={
        status === 'closed'
          ? 'The packet was routed to the host, which answered RST: the segment boundary did not block it.'
          : undefined
      }
    >
      {REACH_LABEL[status] ?? status}
    </Badge>
  )
}

export function reachTone(status: ReachStatus): Tone {
  return REACH_TONE[status] ?? 'neutral'
}

// ---------------------------------------------------------------------------
// Port state
// ---------------------------------------------------------------------------

export function PortStateBadge({ state }: { state: PortState }) {
  const tone: Tone =
    state === 'open' ? 'ok' : state === 'open|filtered' ? 'warn' : 'neutral'
  return <Badge tone={tone}>{state}</Badge>
}
