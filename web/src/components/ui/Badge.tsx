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

/** A severity is never signalled by colour alone: the word is always there,
 * plus a filled-block ramp readable without colour perception. */
const SEVERITY_RAMP: Record<Severity, string> = {
  critical: '████',
  high: '███',
  medium: '██',
  low: '█',
  info: '·',
}

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity
  className?: string
}) {
  return (
    <Badge tone={SEVERITY_TONE[severity] ?? 'neutral'} className={cn('uppercase', className)}>
      <span aria-hidden="true" className="text-[7px] leading-none tracking-tighter">
        {SEVERITY_RAMP[severity] ?? '·'}
      </span>
      {severity}
    </Badge>
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
