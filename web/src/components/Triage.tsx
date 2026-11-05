import { useEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'
import { CheckIcon, FlagIcon, SkipIcon, SpinnerIcon, TodoIcon } from '@/components/icons'
import type { TriageStatus } from '@/types/api'
import { TRIAGE_STATUSES } from '@/types/api'

/**
 * A scan says what is exposed. Deciding whether each service is actually a
 * problem is still done by hand, one port at a time, and on a week-long
 * engagement that pass needs somewhere to live. These are the controls for it.
 *
 * The statuses are deliberately few. More would mean deciding which one
 * applies instead of getting on with the testing.
 */

export const TRIAGE_META: Record<
  TriageStatus,
  { label: string; short: string; tone: string; dot: string; hint: string }
> = {
  todo: {
    label: 'To do',
    short: 'To do',
    tone: 'border-border bg-elevated text-muted',
    dot: 'bg-faint',
    hint: 'Not looked at yet',
  },
  in_progress: {
    label: 'In progress',
    short: 'Doing',
    tone: 'border-info/40 bg-info/10 text-info',
    dot: 'bg-info',
    hint: 'Being tested right now',
  },
  done: {
    label: 'Done',
    short: 'Done',
    tone: 'border-ok/40 bg-ok/10 text-ok',
    dot: 'bg-ok',
    hint: 'Tested, nothing worth reporting',
  },
  flagged: {
    label: 'Flagged',
    short: 'Flag',
    tone: 'border-crit/40 bg-crit/10 text-crit',
    dot: 'bg-crit',
    hint: 'Tested, something to report',
  },
  skipped: {
    label: 'Skipped',
    short: 'Skip',
    tone: 'border-border bg-surface text-faint',
    dot: 'bg-border-strong',
    hint: 'Out of scope or not worth testing',
  },
}

export function triageLabel(status: TriageStatus | undefined): string {
  return TRIAGE_META[status ?? 'todo']?.label ?? String(status)
}

export function TriageIcon({ status, className }: { status: TriageStatus; className?: string }) {
  const props = { width: 13, height: 13, className }
  switch (status) {
    case 'in_progress':
      return <SpinnerIcon {...props} />
    case 'done':
      return <CheckIcon {...props} />
    case 'flagged':
      return <FlagIcon {...props} />
    case 'skipped':
      return <SkipIcon {...props} />
    default:
      return <TodoIcon {...props} />
  }
}

/** A read-only badge, for anywhere the status is shown but not edited. */
export function TriageBadge({
  status,
  className,
}: {
  status: TriageStatus | undefined
  className?: string
}) {
  const meta = TRIAGE_META[status ?? 'todo']
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-medium',
        meta.tone,
        className,
      )}
      title={meta.hint}
    >
      <TriageIcon status={status ?? 'todo'} />
      {meta.label}
    </span>
  )
}

/**
 * The status control used in the table and in the detail pane. It is a menu
 * rather than a cycle button: an operator marking a port done should not have
 * to click four times to get there.
 */
export function TriageSelect({
  value,
  onChange,
  busy,
  className,
  compact,
}: {
  value: TriageStatus | undefined
  onChange: (next: TriageStatus) => void
  busy?: boolean
  className?: string
  compact?: boolean
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const current = value ?? 'todo'
  const meta = TRIAGE_META[current]

  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', esc)
    }
  }, [open])

  return (
    <div ref={ref} className={cn('relative', className)}>
      <button
        type="button"
        disabled={busy}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Status: ${meta.label}. Change it.`}
        onClick={(e) => {
          e.stopPropagation()
          setOpen((v) => !v)
        }}
        className={cn(
          'inline-flex w-full items-center gap-1.5 rounded border px-1.5 py-0.5 text-[11px] font-medium transition-opacity hover:opacity-80 disabled:opacity-50',
          meta.tone,
        )}
      >
        <TriageIcon status={current} />
        <span className="truncate">{compact ? meta.short : meta.label}</span>
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute left-0 z-30 mt-1 w-60 overflow-hidden rounded-md border border-border bg-surface shadow-lg"
        >
          {TRIAGE_STATUSES.map((s) => {
            const m = TRIAGE_META[s]
            return (
              <button
                key={s}
                type="button"
                role="option"
                aria-selected={s === current}
                onClick={(e) => {
                  e.stopPropagation()
                  setOpen(false)
                  if (s !== current) onChange(s)
                }}
                className={cn(
                  'flex w-full items-start gap-2 px-2.5 py-1.5 text-left text-xs hover:bg-elevated',
                  s === current && 'bg-elevated',
                )}
              >
                <span className={cn('mt-1 h-2 w-2 shrink-0 rounded-full', m.dot)} />
                <span className="min-w-0">
                  <span className="block font-medium text-fg">{m.label}</span>
                  <span className="block whitespace-normal text-[11px] leading-snug text-muted">
                    {m.hint}
                  </span>
                </span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

/**
 * The note editor. It saves on blur rather than behind a button: an operator
 * jumping between ports should not lose a line because they forgot to confirm.
 */
export function TriageNote({
  value,
  onSave,
  placeholder = 'What did you test, what did you find?',
  rows = 3,
}: {
  value: string
  onSave: (next: string) => void
  placeholder?: string
  rows?: number
}) {
  const [draft, setDraft] = useState(value)
  const [saved, setSaved] = useState(false)
  const base = useRef(value)

  // Adopt a value that changed underneath us, unless it is being edited.
  useEffect(() => {
    if (value !== base.current && draft === base.current) {
      setDraft(value)
    }
    base.current = value
  }, [value, draft])

  const commit = () => {
    if (draft === base.current) return
    base.current = draft
    onSave(draft)
    setSaved(true)
    window.setTimeout(() => setSaved(false), 1600)
  }

  return (
    <div>
      <textarea
        value={draft}
        rows={rows}
        placeholder={placeholder}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
            e.currentTarget.blur()
          }
        }}
        className="input-base min-h-[4.5rem] w-full resize-y py-1.5 text-[13px] leading-relaxed"
      />
      <div className="mt-1 flex items-center justify-between text-[11px] text-faint">
        <span>Saved when you click away, or with Cmd/Ctrl + Enter.</span>
        {saved && <span className="text-ok">Saved</span>}
      </div>
    </div>
  )
}

/**
 * The progress readout above the table. It answers the only question that
 * matters mid-engagement: how much is left.
 */
export function TriageProgress({
  counts,
  total,
  active,
  onPick,
  noun = 'services',
}: {
  counts: Record<TriageStatus, number>
  total: number
  active: TriageStatus[]
  onPick: (status: TriageStatus | null) => void
  /** What is being counted, so the same bar reads right above findings. */
  noun?: string
}) {
  if (total === 0) return null
  const reviewed = total - (counts.todo ?? 0)
  const pct = Math.round((reviewed / total) * 100)

  return (
    <div className="rounded-md border border-border bg-surface px-3 py-2.5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-medium text-fg">
          {reviewed} of {total} {noun} reviewed
          <span className="ml-1.5 font-normal text-muted">({pct}%)</span>
        </span>
        <div className="flex flex-wrap items-center gap-1">
          <button
            type="button"
            onClick={() => onPick(null)}
            className={cn(
              'rounded border px-1.5 py-0.5 text-[11px]',
              active.length === 0
                ? 'border-accent/50 bg-accent/10 text-accent'
                : 'border-border text-muted hover:text-fg',
            )}
          >
            All {total}
          </button>
          {TRIAGE_STATUSES.map((s) => {
            const n = counts[s] ?? 0
            if (n === 0 && !active.includes(s)) return null
            const on = active.includes(s)
            return (
              <button
                key={s}
                type="button"
                onClick={() => onPick(s)}
                className={cn(
                  'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px]',
                  on ? TRIAGE_META[s].tone : 'border-border text-muted hover:text-fg',
                )}
              >
                <span className={cn('h-1.5 w-1.5 rounded-full', TRIAGE_META[s].dot)} />
                {TRIAGE_META[s].label} {n}
              </button>
            )
          })}
        </div>
      </div>
      <div
        className="mt-2 flex h-1.5 overflow-hidden rounded-full bg-elevated"
        role="img"
        aria-label={`${reviewed} of ${total} ${noun} reviewed`}
      >
        {TRIAGE_STATUSES.filter((s) => s !== 'todo').map((s) => {
          const n = counts[s] ?? 0
          if (n === 0) return null
          return (
            <span
              key={s}
              className={TRIAGE_META[s].dot}
              style={{ width: `${(n / total) * 100}%` }}
              title={`${TRIAGE_META[s].label}: ${n}`}
            />
          )
        })}
      </div>
    </div>
  )
}
