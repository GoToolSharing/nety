import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { cn } from '@/lib/cn'
import { formatAbsolute, formatClock } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { ChevronDownIcon } from '@/components/icons'
import type { ScanLogLine } from '@/types/api'

const LEVEL_CLASS: Record<string, string> = {
  debug: 'text-faint',
  info: 'text-muted',
  warn: 'text-warn',
  error: 'text-crit',
}

/**
 * Streaming log pane. It follows the tail by default; scrolling up pauses the
 * follow (so a line you are reading does not slide away) and a button brings
 * you back to live.
 */
export default function LogPane({
  lines,
  className,
  height = 'h-80',
}: {
  lines: ScanLogLine[]
  className?: string
  height?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [following, setFollowing] = useState(true)
  const [levelFilter, setLevelFilter] = useState<'all' | 'info' | 'warn'>('all')
  const [missed, setMissed] = useState(0)

  const visible = lines.filter((l) => {
    if (levelFilter === 'all') return true
    if (levelFilter === 'info') return l.level !== 'debug'
    return l.level === 'warn' || l.level === 'error'
  })

  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    if (following) {
      el.scrollTop = el.scrollHeight
      setMissed(0)
    } else {
      setMissed((n) => n + 1)
    }
    // Only react to new lines, not to every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible.length])

  useEffect(() => {
    if (following) setMissed(0)
  }, [following])

  const onScroll = () => {
    const el = ref.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 32
    setFollowing(atBottom)
  }

  const jumpToLive = () => {
    const el = ref.current
    if (!el) return
    el.scrollTop = el.scrollHeight
    setFollowing(true)
  }

  return (
    <div className={cn('relative', className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
        <div className="flex items-center gap-2">
          <span className="panel-title">Log</span>
          <span className="tabular text-[11px] text-faint">{lines.length} lines</span>
        </div>
        <div className="flex items-center gap-1">
          {(['all', 'info', 'warn'] as const).map((lv) => (
            <button
              key={lv}
              type="button"
              aria-pressed={levelFilter === lv}
              onClick={() => setLevelFilter(lv)}
              className={cn(
                'rounded px-1.5 py-0.5 text-[11px]',
                levelFilter === lv
                  ? 'bg-accent/20 text-fg'
                  : 'text-muted hover:bg-elevated hover:text-fg',
              )}
            >
              {lv === 'all' ? 'all' : lv === 'info' ? 'info+' : 'warn+'}
            </button>
          ))}
          <span
            className={cn(
              'ml-1.5 inline-flex items-center gap-1 text-[11px]',
              following ? 'text-ok' : 'text-warn',
            )}
            title={
              following
                ? 'Following the tail of the log'
                : 'Auto-scroll paused because you scrolled up'
            }
          >
            <span
              className={cn(
                'inline-block h-1.5 w-1.5 rounded-full bg-current',
                following && 'animate-pulse',
              )}
            />
            {following ? 'live' : 'paused'}
          </span>
        </div>
      </div>

      <div
        ref={ref}
        onScroll={onScroll}
        tabIndex={0}
        role="log"
        aria-label="Scan log"
        aria-live="polite"
        className={cn('log-pane scrollbar-thin overflow-y-auto bg-bg px-3 py-2', height)}
      >
        {visible.length === 0 ? (
          <p className="py-6 text-center text-xs text-faint">
            No log line yet. Lines appear here as the scan runs.
          </p>
        ) : (
          visible.map((l) => (
            <div key={l.id} className="flex gap-2 whitespace-pre-wrap break-words">
              <span className="shrink-0 text-faint" title={formatAbsolute(l.time)}>
                {formatClock(l.time)}
              </span>
              <span
                className={cn(
                  'w-10 shrink-0 uppercase',
                  LEVEL_CLASS[l.level] ?? 'text-muted',
                )}
              >
                {l.level}
              </span>
              <span
                className={cn(
                  'min-w-0 flex-1',
                  l.level === 'error' ? 'text-crit' : 'text-fg',
                )}
              >
                {l.message}
              </span>
            </div>
          ))
        )}
      </div>

      {!following && (
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2">
          <Button
            size="sm"
            variant="primary"
            icon={<ChevronDownIcon />}
            onClick={jumpToLive}
          >
            Back to live{missed > 0 ? ` (${missed} new)` : ''}
          </Button>
        </div>
      )}
    </div>
  )
}
