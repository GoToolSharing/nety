import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import { cn } from '@/lib/cn'
import {
  formatAbsolute,
  formatNumber,
  formatPercent,
  formatRelative,
} from '@/lib/format'
import { ChevronDownIcon, ChevronUpIcon, CopyIcon, CheckIcon, SearchIcon, XIcon } from '@/components/icons'

/** Relative time with the absolute timestamp in the tooltip. */
export function RelativeTime({
  value,
  className,
  prefix,
}: {
  value: string | null | undefined
  className?: string
  prefix?: string
}) {
  const [, force] = useState(0)
  useEffect(() => {
    const t = setInterval(() => force((n) => n + 1), 30_000)
    return () => clearInterval(t)
  }, [])
  if (!value) return <span className={cn('text-faint', className)}>—</span>
  return (
    <time dateTime={value} title={formatAbsolute(value)} className={cn('tabular', className)}>
      {prefix}
      {formatRelative(value)}
    </time>
  )
}

export function Mono({
  children,
  className,
  title,
}: {
  children: ReactNode
  className?: string
  title?: string
}) {
  return (
    <span title={title} className={cn('font-mono text-[12.5px]', className)}>
      {children}
    </span>
  )
}

export function CopyButton({ value, label }: { value: string; label?: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      aria-label={label ?? `Copy ${value}`}
      title={done ? 'Copied' : (label ?? 'Copy')}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value)
          setDone(true)
          setTimeout(() => setDone(false), 1400)
        } catch {
          /* clipboard blocked: nothing we can do, and nothing to break */
        }
      }}
      className="inline-flex h-6 w-6 items-center justify-center rounded text-faint hover:bg-elevated hover:text-fg"
    >
      {done ? <CheckIcon width={13} height={13} /> : <CopyIcon width={13} height={13} />}
    </button>
  )
}

/**
 * Registers the global "/" shortcut that focuses the page search box. Ignored
 * while the operator is typing in a field.
 */
export function useSearchHotkey(ref: RefObject<HTMLInputElement>) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.ctrlKey || e.metaKey || e.altKey) return
      const el = document.activeElement as HTMLElement | null
      const tag = el?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || el?.isContentEditable) {
        return
      }
      e.preventDefault()
      ref.current?.focus()
      ref.current?.select()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [ref])
}

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  className,
  label = 'Search',
  hotkey = true,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  className?: string
  label?: string
  hotkey?: boolean
}) {
  const ref = useRef<HTMLInputElement>(null)
  useSearchHotkey(hotkey ? ref : { current: null })
  return (
    <div className={cn('relative', className)}>
      <label className="sr-only" htmlFor="page-search">
        {label}
      </label>
      <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
      <input
        ref={ref}
        id="page-search"
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            if (value) {
              e.stopPropagation()
              onChange('')
            } else {
              ;(e.target as HTMLInputElement).blur()
            }
          }
        }}
        className="input-base h-9 py-0 pl-8 pr-14"
      />
      {hotkey && !value && (
        <kbd className="pointer-events-none absolute right-2.5 top-1/2 hidden -translate-y-1/2 rounded border border-border bg-elevated px-1.5 py-0.5 text-[10px] text-faint sm:block">
          /
        </kbd>
      )}
      {value && (
        <button
          type="button"
          aria-label="Clear search"
          onClick={() => onChange('')}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-faint hover:text-fg"
        >
          <XIcon width={13} height={13} />
        </button>
      )}
    </div>
  )
}

export type SortDirection = 'asc' | 'desc'

export function SortHeader<K extends string>({
  column,
  label,
  sort,
  onSort,
  className,
  numeric,
}: {
  column: K
  label: ReactNode
  sort: { key: K; dir: SortDirection }
  onSort: (key: K) => void
  className?: string
  numeric?: boolean
}) {
  const active = sort.key === column
  return (
    <th
      scope="col"
      className={className}
      aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}
    >
      <button
        type="button"
        onClick={() => onSort(column)}
        className={cn(
          // Browsers reset text-transform on form controls, so without this
          // the sortable headers lose the uppercase of the plain <th>s beside
          // them and the header row ends up in mixed case.
          'inline-flex items-center gap-1 rounded [text-transform:inherit] [letter-spacing:inherit] hover:text-fg',
          active && 'text-fg',
          numeric && 'justify-end',
        )}
      >
        {label}
        <span className={cn('text-[9px]', active ? 'opacity-100' : 'opacity-0')}>
          {sort.dir === 'asc' ? (
            <ChevronUpIcon width={11} height={11} />
          ) : (
            <ChevronDownIcon width={11} height={11} />
          )}
        </span>
      </button>
    </th>
  )
}

/** Shared sorting state for the client-side tables. */
export function useSort<K extends string>(initialKey: K, initialDir: SortDirection = 'asc') {
  const [sort, setSort] = useState<{ key: K; dir: SortDirection }>({
    key: initialKey,
    dir: initialDir,
  })
  const onSort = (key: K) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }))
  return { sort, onSort, setSort }
}

/**
 * Window pager. The services endpoint applies limit/offset and returns a bare
 * slice, so there is no total: a full page means there may be more.
 */
export function Pagination({
  offset,
  limit,
  count,
  hasMore,
  onChange,
  className,
}: {
  offset: number
  limit: number
  /** Rows on the current page. */
  count: number
  hasMore: boolean
  onChange: (offset: number) => void
  className?: string
}) {
  const from = count === 0 ? 0 : offset + 1
  const to = offset + count
  const canPrev = offset > 0
  const canNext = hasMore

  return (
    <div className={cn('flex items-center justify-between gap-3 px-3 py-2 text-xs', className)}>
      <span className="tabular text-muted">
        {count === 0 ? (
          'No rows'
        ) : (
          <>
            Rows {formatNumber(from)}–{formatNumber(to)}
            {hasMore ? ' (more available)' : ''}
          </>
        )}
      </span>
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          disabled={!canPrev}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="h-7 rounded border border-border bg-elevated px-2.5 hover:border-border-strong disabled:opacity-40"
        >
          Previous
        </button>
        <button
          type="button"
          disabled={!canNext}
          onClick={() => onChange(offset + limit)}
          className="h-7 rounded border border-border bg-elevated px-2.5 hover:border-border-strong disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}

export function ProgressBar({
  value,
  tone = 'accent',
  className,
  height = 'h-2',
  striped,
  label,
}: {
  value: number
  tone?: 'accent' | 'ok' | 'warn' | 'crit' | 'muted'
  className?: string
  height?: string
  striped?: boolean
  label?: string
}) {
  const pct = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0))
  const bg = {
    accent: 'bg-accent',
    ok: 'bg-ok',
    warn: 'bg-warn',
    crit: 'bg-crit',
    muted: 'bg-border-strong',
  }[tone]
  return (
    <div
      role="progressbar"
      aria-valuenow={Math.round(pct * 100)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
      title={label ? `${label}: ${formatPercent(pct, 1)}` : formatPercent(pct, 1)}
      className={cn('w-full overflow-hidden rounded-full bg-elevated', height, className)}
    >
      <div
        className={cn('h-full rounded-full transition-[width] duration-500 ease-out', bg)}
        style={{
          width: `${pct * 100}%`,
          backgroundImage: striped
            ? 'linear-gradient(45deg, rgb(255 255 255 / .18) 25%, transparent 25%, transparent 50%, rgb(255 255 255 / .18) 50%, rgb(255 255 255 / .18) 75%, transparent 75%)'
            : undefined,
          backgroundSize: striped ? '14px 14px' : undefined,
        }}
      />
    </div>
  )
}

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
  className,
}: {
  tabs: { id: T; label: ReactNode; count?: number }[]
  active: T
  onChange: (id: T) => void
  className?: string
}) {
  return (
    <div className={cn('flex gap-1 border-b border-border', className)} role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={active === t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            '-mb-px border-b-2 px-3 py-2 text-sm transition-colors',
            active === t.id
              ? 'border-accent font-medium text-fg'
              : 'border-transparent text-muted hover:text-fg',
          )}
        >
          {t.label}
          {typeof t.count === 'number' && (
            <span className="ml-1.5 tabular text-xs text-faint">{formatNumber(t.count)}</span>
          )}
        </button>
      ))}
    </div>
  )
}

/** A chip-style filter button row. */
export function FilterChips<T extends string | number>({
  options,
  value,
  onChange,
  className,
}: {
  options: { value: T; label: ReactNode; count?: number; tone?: string }[]
  value: T
  onChange: (v: T) => void
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap gap-1.5', className)}>
      {options.map((o) => (
        <button
          key={String(o.value)}
          type="button"
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors',
            value === o.value
              ? 'border-accent bg-accent/15 text-fg'
              : 'border-border bg-elevated text-muted hover:border-border-strong hover:text-fg',
          )}
        >
          {o.label}
          {typeof o.count === 'number' && (
            <span className="tabular text-[11px] text-faint">{formatNumber(o.count)}</span>
          )}
        </button>
      ))}
    </div>
  )
}
