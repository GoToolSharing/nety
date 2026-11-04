import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { AlertIcon, InfoIcon } from '@/components/icons'

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('skeleton h-4 w-full', className)} aria-hidden="true" />
}

/** Table placeholder: the shape of the data that is coming, not a spinner. */
export function TableSkeleton({
  rows = 8,
  columns = 5,
  className,
}: {
  rows?: number
  columns?: number
  className?: string
}) {
  return (
    <div className={cn('p-3', className)} role="status" aria-label="Loading data">
      <div className="mb-3 flex gap-3">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-3 flex-1" />
        ))}
      </div>
      <div className="space-y-2.5">
        {Array.from({ length: rows }).map((_, r) => (
          <div key={r} className="flex gap-3">
            {Array.from({ length: columns }).map((_, c) => (
              <Skeleton
                key={c}
                className={cn('h-4 flex-1', c === 0 && 'max-w-[140px]')}
                /* widths vary a little so it reads as data, not a progress bar */
              />
            ))}
          </div>
        ))}
      </div>
      <span className="sr-only">Loading…</span>
    </div>
  )
}

export function CardSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn('card space-y-3 p-4', className)} role="status" aria-label="Loading">
      <Skeleton className="h-3 w-24" />
      <Skeleton className="h-7 w-32" />
      <Skeleton className="h-3 w-40" />
    </div>
  )
}

/** Empty states always say what to do next. */
export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
}: {
  icon?: ReactNode
  title: string
  description?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 px-6 py-14 text-center',
        className,
      )}
    >
      {icon && (
        <div className="flex h-11 w-11 items-center justify-center rounded-full border border-border bg-elevated text-muted">
          {icon}
        </div>
      )}
      <div>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        {description && (
          <p className="mx-auto mt-1 max-w-md text-sm text-muted">{description}</p>
        )}
      </div>
      {action}
    </div>
  )
}

export function ErrorState({
  title = 'Something went wrong',
  error,
  retry,
  className,
}: {
  title?: string
  error?: unknown
  retry?: () => void
  className?: string
}) {
  const message =
    error instanceof Error ? error.message : typeof error === 'string' ? error : ''
  return (
    <div className={cn('flex flex-col items-center gap-3 px-6 py-12 text-center', className)}>
      <div className="flex h-11 w-11 items-center justify-center rounded-full border border-crit/40 bg-crit/10 text-crit">
        <AlertIcon width={20} height={20} />
      </div>
      <div>
        <h3 className="text-sm font-semibold text-fg">{title}</h3>
        {message && <p className="mt-1 max-w-md text-sm text-muted">{message}</p>}
      </div>
      {retry && (
        <button
          type="button"
          onClick={retry}
          className="inline-flex h-8 items-center rounded-md border border-border bg-elevated px-3 text-sm hover:border-border-strong"
        >
          Try again
        </button>
      )}
    </div>
  )
}

export function InlineAlert({
  tone = 'info',
  title,
  children,
  className,
  icon,
}: {
  tone?: 'info' | 'warn' | 'crit' | 'ok'
  title?: ReactNode
  children?: ReactNode
  className?: string
  icon?: ReactNode
}) {
  const tones = {
    info: 'border-info/40 bg-info/10 text-info',
    warn: 'border-warn/45 bg-warn/10 text-warn',
    crit: 'border-crit/45 bg-crit/10 text-crit',
    ok: 'border-ok/40 bg-ok/10 text-ok',
  }
  return (
    <div
      role={tone === 'crit' ? 'alert' : 'status'}
      className={cn('flex gap-2.5 rounded-md border px-3 py-2.5 text-sm', tones[tone], className)}
    >
      <span className="mt-0.5 shrink-0">
        {icon ?? (tone === 'info' ? <InfoIcon /> : <AlertIcon />)}
      </span>
      <div className="min-w-0 flex-1">
        {title && <div className="font-semibold">{title}</div>}
        {children && <div className={cn('text-fg/90', title && 'mt-0.5')}>{children}</div>}
      </div>
    </div>
  )
}
