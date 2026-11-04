import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'
import { formatNumber } from '@/lib/format'

export function Card({
  className,
  children,
  id,
}: {
  className?: string
  children: ReactNode
  id?: string
}) {
  return (
    <section id={id} className={cn('card', className)}>
      {children}
    </section>
  )
}

export function CardHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <header
      className={cn(
        'flex flex-wrap items-start justify-between gap-3 border-b border-border px-4 py-3',
        className,
      )}
    >
      <div className="min-w-0">
        <h2 className="truncate text-sm font-semibold text-fg">{title}</h2>
        {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </header>
  )
}

export function CardBody({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return <div className={cn('p-4', className)}>{children}</div>
}

export function Stat({
  label,
  value,
  sub,
  tone,
  className,
}: {
  label: ReactNode
  value: ReactNode
  sub?: ReactNode
  tone?: 'default' | 'ok' | 'warn' | 'crit' | 'accent'
  className?: string
}) {
  const toneClass =
    tone === 'ok'
      ? 'text-ok'
      : tone === 'warn'
        ? 'text-warn'
        : tone === 'crit'
          ? 'text-crit'
          : tone === 'accent'
            ? 'text-accent'
            : 'text-fg'
  return (
    <div className={cn('card px-4 py-3', className)}>
      <div className="panel-title">{label}</div>
      <div className={cn('mt-1 text-2xl font-semibold tabular', toneClass)}>
        {typeof value === 'number' ? formatNumber(value) : value}
      </div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  className,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-wrap items-end justify-between gap-3', className)}>
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** A key/value row used in the detail drawers. */
export function KeyValue({
  label,
  children,
  mono,
  className,
}: {
  label: ReactNode
  children: ReactNode
  mono?: boolean
  className?: string
}) {
  return (
    <div className={cn('grid grid-cols-[minmax(0,160px)_1fr] gap-3 py-1 text-sm', className)}>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className={cn('min-w-0 break-words text-fg', mono && 'font-mono text-[12px]')}>
        {children}
      </dd>
    </div>
  )
}
