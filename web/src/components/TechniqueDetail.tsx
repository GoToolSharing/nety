import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Badge } from '@/components/ui/Badge'
import { BoltIcon, ChevronDownIcon, ChevronRightIcon } from '@/components/icons'
import { cn } from '@/lib/cn'
import { techniqueHelpHref, type TechniqueGuide } from '@/lib/techniques'

/**
 * The shared rendering of a bypass technique: the flags, the explanation and
 * the manual reproduction. The Help page and the segmentation matrix both use
 * it, so a technique is described in exactly one place.
 */

export function TechniqueFlags({ t }: { t: TechniqueGuide }) {
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <Badge tone={t.default ? 'accent' : 'neutral'}>
        {t.default ? 'on by default' : 'opt in'}
      </Badge>
      {t.bypass && (
        <Badge
          tone="warn"
          title="A hit through this technique is a bypass, not plain routing"
        >
          <BoltIcon width={10} height={10} />
          bypass
        </Badge>
      )}
      {t.one_way && (
        <Badge
          tone="info"
          title="Traffic only travels one way, so delivery cannot be confirmed"
        >
          one way
        </Badge>
      )}
      {t.l2_active && (
        <Badge
          tone="crit"
          title="Puts frames on the wire that change the switch port state"
        >
          layer 2, active
        </Badge>
      )}
    </span>
  )
}

function Label({ children }: { children: ReactNode }) {
  return (
    <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">
      {children}
    </div>
  )
}

export function TechniqueDetail({ t }: { t: TechniqueGuide }) {
  return (
    <div className="space-y-3">
      <p className="whitespace-normal text-sm text-muted">{t.description}</p>
      {t.notes && (
        <>
          <div>
            <Label>Why it gets through</Label>
            <p className="mt-0.5 whitespace-normal text-sm text-fg">{t.notes.why}</p>
          </div>
          <div>
            <Label>What a positive result means</Label>
            <p className="mt-0.5 whitespace-normal text-sm text-fg">{t.notes.positive}</p>
          </div>
          <div>
            <Label>Reproduce it by hand</Label>
            <pre className="log-pane mt-1 overflow-x-auto rounded-md border border-border bg-elevated px-3 py-2 text-muted">
              {t.notes.manual.join('\n')}
            </pre>
          </div>
        </>
      )}
    </div>
  )
}

/** The link that takes the operator to this technique's entry on the Help page. */
export function TechniqueHelpLink({ t }: { t: TechniqueGuide }) {
  return (
    <Link
      to={techniqueHelpHref(t.id)}
      className="inline-flex items-center gap-0.5 text-xs text-accent underline-offset-2 hover:underline"
    >
      Full entry in Help
      <ChevronRightIcon width={11} height={11} />
    </Link>
  )
}

/**
 * The technique a result was obtained with, named rather than left as a raw
 * id. Pass `onToggle` to make it the control of an inline explanation.
 */
export function TechniqueBadge({
  t,
  expanded,
  onToggle,
  className,
}: {
  t: TechniqueGuide
  expanded?: boolean
  onToggle?: () => void
  className?: string
}) {
  const tone = t.bypass ? 'warn' : 'neutral'
  const tip = t.notes?.short ?? t.description
  const body = (
    <>
      {t.bypass && <BoltIcon width={10} height={10} />}
      {t.title}
      {onToggle && (
        <ChevronDownIcon
          width={10}
          height={10}
          className={cn('transition-transform', expanded && 'rotate-180')}
        />
      )}
    </>
  )

  if (!onToggle) {
    return (
      <Badge tone={tone} title={tip} className={className}>
        {body}
      </Badge>
    )
  }
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-expanded={expanded}
      title={`${tip} Click for the full explanation.`}
      className={cn(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium leading-4',
        t.bypass
          ? 'border-warn/40 bg-warn/15 text-warn hover:bg-warn/25'
          : 'border-border bg-elevated text-muted hover:text-fg',
        className,
      )}
    >
      {body}
    </button>
  )
}
