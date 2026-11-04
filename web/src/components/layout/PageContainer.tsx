import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

/**
 * Scroll container for a mission page. The page itself scrolls vertically;
 * wide tables get their own horizontal scroller so the layout never breaks.
 */
export default function PageContainer({
  children,
  className,
  wide,
}: {
  children: ReactNode
  className?: string
  wide?: boolean
}) {
  return (
    <div className="h-full overflow-y-auto">
      <div className={cn('px-6 py-6', wide ? 'max-w-none' : 'mx-auto max-w-7xl', className)}>
        {children}
      </div>
    </div>
  )
}
