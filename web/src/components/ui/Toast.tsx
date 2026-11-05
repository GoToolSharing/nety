import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { cn } from '@/lib/cn'
import { AlertIcon, CheckIcon, InfoIcon, XIcon } from '@/components/icons'

type ToastTone = 'info' | 'success' | 'error'

interface Toast {
  id: number
  tone: ToastTone
  title: string
  detail?: string
}

interface ToastContextValue {
  push: (t: Omit<Toast, 'id'>) => void
  success: (title: string, detail?: string) => void
  error: (title: string, detail?: unknown) => void
  info: (title: string, detail?: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id))
  }, [])

  const push = useCallback(
    (t: Omit<Toast, 'id'>) => {
      const id = nextId.current++
      setToasts((list) => [...list.slice(-4), { ...t, id }])
      setTimeout(() => dismiss(id), t.tone === 'error' ? 9000 : 5000)
    },
    [dismiss],
  )

  const value = useMemo<ToastContextValue>(
    () => ({
      push,
      success: (title, detail) => push({ tone: 'success', title, detail }),
      info: (title, detail) => push({ tone: 'info', title, detail }),
      error: (title, detail) =>
        push({
          tone: 'error',
          title,
          detail:
            detail instanceof Error
              ? detail.message
              : typeof detail === 'string'
                ? detail
                : undefined,
        }),
    }),
    [push],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        className="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2"
        role="region"
        aria-label="Notifications"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.tone === 'error' ? 'alert' : 'status'}
            className={cn(
              'pointer-events-auto flex animate-fade-in items-start gap-2.5 rounded-lg border bg-surface px-3.5 py-3 shadow-lg',
              t.tone === 'error'
                ? 'border-crit/50'
                : t.tone === 'success'
                  ? 'border-ok/45'
                  : 'border-border',
            )}
          >
            <span
              className={cn(
                'mt-0.5 shrink-0',
                t.tone === 'error'
                  ? 'text-crit'
                  : t.tone === 'success'
                    ? 'text-ok'
                    : 'text-info',
              )}
            >
              {t.tone === 'error' ? (
                <AlertIcon />
              ) : t.tone === 'success' ? (
                <CheckIcon />
              ) : (
                <InfoIcon />
              )}
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-fg">{t.title}</div>
              {t.detail && (
                <div className="mt-0.5 break-words text-xs text-muted">{t.detail}</div>
              )}
            </div>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
              className="shrink-0 rounded p-0.5 text-faint hover:text-fg"
            >
              <XIcon width={14} height={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used inside a ToastProvider')
  return ctx
}
