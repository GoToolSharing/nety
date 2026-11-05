import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'

/** The mission id of the current route, as a number. */
export function useMissionId(): number {
  const { missionId } = useParams()
  const n = Number(missionId)
  return Number.isFinite(n) ? n : 0
}

/** Debounced mirror of a value: used for server-side search boxes. */
export function useDebounced<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}

/** Calls `fn` when Escape is pressed, while `active`. */
export function useEscape(active: boolean, fn: () => void): void {
  const ref = useRef(fn)
  ref.current = fn
  useEffect(() => {
    if (!active) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') ref.current()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [active])
}

/** A value that ticks every `ms`, to re-render live elapsed counters. */
export function useTicker(ms: number, active = true): number {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => setTick((n) => n + 1), ms)
    return () => clearInterval(t)
  }, [ms, active])
  return tick
}
