import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { EventSocket, type SocketStatus } from '@/live/socket'
import { LiveStore } from '@/live/store'
import { Invalidator, applyEvent, resynchronise } from '@/live/apply'

interface LiveContextValue {
  status: SocketStatus
  lastEventAt: number | null
  store: LiveStore
}

const LiveContext = createContext<LiveContextValue | null>(null)

export function LiveProvider({
  missionId,
  children,
}: {
  missionId: number
  children: ReactNode
}) {
  const qc = useQueryClient()
  const [status, setStatus] = useState<SocketStatus>('connecting')
  const lastEventAt = useRef<number | null>(null)
  const store = useMemo(() => new LiveStore(), [missionId])

  useEffect(() => {
    if (!missionId) return
    const invalidator = new Invalidator(qc)
    const ctx = {
      qc,
      missionId,
      store,
      invalidator,
      // The server dropped events because this browser could not keep up:
      // refetch the affected tables rather than show a stale page.
      onDropped: () => resynchronise(qc, missionId),
    }

    const socket = new EventSocket(missionId, {
      onEvent: (event) => {
        lastEventAt.current = Date.now()
        applyEvent(ctx, event)
      },
      onStatus: (s) => {
        setStatus(s)
        // A reconnect means we may have missed events while offline.
        if (s === 'open' && lastEventAt.current !== null) resynchronise(qc, missionId)
      },
    })
    socket.start()

    return () => {
      socket.stop()
      invalidator.dispose()
      store.clear()
    }
  }, [missionId, qc, store])

  const value = useMemo<LiveContextValue>(
    () => ({ status, lastEventAt: lastEventAt.current, store }),
    [status, store],
  )

  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>
}

export function useLive(): LiveContextValue {
  const ctx = useContext(LiveContext)
  if (!ctx) throw new Error('useLive must be used inside a LiveProvider')
  return ctx
}

/** Re-renders the caller whenever the live store changes (coalesced). */
export function useLiveVersion(): number {
  const { store } = useLive()
  return useSyncExternalStore(store.subscribe, store.getSnapshot, store.getSnapshot)
}
