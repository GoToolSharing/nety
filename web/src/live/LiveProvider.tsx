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
  /** When the next reconnect attempt is due, in ms (while reconnecting). */
  retryInMs: number | null
  lastEventAt: number | null
  /** How many times the server told us it had to drop events. */
  droppedCount: number
  store: LiveStore
  reconnectNow: () => void
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
  const [retryInMs, setRetryInMs] = useState<number | null>(null)
  const [droppedCount, setDroppedCount] = useState(0)
  const lastEventAt = useRef<number | null>(null)
  const store = useMemo(() => new LiveStore(), [missionId])
  const socketRef = useRef<EventSocket | null>(null)

  useEffect(() => {
    if (!missionId) return
    const invalidator = new Invalidator(qc)
    const ctx = {
      qc,
      missionId,
      store,
      invalidator,
      onDropped: () => {
        setDroppedCount((n) => n + 1)
        resynchronise(qc, missionId)
      },
    }

    const socket = new EventSocket(missionId, {
      onEvent: (event) => {
        lastEventAt.current = Date.now()
        applyEvent(ctx, event)
      },
      onStatus: (s, delay) => {
        setStatus(s)
        setRetryInMs(s === 'reconnecting' ? (delay ?? null) : null)
        // A reconnect means we may have missed events while offline.
        if (s === 'open' && lastEventAt.current !== null) resynchronise(qc, missionId)
      },
    })
    socketRef.current = socket
    socket.start()

    return () => {
      socket.stop()
      socketRef.current = null
      invalidator.dispose()
      store.clear()
    }
  }, [missionId, qc, store])

  const value = useMemo<LiveContextValue>(
    () => ({
      status,
      retryInMs,
      lastEventAt: lastEventAt.current,
      droppedCount,
      store,
      reconnectNow: () => socketRef.current?.reconnectNow(),
    }),
    [status, retryInMs, droppedCount, store],
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
