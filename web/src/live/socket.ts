import { wsUrl } from '@/lib/api'
import type { LiveEvent } from '@/types/api'

export type SocketStatus = 'connecting' | 'open' | 'reconnecting' | 'closed'

interface SocketHandlers {
  onEvent: (event: LiveEvent) => void
  onStatus: (status: SocketStatus, nextRetryInMs?: number) => void
}

const BASE_DELAY = 500
const MAX_DELAY = 30_000

/**
 * One WebSocket to /api/missions/{id}/events with exponential backoff and
 * full jitter. The server pings every 30 s and the browser answers pongs on
 * its own (ping frames are never surfaced to JS), which keeps middleboxes
 * from dropping an idle mission and makes a dead link surface as `onclose`.
 */
export class EventSocket {
  private url: string
  private handlers: SocketHandlers
  private ws: WebSocket | null = null
  private attempt = 0
  private retryTimer: ReturnType<typeof setTimeout> | null = null
  private stopped = false

  constructor(missionId: number, handlers: SocketHandlers) {
    this.url = wsUrl(`api/missions/${missionId}/events`)
    this.handlers = handlers
  }

  start(): void {
    this.stopped = false
    this.open()
  }

  stop(): void {
    this.stopped = true
    if (this.retryTimer) clearTimeout(this.retryTimer)
    this.retryTimer = null
    const ws = this.ws
    this.ws = null
    if (ws) {
      ws.onclose = null
      ws.onerror = null
      ws.onmessage = null
      ws.onopen = null
      try {
        ws.close(1000, 'client navigating away')
      } catch {
        /* already closing */
      }
    }
    this.handlers.onStatus('closed')
  }

  /** Force an immediate reconnect (used by the "reconnect now" button). */
  reconnectNow(): void {
    if (this.stopped) return
    if (this.retryTimer) clearTimeout(this.retryTimer)
    this.retryTimer = null
    this.attempt = 0
    if (this.ws) {
      try {
        this.ws.close()
      } catch {
        /* ignore */
      }
      return // onclose schedules the reconnect
    }
    this.open()
  }

  private open(): void {
    if (this.stopped) return
    this.handlers.onStatus(this.attempt === 0 ? 'connecting' : 'reconnecting')
    let ws: WebSocket
    try {
      ws = new WebSocket(this.url)
    } catch {
      this.scheduleRetry()
      return
    }
    this.ws = ws

    ws.onopen = () => {
      if (this.stopped) return
      this.attempt = 0
      this.handlers.onStatus('open')
    }

    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return
      for (const line of ev.data.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed) continue
        try {
          this.handlers.onEvent(JSON.parse(trimmed) as LiveEvent)
        } catch {
          /* a malformed frame must never kill the stream */
        }
      }
    }

    ws.onerror = () => {
      /* onclose always follows; nothing to do here */
    }

    ws.onclose = () => {
      if (this.ws === ws) this.ws = null
      if (this.stopped) return
      this.scheduleRetry()
    }
  }

  private scheduleRetry(): void {
    if (this.stopped || this.retryTimer) return
    const exponential = Math.min(MAX_DELAY, BASE_DELAY * 2 ** this.attempt)
    // Full jitter, so a server restart does not get a thundering herd.
    const delay = Math.round(exponential / 2 + Math.random() * (exponential / 2))
    this.attempt = Math.min(this.attempt + 1, 10)
    this.handlers.onStatus('reconnecting', delay)
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null
      this.open()
    }, delay)
  }
}
