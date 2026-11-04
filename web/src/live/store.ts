import type { Finding, Host, ReachResult, ScanLogLine, Service } from '@/types/api'

const MAX_LOGS = 3000
const MAX_ROWS = 2000

export interface ScanBuffers {
  logs: ScanLogLine[]
  hosts: Map<number, Host>
  services: Map<number, Service>
  findings: Map<number, Finding>
  reach: ReachResult[]
  /** Monotonic counter bumped on every row so tables can flash new entries. */
  seen: Map<number, number>
}

function emptyBuffers(): ScanBuffers {
  return {
    logs: [],
    hosts: new Map(),
    services: new Map(),
    findings: new Map(),
    reach: [],
    seen: new Map(),
  }
}

/**
 * Mutable store for the high-frequency part of the live stream (log lines and
 * freshly streamed rows of the scan currently open). Kept outside React state
 * and read through useSyncExternalStore so a scan emitting hundreds of events
 * per second causes one coalesced render per frame window rather than one per
 * event.
 */
export class LiveStore {
  private scans = new Map<number, ScanBuffers>()
  private listeners = new Set<() => void>()
  private version = 0
  private flushTimer: ReturnType<typeof setTimeout> | null = null
  private logSeq = -1

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => {
      this.listeners.delete(listener)
    }
  }

  getSnapshot = (): number => this.version

  buffers(scanId: number): ScanBuffers | undefined {
    return this.scans.get(scanId)
  }

  private ensure(scanId: number): ScanBuffers {
    let b = this.scans.get(scanId)
    if (!b) {
      b = emptyBuffers()
      this.scans.set(scanId, b)
    }
    return b
  }

  /** Coalesce notifications into one per ~120 ms. */
  private touch(): void {
    if (this.flushTimer) return
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null
      this.version++
      for (const l of this.listeners) l()
    }, 120)
  }

  /** Seed the log pane from GET /api/scans/{id}/logs. */
  seedLogs(scanId: number, lines: ScanLogLine[]): void {
    const b = this.ensure(scanId)
    const known = new Set(b.logs.map((l) => l.id))
    const merged = [...lines.filter((l) => !known.has(l.id)), ...b.logs]
    merged.sort((a, b2) => a.id - b2.id)
    b.logs = merged.slice(-MAX_LOGS)
    this.touch()
  }

  addLog(scanId: number, line: Omit<ScanLogLine, 'id'> & { id?: number }): void {
    const b = this.ensure(scanId)
    const id = line.id ?? this.logSeq--
    b.logs.push({ ...line, id })
    if (b.logs.length > MAX_LOGS) b.logs.splice(0, b.logs.length - MAX_LOGS)
    this.touch()
  }

  addHost(scanId: number, host: Host): void {
    const b = this.ensure(scanId)
    if (!b.hosts.has(host.id)) this.mark(b, host.id)
    b.hosts.set(host.id, host)
    trim(b.hosts)
    this.touch()
  }

  addService(scanId: number, svc: Service): void {
    const b = this.ensure(scanId)
    if (!b.services.has(svc.id)) this.mark(b, svc.id)
    b.services.set(svc.id, svc)
    trim(b.services)
    this.touch()
  }

  addFinding(scanId: number, f: Finding): void {
    const b = this.ensure(scanId)
    if (!b.findings.has(f.id)) this.mark(b, f.id)
    b.findings.set(f.id, f)
    trim(b.findings)
    this.touch()
  }

  addReach(scanId: number, r: ReachResult): void {
    const b = this.ensure(scanId)
    b.reach.push(r)
    if (b.reach.length > MAX_ROWS) b.reach.splice(0, b.reach.length - MAX_ROWS)
    this.touch()
  }

  private mark(b: ScanBuffers, id: number): void {
    b.seen.set(id, Date.now())
    if (b.seen.size > MAX_ROWS * 2) {
      const cutoff = Date.now() - 10_000
      for (const [k, v] of b.seen) if (v < cutoff) b.seen.delete(k)
    }
  }

  /** Drop a scan's buffers when its page unmounts. */
  release(scanId: number): void {
    this.scans.delete(scanId)
  }

  clear(): void {
    this.scans.clear()
    this.version++
    for (const l of this.listeners) l()
  }
}

function trim<T>(m: Map<number, T>): void {
  if (m.size <= MAX_ROWS) return
  const excess = m.size - MAX_ROWS
  let i = 0
  for (const k of m.keys()) {
    m.delete(k)
    if (++i >= excess) break
  }
}
