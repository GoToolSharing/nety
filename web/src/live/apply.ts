import type { QueryClient, QueryKey } from '@tanstack/react-query'
import { qk } from '@/lib/queries'
import type {
  Asset,
  Finding,
  Host,
  HostDetail,
  LiveEvent,
  LogLine,
  Network,
  ReachResult,
  Scan,
  ScanProgressEvent,
  Service,
  ServicePage,
} from '@/types/api'
import type { LiveStore } from '@/live/store'

/** Coalesces repeated invalidations of the same key into one per window. */
export class Invalidator {
  private pending = new Map<string, ReturnType<typeof setTimeout>>()
  constructor(
    private qc: QueryClient,
    private delay = 1200,
  ) {}

  schedule(key: QueryKey): void {
    const id = JSON.stringify(key)
    if (this.pending.has(id)) return
    this.pending.set(
      id,
      setTimeout(() => {
        this.pending.delete(id)
        void this.qc.invalidateQueries({ queryKey: key })
      }, this.delay),
    )
  }

  flush(key: QueryKey): void {
    const id = JSON.stringify(key)
    const t = this.pending.get(id)
    if (t) {
      clearTimeout(t)
      this.pending.delete(id)
    }
    void this.qc.invalidateQueries({ queryKey: key })
  }

  dispose(): void {
    for (const t of this.pending.values()) clearTimeout(t)
    this.pending.clear()
  }
}

function upsert<T extends { id: number }>(rows: T[] | undefined, item: T): T[] {
  if (!rows) return [item]
  const i = rows.findIndex((r) => r.id === item.id)
  if (i === -1) return [...rows, item]
  const next = rows.slice()
  next[i] = { ...rows[i], ...item }
  return next
}

/**
 * Patch every cached list whose key is `[root, missionId, filterValue]`,
 * skipping the caches whose filter excludes the incoming row. This is what
 * makes rows appear in open tables without a refetch.
 */
function patchFiltered<T extends { id: number }>(
  qc: QueryClient,
  root: QueryKey,
  item: T,
  matches: (filter: number | null) => boolean,
): void {
  for (const query of qc.getQueryCache().findAll({ queryKey: root })) {
    const filter = (query.queryKey[2] ?? null) as number | null
    if (!matches(filter)) continue
    const data = query.state.data as T[] | undefined
    if (data === undefined) continue
    qc.setQueryData(query.queryKey, upsert(data, item))
  }
}

/**
 * Findings are listed per filter, and triaging one can move it out of the
 * window on screen. Patch the lists whose filter it still matches, drop it
 * from the ones it no longer belongs to, and leave anything else to the
 * throttled refetch.
 *
 * It answers true when a list did not hold the finding at all. The server
 * filters and orders these listings, so where a new row belongs is its answer
 * to give, not something to guess by appending to the end of a sorted table.
 */
function patchFindingLists(qc: QueryClient, missionId: number, f: Finding): boolean {
  let unseen = false
  for (const query of qc.getQueryCache().findAll({ queryKey: qk.findingsRoot(missionId) })) {
    const params = (query.queryKey[2] ?? {}) as { network_id?: number; triage?: string }
    const data = query.state.data as Finding[] | undefined
    if (data === undefined) continue
    if (params.network_id && params.network_id !== f.network_id) continue
    if (params.triage && !params.triage.split(',').includes(f.triage?.status ?? 'todo')) {
      if (data.some((x) => x.id === f.id)) {
        qc.setQueryData(
          query.queryKey,
          data.filter((x) => x.id !== f.id),
        )
      }
      continue
    }
    if (!data.some((x) => x.id === f.id)) {
      unseen = true
      continue
    }
    qc.setQueryData(query.queryKey, upsert(data, f))
  }
  return unseen
}

/**
 * Refresh the rows a cached listing already shows, and answer whether every
 * listing had the row. A listing that does not hold it yet is left to the
 * throttled refetch, for the same reason as the findings above: the server
 * decides what belongs in a filtered, sorted listing and where.
 */
function patchListedRows<T extends { id: number }>(
  qc: QueryClient,
  root: QueryKey,
  item: T,
): boolean {
  let unseen = false
  for (const query of qc.getQueryCache().findAll({ queryKey: root })) {
    const data = query.state.data as T[] | undefined
    if (data === undefined) continue
    if (!data.some((row) => row.id === item.id)) {
      unseen = true
      continue
    }
    qc.setQueryData(query.queryKey, upsert(data, item))
  }
  return unseen
}

/** Services are paginated server-side: patch rows already on screen and let a
 * throttled refetch bring in genuinely new ones without breaking the window. */
function patchServicePages(qc: QueryClient, missionId: number, svc: Service): boolean {
  let touched = false
  for (const query of qc.getQueryCache().findAll({ queryKey: qk.servicesRoot(missionId) })) {
    const page = query.state.data as ServicePage | undefined
    if (!page?.items) continue
    const i = page.items.findIndex((s) => s.id === svc.id)
    if (i === -1) continue
    const items = page.items.slice()
    items[i] = { ...items[i], ...svc }
    qc.setQueryData(query.queryKey, { ...page, items })
    touched = true
  }
  return touched
}

export interface ApplyContext {
  qc: QueryClient
  missionId: number
  store: LiveStore
  invalidator: Invalidator
  /** Called when the server reports it dropped events for this client. */
  onDropped: () => void
}

const DROPPED_MARKER = 'events dropped'
/** What the server says after a triage change that moves whole tables. */
const TRIAGE_MARKER = 'triage updated'

export function applyEvent(ctx: ApplyContext, ev: LiveEvent): void {
  const { qc, missionId, store, invalidator } = ctx
  if (ev.mission_id && ev.mission_id !== missionId) return
  const scanId = ev.scan_id ?? 0

  switch (ev.type) {
    case 'scan.status':
    case 'scan.phase': {
      // These carry the whole scan object.
      const scan = ev.data as Scan
      if (!scan?.id) return
      qc.setQueryData(qk.scan(scan.id), (old: Scan | undefined) =>
        old ? { ...old, ...scan } : scan,
      )
      qc.setQueryData(qk.scans(missionId), (old: Scan[] | undefined) =>
        old ? upsert(old, scan) : old,
      )
      if (ev.type === 'scan.status') {
        // A finished scan changes every count on the overview.
        invalidator.schedule(qk.summary(missionId))
        if (
          scan.status === 'completed' ||
          scan.status === 'failed' ||
          scan.status === 'cancelled'
        ) {
          invalidator.schedule(qk.scans(missionId))
        }
      }
      return
    }

    case 'scan.progress': {
      // A partial update: {scan_id, phase, progress, stats, phases}.
      const p = ev.data as ScanProgressEvent
      const id = p?.scan_id || scanId
      if (!id) return
      const patch = (old: Scan | undefined): Scan | undefined =>
        old
          ? {
              ...old,
              phase: p.phase ?? old.phase,
              progress: typeof p.progress === 'number' ? p.progress : old.progress,
              stats: p.stats ?? old.stats,
              phases: p.phases ?? old.phases,
            }
          : old
      qc.setQueryData(qk.scan(id), patch)
      qc.setQueryData(qk.scans(missionId), (old: Scan[] | undefined) =>
        old?.map((s) => (s.id === id ? (patch(s) as Scan) : s)),
      )
      return
    }

    case 'scan.log': {
      const line = ev.data as LogLine
      if (!line) return
      if (
        line.level === 'warn' &&
        typeof line.message === 'string' &&
        line.message.toLowerCase().includes(DROPPED_MARKER)
      ) {
        ctx.onDropped()
      } else if (
        line.level === 'info' &&
        typeof line.message === 'string' &&
        line.message.toLowerCase().includes(TRIAGE_MARKER)
      ) {
        // Someone skipped a host or a machine, or triaged a batch. That moves
        // rows in and out of tables wholesale rather than one at a time, so
        // the only honest answer is to refetch the ones it touches.
        for (const key of [
          qk.hostsRoot(missionId),
          qk.servicesRoot(missionId),
          qk.findingsRoot(missionId),
          qk.reachRoot(missionId),
          qk.matrix(missionId),
          qk.triageSummaryRoot(missionId),
          qk.summary(missionId),
        ]) {
          invalidator.schedule(key)
        }
      }
      store.addLog(scanId, {
        time: ev.time,
        level: line.level || 'info',
        message: line.message ?? '',
      })
      return
    }

    case 'host': {
      const host = ev.data as Host
      if (!host?.id) return
      if (patchListedRows(qc, qk.hostsRoot(missionId), host)) {
        invalidator.schedule(qk.hostsRoot(missionId))
      }
      if (scanId) store.addHost(scanId, host)
      invalidator.schedule(qk.summary(missionId))
      return
    }

    case 'service': {
      const svc = ev.data as Service
      if (!svc?.id) return
      const patched = patchServicePages(qc, missionId, svc)
      if (!patched) invalidator.schedule(qk.servicesRoot(missionId))
      qc.setQueryData(qk.host(svc.host_id), (old: HostDetail | undefined) =>
        old ? { ...old, services: upsert(old.services ?? [], svc) } : old,
      )
      if (scanId) store.addService(scanId, svc)
      invalidator.schedule(qk.summary(missionId))
      return
    }

    case 'finding': {
      const f = ev.data as Finding
      if (!f?.id) return
      if (patchFindingLists(qc, missionId, f)) {
        invalidator.schedule(qk.findingsRoot(missionId))
      }
      if (scanId) store.addFinding(scanId, f)
      invalidator.schedule(qk.summary(missionId))
      return
    }

    case 'reach': {
      const r = ev.data as ReachResult
      if (!r?.id) return
      patchFiltered(
        qc,
        qk.reachRoot(missionId),
        r,
        (flt) => flt === null || flt === r.source_network_id,
      )
      if (scanId) store.addReach(scanId, r)
      invalidator.schedule(qk.matrix(missionId))
      return
    }

    case 'asset': {
      const a = ev.data as Asset
      if (!a?.id) return
      if (patchListedRows(qc, qk.assetsRoot(missionId), a)) {
        invalidator.schedule(qk.assetsRoot(missionId))
      }
      qc.setQueryData(qk.asset(a.id), a)
      invalidator.schedule(qk.summary(missionId))
      return
    }

    case 'network': {
      const n = ev.data as Network
      if (!n?.id) return
      qc.setQueryData(qk.networks(missionId), (old: Network[] | undefined) =>
        old ? upsert(old, n) : old,
      )
      return
    }
  }
}

/** Refetch everything that could have gone stale while events were dropped. */
export function resynchronise(qc: QueryClient, missionId: number): void {
  const keys: QueryKey[] = [
    qk.scans(missionId),
    qk.networks(missionId),
    qk.hostsRoot(missionId),
    qk.servicesRoot(missionId),
    qk.findingsRoot(missionId),
    qk.assetsRoot(missionId),
    qk.reachRoot(missionId),
    qk.matrix(missionId),
    qk.triageSummaryRoot(missionId),
    qk.summary(missionId),
  ]
  for (const key of keys) void qc.invalidateQueries({ queryKey: key })
  void qc.invalidateQueries({ queryKey: ['scan'] })
}
