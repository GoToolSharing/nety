const numberFmt = new Intl.NumberFormat(undefined)
const compactFmt = new Intl.NumberFormat(undefined, {
  notation: 'compact',
  maximumFractionDigits: 1,
})
const dateTimeFmt = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'medium',
})
const timeFmt = new Intl.DateTimeFormat(undefined, { timeStyle: 'medium' })

export function formatNumber(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '-'
  return numberFmt.format(n)
}

export function formatCompact(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '-'
  return Math.abs(n) >= 10000 ? compactFmt.format(n) : numberFmt.format(n)
}

export function formatPercent(fraction: number | null | undefined, digits = 0): string {
  if (fraction === null || fraction === undefined || Number.isNaN(fraction)) return '-'
  const clamped = Math.max(0, Math.min(1, fraction))
  return `${(clamped * 100).toFixed(digits)}%`
}

/** Human duration from seconds: "4s", "2m 10s", "1h 06m", "2d 3h". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return '-'
  const s = Math.max(0, Math.round(seconds))
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, '0')}m`
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`
}

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '-'
  if (ms < 1) return `${ms.toFixed(2)} ms`
  if (ms < 1000) return `${ms.toFixed(1)} ms`
  return formatDuration(ms / 1000)
}

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return '-'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i++
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[i]}`
}

export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? null : d
}

/** Absolute timestamp, used for the title attribute of relative times. */
export function formatAbsolute(value: string | Date | null | undefined): string {
  const d = value instanceof Date ? value : parseDate(value)
  if (!d) return '-'
  return dateTimeFmt.format(d)
}

export function formatClock(value: string | Date | null | undefined): string {
  const d = value instanceof Date ? value : parseDate(value)
  if (!d) return '-'
  return timeFmt.format(d)
}

const RELATIVE_STEPS: [limit: number, divisor: number, unit: Intl.RelativeTimeFormatUnit][] =
  [
    [60, 1, 'second'],
    [3600, 60, 'minute'],
    [86400, 3600, 'hour'],
    [604800, 86400, 'day'],
    [2629800, 604800, 'week'],
    [31557600, 2629800, 'month'],
    [Infinity, 31557600, 'year'],
  ]

const relFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

export function formatRelative(value: string | Date | null | undefined): string {
  const d = value instanceof Date ? value : parseDate(value)
  if (!d) return '-'
  const deltaSeconds = (d.getTime() - Date.now()) / 1000
  const abs = Math.abs(deltaSeconds)
  if (abs < 5) return 'just now'
  for (const [limit, divisor, unit] of RELATIVE_STEPS) {
    if (abs < limit) return relFmt.format(Math.round(deltaSeconds / divisor), unit)
  }
  return formatAbsolute(d)
}

/** Elapsed time between two instants (end defaults to now). */
export function elapsedSeconds(
  start: string | null | undefined,
  end?: string | null,
): number | null {
  const a = parseDate(start)
  if (!a) return null
  const b = parseDate(end ?? null) ?? new Date()
  return (b.getTime() - a.getTime()) / 1000
}

export function titleCase(s: string): string {
  if (!s) return ''
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/** "src-port-53" -> "Src port 53" - readable label for an id-ish string. */
export function humanizeId(s: string): string {
  if (!s) return ''
  return titleCase(s.replace(/[-_]+/g, ' '))
}

/** Natural IPv4/IPv6 sort key so 10.0.0.9 comes before 10.0.0.10. */
export function ipSortKey(ip: string): string {
  if (!ip) return ''
  if (ip.includes(':')) return ip.toLowerCase()
  const parts = ip.split('.')
  if (parts.length !== 4) return ip
  return parts.map((p) => p.padStart(3, '0')).join('.')
}

export function compareIP(a: string, b: string): number {
  return ipSortKey(a).localeCompare(ipSortKey(b))
}

/** Truncate for display without breaking the layout. */
export function truncate(s: string, max: number): string {
  if (!s) return ''
  return s.length <= max ? s : s.slice(0, max - 1) + '…'
}
