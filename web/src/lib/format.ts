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

const RELATIVE_STEPS: [
  limit: number,
  divisor: number,
  unit: Intl.RelativeTimeFormatUnit,
][] = [
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

/** "src-port-53" -> "Src port 53": readable label for an id-ish string. */
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

function isIPv4(s: string): boolean {
  const parts = s.split('.')
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
}

function isIPv6(s: string): boolean {
  // At most one "::" run; everything else is hextets, with an optional IPv4
  // tail standing for the last two of them.
  const halves = s.split('::')
  if (halves.length > 2) return false
  const compressed = halves.length === 2
  const split = (part: string) => (part === '' ? [] : part.split(':'))
  const groups = [...split(halves[0]), ...(compressed ? split(halves[1]) : [])]
  if (groups.some((g) => g === '')) return false
  const last = groups[groups.length - 1] ?? ''
  const hasV4Tail = last.includes('.')
  if (hasV4Tail && !isIPv4(last)) return false
  const hextets = hasV4Tail ? groups.slice(0, -1) : groups
  if (hextets.some((g) => !/^[0-9a-fA-F]{1,4}$/.test(g))) return false
  // An IPv4 tail stands for two hextets, and the group holding it was already
  // counted as one.
  const count = groups.length + (hasV4Tail ? 1 : 0)
  return compressed ? count <= 7 : count === 8
}

/**
 * True when the text is a complete address or CIDR prefix, v4 or v6.
 *
 * The address filter is only sent once it passes this, so typing half a subnet
 * does not blank the table with a 400 at every keystroke. The server parses it
 * again and is the one that refuses what it cannot read.
 */
export function isAddressOrPrefix(value: string): boolean {
  const v = value.trim()
  if (!v) return false
  const slash = v.indexOf('/')
  const address = slash === -1 ? v : v.slice(0, slash)
  const v6 = address.includes(':')
  if (!(v6 ? isIPv6(address) : isIPv4(address))) return false
  if (slash === -1) return true
  const bits = v.slice(slash + 1)
  return /^\d{1,3}$/.test(bits) && Number(bits) <= (v6 ? 128 : 32)
}

const dayMonthFmt = new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' })

/** Short calendar date, for an address history: "3 Nov". */
export function formatDay(value: string | null | undefined): string {
  const d = parseDate(value)
  return d ? dayMonthFmt.format(d) : '?'
}

/** What the history adds to one of a machine's addresses. */
export interface AddressHistoryMark {
  /** True while the machine is still answering there. */
  current: boolean
  /** "since 5 Nov" for an address it still has, "until 3 Nov" for one it left. */
  label: string
}

/** The shape addressHistory needs of an address; anything else rides along. */
interface SeenAddress {
  ip: string
  first_seen: string
  last_seen: string
}

/**
 * How far behind the machine's latest sighting an address may be and still
 * count as current. A scan is a day's work and its phases do not all reach
 * every address at the same minute, so anything seen in the same pass is "it
 * is there now"; an address last seen before that is one the machine has left.
 */
const STILL_CURRENT_MS = 6 * 60 * 60 * 1000

/**
 * The address history of a machine: where it was, where it is, and since or
 * until when. This is the payoff of the identity correlation, and the only
 * place the operator sees that a machine moved rather than that a new one
 * appeared.
 *
 * Addresses it has left come first, oldest departure first, then the ones it
 * still answers on, so the list reads as a timeline.
 */
export function addressHistory<T extends SeenAddress>(
  ips: T[] | null | undefined,
): (T & AddressHistoryMark)[] {
  const rows = ips ?? []
  if (rows.length === 0) return []
  const latest = Math.max(...rows.map((ip) => parseDate(ip.last_seen)?.getTime() ?? 0))
  const entries = rows.map((ip) => {
    const seen = parseDate(ip.last_seen)?.getTime() ?? 0
    const current = latest - seen <= STILL_CURRENT_MS
    return {
      ...ip,
      current,
      label: current
        ? `since ${formatDay(ip.first_seen)}`
        : `until ${formatDay(ip.last_seen)}`,
    }
  })
  return entries.sort((a, b) => {
    if (a.current !== b.current) return a.current ? 1 : -1
    const key = a.current ? 'first_seen' : 'last_seen'
    return a[key].localeCompare(b[key])
  })
}

/** The address history as one line: "10.20.0.7 until 3 Nov, 10.20.0.12 since 5 Nov". */
export function formatAddressHistory(ips: SeenAddress[] | null | undefined): string {
  return addressHistory(ips)
    .map((e) => `${e.ip} ${e.label}`)
    .join(', ')
}

/** Truncate for display without breaking the layout. */
export function truncate(s: string, max: number): string {
  if (!s) return ''
  return s.length <= max ? s : s.slice(0, max - 1) + '…'
}
