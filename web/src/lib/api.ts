import type {
  ApiErrorBody,
  Asset,
  AssetPatch,
  AuditEntry,
  CheckInfo,
  ExportFormat,
  Finding,
  Host,
  HostDetail,
  InterfaceInfo,
  Matrix,
  Mission,
  MissionInput,
  MissionSummary,
  Network,
  NetworkInput,
  ReachResult,
  Role,
  Scan,
  ScanInput,
  ScanLogLine,
  ScanProfileInfo,
  ServerStatus,
  Service,
  ServicePage,
  SessionInfo,
  TechniqueInfo,
  User,
} from '@/types/api'

export class ApiError extends Error {
  status: number
  code: string
  constructor(status: number, message: string, code = '') {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

/** Fired when any request comes back 401 so the app can bounce to /login. */
export const UNAUTHORIZED_EVENT = 'nety:unauthorized'

export function readCookie(name: string): string {
  const prefix = name + '='
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) return decodeURIComponent(part.slice(prefix.length))
  }
  return ''
}

export function csrfToken(): string {
  return readCookie('nety_csrf')
}

/**
 * The API base path is `/api` on the same origin (docs/API.md). Absolute from
 * the origin root so a deep SPA route such as /missions/3/scans/7 does not
 * turn a relative request into /missions/3/scans/api/....
 */
export function apiUrl(path: string): string {
  return new URL('/' + path.replace(/^\//, ''), window.location.origin).toString()
}

export function wsUrl(path: string): string {
  const u = new URL(apiUrl(path))
  u.protocol = u.protocol === 'https:' ? 'wss:' : 'ws:'
  return u.toString()
}

type Query = Record<string, string | number | boolean | undefined | null>

function withQuery(path: string, query?: Query): string {
  if (!query) return path
  const parts: string[] = []
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null || v === '') continue
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  }
  return parts.length ? `${path}?${parts.join('&')}` : path
}

interface RequestOptions {
  method?: string
  body?: unknown
  query?: Query
  signal?: AbortSignal
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD') {
    const token = csrfToken()
    if (token) headers['X-CSRF-Token'] = token
  }

  let res: Response
  try {
    res = await fetch(apiUrl(withQuery(path, opts.query)), {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      signal: opts.signal,
    })
  } catch (err) {
    if ((err as Error)?.name === 'AbortError') throw err
    throw new ApiError(0, 'Cannot reach the NETY server.', 'network')
  }

  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT))
    throw new ApiError(401, 'Your session has expired.', 'unauthorized')
  }

  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`
    let code = ''
    try {
      const body = (await res.json()) as ApiErrorBody
      if (body?.error) message = body.error
      if (body?.code) code = body.code
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message, code)
  }

  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

/** Some list handlers may return `null` for an empty slice (Go nil slice). */
function list<T>(v: T[] | null | undefined): T[] {
  return Array.isArray(v) ? v : []
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

export const api = {
  // --- session -------------------------------------------------------------
  login: (username: string, password: string) =>
    request<SessionInfo>('api/auth/login', { method: 'POST', body: { username, password } }),
  logout: () => request<void>('api/auth/logout', { method: 'POST' }),
  me: () => request<SessionInfo>('api/auth/me'),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('api/auth/password', {
      method: 'POST',
      body: { current_password, new_password },
    }),

  // --- users ---------------------------------------------------------------
  users: async () => list(await request<User[] | null>('api/users')),
  createUser: (body: {
    username: string
    display_name: string
    role: Role
    password: string
  }) => request<User>('api/users', { method: 'POST', body }),
  patchUser: (
    id: number,
    body: { display_name?: string; role?: Role; disabled?: boolean },
  ) => request<User>(`api/users/${id}`, { method: 'PATCH', body }),
  setUserPassword: (id: number, new_password: string, must_change: boolean) =>
    request<void>(`api/users/${id}/password`, {
      method: 'POST',
      body: { new_password, must_change },
    }),
  deleteUser: (id: number) => request<void>(`api/users/${id}`, { method: 'DELETE' }),

  // --- missions ------------------------------------------------------------
  missions: async () => list(await request<Mission[] | null>('api/missions')),
  mission: (id: number) => request<Mission>(`api/missions/${id}`),
  createMission: (body: MissionInput) =>
    request<Mission>('api/missions', { method: 'POST', body }),
  patchMission: (id: number, body: Partial<MissionInput>) =>
    request<Mission>(`api/missions/${id}`, { method: 'PATCH', body }),
  deleteMission: (id: number) => request<void>(`api/missions/${id}`, { method: 'DELETE' }),
  missionMembers: async (id: number) =>
    list(await request<number[] | null>(`api/missions/${id}/members`)),
  setMissionMembers: (id: number, user_ids: number[]) =>
    request<void>(`api/missions/${id}/members`, { method: 'PUT', body: { user_ids } }),
  missionSummary: (id: number) => request<MissionSummary>(`api/missions/${id}/summary`),

  // --- networks ------------------------------------------------------------
  networks: async (missionId: number) =>
    list(await request<Network[] | null>(`api/missions/${missionId}/networks`)),
  createNetwork: (missionId: number, body: NetworkInput) =>
    request<Network>(`api/missions/${missionId}/networks`, { method: 'POST', body }),
  network: (id: number) => request<Network>(`api/networks/${id}`),
  patchNetwork: (id: number, body: Partial<NetworkInput>) =>
    request<Network>(`api/networks/${id}`, { method: 'PATCH', body }),
  deleteNetwork: (id: number) => request<void>(`api/networks/${id}`, { method: 'DELETE' }),
  interfaces: async () => list(await request<InterfaceInfo[] | null>('api/interfaces')),
  detectNetwork: (iface?: string) =>
    request<Network>('api/networks/detect', {
      method: 'POST',
      body: { interface: iface ?? '' },
    }),

  // --- scans ---------------------------------------------------------------
  scans: async (missionId: number) =>
    list(await request<Scan[] | null>(`api/missions/${missionId}/scans`)),
  scan: (id: number) => request<Scan>(`api/scans/${id}`),
  createScan: (missionId: number, body: ScanInput) =>
    request<Scan>(`api/missions/${missionId}/scans`, { method: 'POST', body }),
  deleteScan: (id: number) => request<void>(`api/scans/${id}`, { method: 'DELETE' }),
  startScan: (id: number) => request<Scan>(`api/scans/${id}/start`, { method: 'POST' }),
  pauseScan: (id: number) => request<Scan>(`api/scans/${id}/pause`, { method: 'POST' }),
  stopScan: (id: number) => request<Scan>(`api/scans/${id}/stop`, { method: 'POST' }),
  retryFailed: (id: number) =>
    request<Scan>(`api/scans/${id}/retry-failed`, { method: 'POST' }),
  scanLogs: async (id: number, after = 0, limit = 500) =>
    list(
      await request<ScanLogLine[] | null>(`api/scans/${id}/logs`, {
        query: { after, limit },
      }),
    ),
  scanProfiles: async () =>
    list(await request<ScanProfileInfo[] | null>('api/scan-profiles')),
  techniques: async () => list(await request<TechniqueInfo[] | null>('api/techniques')),
  checks: async () => list(await request<CheckInfo[] | null>('api/checks')),

  // --- results -------------------------------------------------------------
  hosts: async (missionId: number, networkId?: number) =>
    list(
      await request<Host[] | null>(`api/missions/${missionId}/hosts`, {
        query: { network_id: networkId },
      }),
    ),
  host: (id: number) => request<HostDetail>(`api/hosts/${id}`),
  services: async (
    missionId: number,
    params: {
      network_id?: number
      host_id?: number
      port?: number
      protocol?: string
      q?: string
      limit?: number
      offset?: number
    } = {},
  ): Promise<ServicePage> => {
    const limit = params.limit ?? 0
    const offset = params.offset ?? 0
    const raw = await request<Service[] | null>(`api/missions/${missionId}/services`, {
      query: params,
    })
    const items = list(raw)
    // The handler returns a bare slice, so a full page means "there may be
    // more"; a short page is the last one.
    return { items, has_more: limit > 0 && items.length >= limit, limit, offset }
  },
  findings: async (missionId: number, networkId?: number) =>
    list(
      await request<Finding[] | null>(`api/missions/${missionId}/findings`, {
        query: { network_id: networkId },
      }),
    ),
  assets: async (missionId: number) =>
    list(await request<Asset[] | null>(`api/missions/${missionId}/assets`)),
  asset: (id: number) => request<Asset>(`api/assets/${id}`),
  patchAsset: (id: number, body: AssetPatch) =>
    request<Asset>(`api/assets/${id}`, { method: 'PATCH', body }),
  mergeAssets: (id: number, source_id: number) =>
    request<Asset>(`api/assets/${id}/merge`, { method: 'POST', body: { source_id } }),
  matrix: (missionId: number) => request<Matrix>(`api/missions/${missionId}/matrix`),
  reach: async (missionId: number, sourceNetworkId?: number) =>
    list(
      await request<ReachResult[] | null>(`api/missions/${missionId}/reach`, {
        query: { source_network_id: sourceNetworkId },
      }),
    ),

  // --- exports -------------------------------------------------------------
  exportFormats: async () =>
    list(await request<ExportFormat[] | null>('api/export-formats')),
  exportUrl: (missionId: number, format: string, networkId?: number) =>
    apiUrl(
      withQuery(`api/missions/${missionId}/export`, {
        format,
        network_id: networkId,
      }),
    ),

  // --- misc ----------------------------------------------------------------
  status: () => request<ServerStatus>('api/status'),
  audit: async (params: { limit?: number; mission_id?: number } = {}) =>
    list(await request<AuditEntry[] | null>('api/audit', { query: params })),
}
