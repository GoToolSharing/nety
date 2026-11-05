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
  MissionMember,
  MissionImportResult,
  MissionResetCounts,
  MissionSummary,
  Network,
  NetworkInput,
  ReachResult,
  Role,
  Scan,
  ScanDiff,
  ScanInput,
  ScanLogLine,
  ScanProfileInfo,
  ServerStatus,
  Service,
  ServicePage,
  SessionInfo,
  TechniqueInfo,
  TriageStatus,
  TriageSummary,
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

/**
 * The parameters every result listing shares: a network, an address or CIDR
 * prefix, and the column the server orders by.
 */
export type ListParams = {
  network_id?: number
  ip?: string
  sort?: string
  dir?: 'asc' | 'desc'
}

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
  // A FormData body carries its own content type, including the multipart
  // boundary the browser generates, so setting one here would break the
  // upload. Everything else is JSON.
  const isForm = typeof FormData !== 'undefined' && opts.body instanceof FormData
  if (opts.body !== undefined && !isForm) headers['Content-Type'] = 'application/json'
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
      body:
        opts.body === undefined
          ? undefined
          : isForm
            ? (opts.body as FormData)
            : JSON.stringify(opts.body),
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
  // The mission name has to be typed back, so the server refuses a reset that
  // was fired from the wrong tab.
  resetMission: (id: number, confirm: string) =>
    request<MissionResetCounts>(`api/missions/${id}/reset`, {
      method: 'POST',
      body: { confirm },
    }),
  // The handler answers the people as well as their ids: listing every account
  // is admin-only, so an operator needs the names to come back with the ids.
  missionMembers: async (id: number) => {
    const r = await request<{ user_ids: number[] | null; members: MissionMember[] | null }>(
      `api/missions/${id}/members`,
    )
    return { ids: list(r.user_ids), members: list(r.members) }
  },
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
  /**
   * What changed between two scans of the same network. Leaving `against`
   * out lets the server pick the most recent earlier completed scan, and the
   * answer says which one that was.
   */
  scanDiff: (missionId: number, scanId: number, against?: number) =>
    request<ScanDiff>(`api/missions/${missionId}/scans/${scanId}/diff`, {
      query: { against },
    }),
  scanProfiles: async () =>
    list(await request<ScanProfileInfo[] | null>('api/scan-profiles')),
  techniques: async () => list(await request<TechniqueInfo[] | null>('api/techniques')),
  checks: async () => list(await request<CheckInfo[] | null>('api/checks')),

  // --- results -------------------------------------------------------------
  /**
   * `ip` takes one address or a CIDR prefix; `sort` and `dir` order the whole
   * listing in SQL, not the rows that happen to be on screen.
   */
  hosts: async (missionId: number, params: ListParams = {}) =>
    list(await request<Host[] | null>(`api/missions/${missionId}/hosts`, { query: params })),
  host: (id: number) => request<HostDetail>(`api/hosts/${id}`),

  /** Record a status, a note, or both on one address. */
  triageHost: (id: number, body: { status?: TriageStatus; note?: string }) =>
    request<Host>(`api/hosts/${id}`, { method: 'PATCH', body }),

  /** Apply one status to a selection of addresses in a single call. */
  triageHostsBulk: (missionId: number, hostIds: number[], status: TriageStatus) =>
    request<{ updated: number; status: TriageStatus }>(
      `api/missions/${missionId}/hosts/triage`,
      { method: 'POST', body: { host_ids: hostIds, status } },
    ),

  services: async (
    missionId: number,
    params: ListParams & {
      host_id?: number
      port?: number
      protocol?: string
      q?: string
      triage?: string
      /** Show the services of hosts the operator has skipped. */
      include_skipped?: boolean
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
  service: (id: number) => request<Service>(`api/services/${id}`),

  /** Record a status, a note, or both. A field left out is left alone. */
  triageService: (id: number, body: { status?: TriageStatus; note?: string }) =>
    request<Service>(`api/services/${id}`, { method: 'PATCH', body }),

  /** Apply one status to a selection in a single call. */
  triageBulk: (missionId: number, serviceIds: number[], status: TriageStatus) =>
    request<{ updated: number; status: TriageStatus }>(
      `api/missions/${missionId}/services/triage`,
      { method: 'POST', body: { service_ids: serviceIds, status } },
    ),

  triageSummary: (missionId: number, networkId?: number) =>
    request<TriageSummary>(`api/missions/${missionId}/triage`, {
      query: { network_id: networkId },
    }),

  findings: async (
    missionId: number,
    params: ListParams & {
      host_id?: number
      triage?: string
      /** Show the findings of hosts the operator has skipped. */
      include_skipped?: boolean
    } = {},
  ) => list(await request<Finding[] | null>(`api/missions/${missionId}/findings`, { query: params })),
  finding: (id: number) => request<Finding>(`api/findings/${id}`),

  /** Record a status, a note, or both. A field left out is left alone. */
  triageFinding: (id: number, body: { status?: TriageStatus; note?: string }) =>
    request<Finding>(`api/findings/${id}`, { method: 'PATCH', body }),

  /** Apply one status to a selection in a single call. */
  triageFindingsBulk: (missionId: number, findingIds: number[], status: TriageStatus) =>
    request<{ updated: number; status: TriageStatus }>(
      `api/missions/${missionId}/findings/triage`,
      { method: 'POST', body: { finding_ids: findingIds, status } },
    ),

  assets: async (missionId: number, params: ListParams = {}) =>
    list(await request<Asset[] | null>(`api/missions/${missionId}/assets`, { query: params })),
  asset: (id: number) => request<Asset>(`api/assets/${id}`),
  patchAsset: (id: number, body: AssetPatch) =>
    request<Asset>(`api/assets/${id}`, { method: 'PATCH', body }),

  /**
   * Triage a machine. The same endpoint as any other edit, because a machine
   * is one thing; the status reaches every address of it.
   */
  triageAsset: (id: number, body: { status?: TriageStatus; note?: string }) =>
    request<Asset>(`api/assets/${id}`, { method: 'PATCH', body }),

  /** Apply one status to a selection of machines in a single call. */
  triageAssetsBulk: (missionId: number, assetIds: number[], status: TriageStatus) =>
    request<{ updated: number; status: TriageStatus }>(
      `api/missions/${missionId}/assets/triage`,
      { method: 'POST', body: { asset_ids: assetIds, status } },
    ),

  mergeAssets: (id: number, source_id: number) =>
    request<Asset>(`api/assets/${id}/merge`, { method: 'POST', body: { source_id } }),
  matrix: (missionId: number, includeSkipped?: boolean) =>
    request<Matrix>(`api/missions/${missionId}/matrix`, {
      query: { include_skipped: includeSkipped },
    }),
  reach: async (missionId: number, sourceNetworkId?: number, includeSkipped?: boolean) =>
    list(
      await request<ReachResult[] | null>(`api/missions/${missionId}/reach`, {
        query: { source_network_id: sourceNetworkId, include_skipped: includeSkipped },
      }),
    ),

  // --- exports -------------------------------------------------------------
  exportFormats: async () =>
    list(await request<ExportFormat[] | null>('api/export-formats')),
  // The whole mission as one file: every row of every table it owns, which is
  // what a backup has to be. The browser downloads it straight from the URL,
  // since the session cookie travels with it.
  bundleUrl: (missionId: number) => apiUrl(`api/missions/${missionId}/bundle`),

  importBundle: async (
    file: File,
    opts: { name?: string; createUsers?: boolean } = {},
  ): Promise<MissionImportResult> => {
    const form = new FormData()
    form.append('file', file)
    return request<MissionImportResult>(
      withQuery('api/missions/import', {
        name: opts.name || undefined,
        create_users: opts.createUsers ? 'true' : undefined,
      }),
      { method: 'POST', body: form },
    )
  },

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
