import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type {
  AssetPatch,
  MissionInput,
  NetworkInput,
  Role,
  ScanInput,
} from '@/types/api'

/**
 * Central query-key registry. The live WebSocket layer patches caches by key
 * prefix, so every key here starts with a stable entity name followed by the
 * mission id.
 */
export const qk = {
  session: ['session'] as const,
  status: ['status'] as const,
  users: ['users'] as const,
  audit: (limit: number) => ['audit', limit] as const,

  missions: ['missions'] as const,
  mission: (id: number) => ['mission', id] as const,
  summary: (missionId: number) => ['summary', missionId] as const,
  members: (missionId: number) => ['members', missionId] as const,

  networks: (missionId: number) => ['networks', missionId] as const,
  interfaces: ['interfaces'] as const,

  scans: (missionId: number) => ['scans', missionId] as const,
  scan: (id: number) => ['scan', id] as const,
  scanLogs: (id: number) => ['scan-logs', id] as const,
  profiles: ['scan-profiles'] as const,
  techniques: ['techniques'] as const,
  checks: ['checks'] as const,

  hostsRoot: (missionId: number) => ['hosts', missionId] as const,
  hosts: (missionId: number, networkId?: number) =>
    ['hosts', missionId, networkId ?? null] as const,
  host: (id: number) => ['host', id] as const,

  servicesRoot: (missionId: number) => ['services', missionId] as const,
  services: (missionId: number, params: Record<string, unknown>) =>
    ['services', missionId, params] as const,

  findingsRoot: (missionId: number) => ['findings', missionId] as const,
  findings: (missionId: number, params: Record<string, unknown> = {}) =>
    ['findings', missionId, params] as const,

  assets: (missionId: number) => ['assets', missionId] as const,
  asset: (id: number) => ['asset', id] as const,

  matrix: (missionId: number) => ['matrix', missionId] as const,
  matrixView: (missionId: number, includeSkipped: boolean) =>
    ['matrix', missionId, includeSkipped] as const,
  reachRoot: (missionId: number) => ['reach', missionId] as const,
  reach: (missionId: number, sourceNetworkId?: number, includeSkipped = false) =>
    ['reach', missionId, sourceNetworkId ?? null, includeSkipped] as const,

  // The triage progress bars, and the count of what a skipped host is keeping
  // off the screen, come from the same call.
  triageSummaryRoot: (missionId: number) => ['triage-summary', missionId] as const,
  triageSummary: (missionId: number, networkId?: number) =>
    ['triage-summary', missionId, networkId ?? null] as const,

  exportFormats: ['export-formats'] as const,
}

/** Reference data: changes only when the binary changes. */
const STATIC = { staleTime: 60 * 60 * 1000, gcTime: 2 * 60 * 60 * 1000 }

// ---------------------------------------------------------------------------
// Reference data
// ---------------------------------------------------------------------------

export const useInterfaces = (enabled = true) =>
  useQuery({ queryKey: qk.interfaces, queryFn: api.interfaces, enabled, staleTime: 15_000 })

export const useScanProfiles = () =>
  useQuery({ queryKey: qk.profiles, queryFn: api.scanProfiles, ...STATIC })

export const useTechniques = () =>
  useQuery({ queryKey: qk.techniques, queryFn: api.techniques, ...STATIC })

export const useChecks = () =>
  useQuery({ queryKey: qk.checks, queryFn: api.checks, ...STATIC })

export const useExportFormats = () =>
  useQuery({ queryKey: qk.exportFormats, queryFn: api.exportFormats, ...STATIC })

export const useServerStatus = () =>
  useQuery({ queryKey: qk.status, queryFn: api.status, staleTime: 30_000, retry: false })

// ---------------------------------------------------------------------------
// Missions
// ---------------------------------------------------------------------------

export const useMissions = () =>
  useQuery({ queryKey: qk.missions, queryFn: api.missions })

export const useMission = (id: number) =>
  useQuery({ queryKey: qk.mission(id), queryFn: () => api.mission(id), enabled: id > 0 })

export const useMissionSummary = (id: number) =>
  useQuery({
    queryKey: qk.summary(id),
    queryFn: () => api.missionSummary(id),
    enabled: id > 0,
    retry: false,
  })

export function useCreateMission() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: MissionInput) => api.createMission(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.missions }),
  })
}

export function usePatchMission() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<MissionInput> }) =>
      api.patchMission(id, body),
    onSuccess: (m) => {
      qc.invalidateQueries({ queryKey: qk.missions })
      qc.invalidateQueries({ queryKey: qk.mission(m.id) })
    },
  })
}

// ---------------------------------------------------------------------------
// Networks
// ---------------------------------------------------------------------------

export const useNetworks = (missionId: number) =>
  useQuery({
    queryKey: qk.networks(missionId),
    queryFn: () => api.networks(missionId),
    enabled: missionId > 0,
  })

export function useCreateNetwork(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: NetworkInput) => api.createNetwork(missionId, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.networks(missionId) })
      qc.invalidateQueries({ queryKey: qk.summary(missionId) })
    },
  })
}

export function usePatchNetwork(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: Partial<NetworkInput> }) =>
      api.patchNetwork(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.networks(missionId) }),
  })
}

export function useDeleteNetwork(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.deleteNetwork(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.networks(missionId) })
      qc.invalidateQueries({ queryKey: qk.summary(missionId) })
    },
  })
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const useScans = (missionId: number) =>
  useQuery({
    queryKey: qk.scans(missionId),
    queryFn: () => api.scans(missionId),
    enabled: missionId > 0,
  })

export const useScan = (id: number) =>
  useQuery({
    queryKey: qk.scan(id),
    queryFn: () => api.scan(id),
    enabled: id > 0,
    // The WebSocket carries progress; this is only the safety net.
    refetchInterval: (q) => {
      const s = q.state.data
      return s && (s.status === 'running' || s.status === 'queued') ? 10_000 : false
    },
  })

export function useCreateScan(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: ScanInput) => api.createScan(missionId, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.scans(missionId) }),
  })
}

export function useScanAction(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      action,
    }: {
      id: number
      action: 'start' | 'pause' | 'stop' | 'retry-failed'
    }) => {
      switch (action) {
        case 'start':
          return api.startScan(id)
        case 'pause':
          return api.pauseScan(id)
        case 'stop':
          return api.stopScan(id)
        case 'retry-failed':
          return api.retryFailed(id)
      }
    },
    onSuccess: (scan) => {
      if (scan?.id) qc.setQueryData(qk.scan(scan.id), scan)
      qc.invalidateQueries({ queryKey: qk.scans(missionId) })
    },
  })
}

export function useDeleteScan(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.deleteScan(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.scans(missionId) }),
  })
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/**
 * The hosts of a mission. `enabled` is there for the screens that only need
 * the list to know which addresses are skipped, and only once the operator
 * has asked to see those rows.
 */
export const useHosts = (missionId: number, networkId?: number, enabled = true) =>
  useQuery({
    queryKey: qk.hosts(missionId, networkId),
    queryFn: () => api.hosts(missionId, networkId),
    enabled: enabled && missionId > 0,
  })

export const useHost = (id: number) =>
  useQuery({ queryKey: qk.host(id), queryFn: () => api.host(id), enabled: id > 0 })

export const useServices = (
  missionId: number,
  params: {
    network_id?: number
    host_id?: number
    port?: number
    protocol?: string
    q?: string
    triage?: string
    include_skipped?: boolean
    limit?: number
    offset?: number
  },
) =>
  useQuery({
    queryKey: qk.services(missionId, params),
    queryFn: () => api.services(missionId, params),
    enabled: missionId > 0,
    placeholderData: (prev) => prev,
  })

export const useFindings = (
  missionId: number,
  params: {
    network_id?: number
    host_id?: number
    triage?: string
    include_skipped?: boolean
  } = {},
) =>
  useQuery({
    queryKey: qk.findings(missionId, params),
    queryFn: () => api.findings(missionId, params),
    enabled: missionId > 0,
    placeholderData: (prev) => prev,
  })

export const useAssets = (missionId: number) =>
  useQuery({
    queryKey: qk.assets(missionId),
    queryFn: () => api.assets(missionId),
    enabled: missionId > 0,
  })

export function usePatchAsset(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, body }: { id: number; body: AssetPatch }) =>
      api.patchAsset(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.assets(missionId) }),
  })
}

export function useMergeAssets(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, source_id }: { id: number; source_id: number }) =>
      api.mergeAssets(id, source_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.assets(missionId) })
      qc.invalidateQueries({ queryKey: qk.hostsRoot(missionId) })
    },
  })
}

export const useMatrix = (missionId: number, includeSkipped = false) =>
  useQuery({
    queryKey: qk.matrixView(missionId, includeSkipped),
    queryFn: () => api.matrix(missionId, includeSkipped || undefined),
    enabled: missionId > 0,
  })

export const useReach = (missionId: number, sourceNetworkId?: number, includeSkipped = false) =>
  useQuery({
    queryKey: qk.reach(missionId, sourceNetworkId, includeSkipped),
    queryFn: () => api.reach(missionId, sourceNetworkId, includeSkipped || undefined),
    enabled: missionId > 0,
  })

/** The triage progress and what the listings are hiding, in one call. */
export const useTriageSummary = (missionId: number, networkId?: number) =>
  useQuery({
    queryKey: qk.triageSummary(missionId, networkId),
    queryFn: () => api.triageSummary(missionId, networkId || undefined),
    enabled: missionId > 0,
  })

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

/** Who can see a mission. Readable by any member; only an admin may change it. */
export const useMissionMembers = (missionId: number, enabled = true) =>
  useQuery({
    queryKey: qk.members(missionId),
    queryFn: () => api.missionMembers(missionId),
    enabled: enabled && missionId > 0,
  })

export function useSetMissionMembers(missionId: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (userIds: number[]) => api.setMissionMembers(missionId, userIds),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: qk.members(missionId) })
      void qc.invalidateQueries({ queryKey: qk.missions })
    },
  })
}

export const useUsers = (enabled = true) =>
  useQuery({ queryKey: qk.users, queryFn: api.users, enabled })

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (body: {
      username: string
      display_name: string
      role: Role
      password: string
    }) => api.createUser(body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.users }),
  })
}

export function usePatchUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({
      id,
      body,
    }: {
      id: number
      body: { display_name?: string; role?: Role; disabled?: boolean }
    }) => api.patchUser(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.users }),
  })
}

export function useResetUserPassword() {
  return useMutation({
    mutationFn: ({
      id,
      password,
      mustChange,
    }: {
      id: number
      password: string
      mustChange: boolean
    }) => api.setUserPassword(id, password, mustChange),
  })
}

export function useDeleteUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: number) => api.deleteUser(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.users }),
  })
}

export const useAudit = (limit = 200, enabled = true) =>
  useQuery({
    queryKey: qk.audit(limit),
    queryFn: () => api.audit({ limit }),
    enabled,
    retry: false,
  })
