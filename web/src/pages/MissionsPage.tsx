import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueries } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useCreateMission, useMissions, usePatchMission } from '@/lib/queries'
import { useAuth } from '@/state/auth'
import { useToast } from '@/components/ui/Toast'
import { Button } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { TextAreaField, TextField } from '@/components/ui/Field'
import { CardSkeleton, EmptyState, ErrorState } from '@/components/ui/Feedback'
import { PageHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { RelativeTime, SearchInput } from '@/components/common'
import { AssetIcon, FindingIcon, HostIcon, NetworkIcon, PlusIcon, ScanIcon } from '@/components/icons'
import { formatNumber } from '@/lib/format'
import type { Mission, MissionSummary } from '@/types/api'

function parseList(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function CreateMissionModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateMission()
  const toast = useToast()
  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [description, setDescription] = useState('')
  const [scope, setScope] = useState('')
  const [exclude, setExclude] = useState('')
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    if (!name.trim()) {
      setError('A mission needs a name.')
      return
    }
    try {
      await create.mutateAsync({
        name: name.trim(),
        client: client.trim(),
        description: description.trim(),
        scope_cidrs: parseList(scope),
        exclude_cidrs: parseList(exclude),
      })
      toast.success('Mission created')
      setName('')
      setClient('')
      setDescription('')
      setScope('')
      setExclude('')
      setError(null)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the mission.')
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New mission"
      description="One mission per engagement. Networks, scans and results all live inside it."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={create.isPending}>
            Create mission
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        {error && <p className="text-sm text-crit">{error}</p>}
        <TextField
          label="Name"
          required
          data-autofocus
          placeholder="Internal audit — HQ"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <TextField
          label="Client"
          placeholder="ACME Corp"
          value={client}
          onChange={(e) => setClient(e.target.value)}
        />
        <TextAreaField
          label="Description"
          rows={2}
          placeholder="Scope notes, contacts, constraints…"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
        />
        <TextAreaField
          label="Scope CIDRs"
          rows={2}
          spellCheck={false}
          className="font-mono text-[12.5px]"
          placeholder="10.0.0.0/8 192.168.0.0/16"
          hint="Optional. Added to auto-targets when a scan has auto-targets enabled."
          value={scope}
          onChange={(e) => setScope(e.target.value)}
        />
        <TextAreaField
          label="Excluded CIDRs"
          rows={2}
          spellCheck={false}
          className="font-mono text-[12.5px]"
          placeholder="10.0.99.0/24"
          hint="Never probed, under any circumstance."
          value={exclude}
          onChange={(e) => setExclude(e.target.value)}
        />
        <button type="submit" className="hidden" aria-hidden="true" />
      </form>
    </Modal>
  )
}

function CountChip({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode
  label: string
  value: number | undefined
}) {
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs text-muted"
      title={`${label}: ${value === undefined ? 'unknown' : formatNumber(value)}`}
    >
      <span className="text-faint">{icon}</span>
      <span className="tabular text-fg">{value === undefined ? '—' : formatNumber(value)}</span>
      <span className="hidden sm:inline">{label}</span>
    </span>
  )
}

function MissionCard({
  mission,
  summary,
  onArchiveToggle,
  canWrite,
}: {
  mission: Mission
  summary?: MissionSummary
  onArchiveToggle: (m: Mission) => void
  canWrite: boolean
}) {
  const severity = summary?.severity ?? {}
  const criticalish = (severity.critical ?? 0) + (severity.high ?? 0)

  return (
    <div className="card flex flex-col transition-colors hover:border-border-strong">
      <Link
        to={`/missions/${mission.id}`}
        className="flex-1 rounded-t-lg p-4 focus-visible:outline-offset-[-2px]"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="truncate text-sm font-semibold text-fg">{mission.name}</h3>
            {mission.client && (
              <p className="mt-0.5 truncate text-xs text-muted">{mission.client}</p>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {mission.archived && <Badge tone="neutral">Archived</Badge>}
            {criticalish > 0 && (
              <Badge tone="crit" title={`${criticalish} high or critical findings`}>
                {formatNumber(criticalish)} high+
              </Badge>
            )}
            {(summary?.running_scans ?? 0) > 0 && (
              <Badge tone="accent">
                <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
                {summary?.running_scans} running
              </Badge>
            )}
          </div>
        </div>

        {mission.description && (
          <p className="mt-2 line-clamp-2 text-xs text-muted">{mission.description}</p>
        )}

        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5">
          <CountChip
            icon={<NetworkIcon width={13} height={13} />}
            label="networks"
            value={summary?.networks?.length}
          />
          <CountChip icon={<HostIcon width={13} height={13} />} label="hosts" value={summary?.hosts} />
          <CountChip
            icon={<ScanIcon width={13} height={13} />}
            label="scans"
            value={summary?.scans}
          />
          <CountChip
            icon={<FindingIcon width={13} height={13} />}
            label="findings"
            value={summary?.findings}
          />
          <CountChip
            icon={<AssetIcon width={13} height={13} />}
            label="assets"
            value={summary?.assets}
          />
        </div>
      </Link>

      <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2">
        <span className="text-[11px] text-faint">
          Updated <RelativeTime value={mission.updated_at} />
        </span>
        {canWrite && (
          <button
            type="button"
            onClick={() => onArchiveToggle(mission)}
            className="rounded text-[11px] text-muted underline-offset-2 hover:text-fg hover:underline"
          >
            {mission.archived ? 'Unarchive' : 'Archive'}
          </button>
        )}
      </div>
    </div>
  )
}

export default function MissionsPage() {
  const { canWrite } = useAuth()
  const toast = useToast()
  const missions = useMissions()
  const patch = usePatchMission()
  const [showArchived, setShowArchived] = useState(false)
  const [query, setQuery] = useState('')
  const [createOpen, setCreateOpen] = useState(false)

  const all = missions.data ?? []

  const summaries = useQueries({
    queries: all.map((m) => ({
      queryKey: qk.summary(m.id),
      queryFn: () => api.missionSummary(m.id),
      retry: false,
      staleTime: 30_000,
    })),
  })

  const summaryById = useMemo(() => {
    const map = new Map<number, MissionSummary>()
    all.forEach((m, i) => {
      const data = summaries[i]?.data
      if (data) map.set(m.id, data)
    })
    return map
  }, [all, summaries])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return all
      .filter((m) => (showArchived ? true : !m.archived))
      .filter(
        (m) =>
          !q ||
          m.name.toLowerCase().includes(q) ||
          m.client.toLowerCase().includes(q) ||
          m.description.toLowerCase().includes(q),
      )
      .sort((a, b) => {
        if (a.archived !== b.archived) return a.archived ? 1 : -1
        return b.updated_at.localeCompare(a.updated_at)
      })
  }, [all, query, showArchived])

  const archivedCount = all.filter((m) => m.archived).length

  const toggleArchive = async (m: Mission) => {
    try {
      await patch.mutateAsync({ id: m.id, body: { archived: !m.archived } })
      toast.success(m.archived ? 'Mission unarchived' : 'Mission archived')
    } catch (err) {
      toast.error('Could not update the mission', err)
    }
  }

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-6xl px-6 py-7">
        <PageHeader
          title="Missions"
          description="Every engagement is a mission: its networks, scans, results and exports live inside it."
          actions={
            canWrite && (
              <Button variant="primary" icon={<PlusIcon />} onClick={() => setCreateOpen(true)}>
                New mission
              </Button>
            )
          }
        />

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <SearchInput
            value={query}
            onChange={setQuery}
            placeholder="Filter missions…"
            className="w-full max-w-xs"
          />
          {archivedCount > 0 && (
            <label className="flex cursor-pointer items-center gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={showArchived}
                onChange={(e) => setShowArchived(e.target.checked)}
                className="h-3.5 w-3.5 accent-[rgb(var(--c-accent))]"
              />
              Show archived ({archivedCount})
            </label>
          )}
        </div>

        <div className="mt-5">
          {missions.isLoading ? (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {Array.from({ length: 3 }).map((_, i) => (
                <CardSkeleton key={i} />
              ))}
            </div>
          ) : missions.isError ? (
            <ErrorState
              title="Could not load missions"
              error={missions.error}
              retry={() => void missions.refetch()}
            />
          ) : visible.length === 0 ? (
            <div className="card">
              <EmptyState
                icon={<ScanIcon width={20} height={20} />}
                title={all.length === 0 ? 'No missions yet' : 'No mission matches that filter'}
                description={
                  all.length === 0
                    ? 'Create a mission for the engagement you are starting. You will then declare the VLAN you are plugged into as a network, and launch a discovery scan on it.'
                    : 'Clear the filter, or include archived missions.'
                }
                action={
                  all.length === 0 && canWrite ? (
                    <Button
                      variant="primary"
                      icon={<PlusIcon />}
                      onClick={() => setCreateOpen(true)}
                    >
                      Create the first mission
                    </Button>
                  ) : undefined
                }
              />
            </div>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {visible.map((m) => (
                <MissionCard
                  key={m.id}
                  mission={m}
                  summary={summaryById.get(m.id)}
                  onArchiveToggle={(mm) => void toggleArchive(mm)}
                  canWrite={canWrite}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      <CreateMissionModal open={createOpen} onClose={() => setCreateOpen(false)} />
    </div>
  )
}
