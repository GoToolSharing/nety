import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { qk, useMission, useMissionSummary } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardBody, CardHeader, PageHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { TextAreaField, TextField } from '@/components/ui/Field'
import { InlineAlert, Skeleton } from '@/components/ui/Feedback'
import { Modal } from '@/components/ui/Modal'
import { useToast } from '@/components/ui/Toast'
import { formatNumber } from '@/lib/format'
import { DownloadIcon } from '@/components/icons'

function splitList(value: string): string[] {
  return value
    .split(/[\s,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/**
 * What a mission is, and the two ways to undo it.
 *
 * The mission could be created and deleted but never edited, so a typo in a
 * client name or a scope that grew during the engagement had nowhere to go.
 * That lives here now, next to the two destructive actions, because they are
 * the same question asked at different volumes: change this, empty this,
 * remove this.
 */
export default function SettingsPage() {
  const missionId = useMissionId()
  const mission = useMission(missionId)
  const summary = useMissionSummary(missionId)
  const { isAdmin, canWrite } = useAuth()
  const toast = useToast()
  const qc = useQueryClient()
  const navigate = useNavigate()

  const [name, setName] = useState('')
  const [client, setClient] = useState('')
  const [description, setDescription] = useState('')
  const [scope, setScope] = useState('')
  const [excludes, setExcludes] = useState('')
  const [saving, setSaving] = useState(false)
  const [confirming, setConfirming] = useState<'reset' | 'delete' | null>(null)

  useEffect(() => {
    const m = mission.data
    if (!m) return
    setName(m.name)
    setClient(m.client ?? '')
    setDescription(m.description ?? '')
    setScope((m.scope_cidrs ?? []).join('\n'))
    setExcludes((m.exclude_cidrs ?? []).join('\n'))
  }, [mission.data])

  const save = async () => {
    setSaving(true)
    try {
      await api.patchMission(missionId, {
        name: name.trim(),
        client: client.trim(),
        description: description.trim(),
        scope_cidrs: splitList(scope),
        exclude_cidrs: splitList(excludes),
      })
      void qc.invalidateQueries({ queryKey: qk.mission(missionId) })
      void qc.invalidateQueries({ queryKey: qk.missions })
      toast.success('Mission updated')
    } catch (e) {
      toast.error('Could not save the mission', e)
    } finally {
      setSaving(false)
    }
  }

  if (mission.isLoading) {
    return (
      <PageContainer>
        <Skeleton className="h-7 w-48" />
        <Skeleton className="mt-4 h-40 w-full" />
      </PageContainer>
    )
  }

  const s = summary.data
  const stored = [
    ['hosts', s?.hosts],
    ['services', s?.services],
    ['findings', s?.findings],
    ['assets', s?.assets],
  ] as const

  return (
    <PageContainer>
      <PageHeader
        title="Settings"
        description="What this mission is, and the two ways to undo it."
      />

      <div className="mt-5 max-w-3xl space-y-5">
        <Card>
          <CardHeader
            title="Mission"
            description="The scope and the exclusions apply to every scan of this mission, on top of whatever a scan asks for."
          />
          <CardBody className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <TextField
                label="Name"
                value={name}
                disabled={!canWrite}
                onChange={(e) => setName(e.target.value)}
              />
              <TextField
                label="Client"
                value={client}
                disabled={!canWrite}
                onChange={(e) => setClient(e.target.value)}
              />
            </div>
            <TextAreaField
              label="Description"
              rows={2}
              value={description}
              disabled={!canWrite}
              onChange={(e) => setDescription(e.target.value)}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <TextAreaField
                label="Scope"
                rows={3}
                spellCheck={false}
                className="font-mono text-[12.5px]"
                hint="Added to the targets of a scan that has auto-targets on."
                value={scope}
                disabled={!canWrite}
                onChange={(e) => setScope(e.target.value)}
              />
              <TextAreaField
                label="Exclusions"
                rows={3}
                spellCheck={false}
                className="font-mono text-[12.5px]"
                hint="Never probed by anything, including a segmentation scan."
                value={excludes}
                disabled={!canWrite}
                onChange={(e) => setExcludes(e.target.value)}
              />
            </div>
            {canWrite && (
              <div className="flex justify-end">
                <Button variant="primary" loading={saving} onClick={() => void save()}>
                  Save
                </Button>
              </div>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="Backup"
            description="The whole mission as one file, to put back on another installation."
          />
          <CardBody className="space-y-3">
            <p className="text-xs text-muted">
              Everything the mission owns travels: its networks, its scans with their pending
              work units and their logs, its hosts, services, assets with the addresses each
              machine has held, findings, segmentation results, and every status and note your
              team wrote, with who wrote them. Not the audit log, which belongs to this server
              and can name work on another client, and no password ever.
            </p>
            <p className="text-xs text-faint">
              Restoring it always creates a new mission. It never merges into one that is
              already here, so a restore cannot quietly reconcile two versions of the same
              engagement. Administrators restore from the missions list.
            </p>
            <div>
              <a
                href={api.bundleUrl(missionId)}
                download
                className="inline-flex items-center gap-2 rounded-md border border-border bg-elevated px-3 py-1.5 text-sm font-medium text-fg transition-colors hover:border-accent/60 hover:bg-surface"
              >
                <DownloadIcon width={15} height={15} className="text-faint" />
                Download the mission
              </a>
            </div>
          </CardBody>
        </Card>

        {isAdmin && (
          <Card className="border-crit/40">
            <CardHeader
              title="Danger zone"
              description="Both of these are immediate and cannot be undone. Export first if any of it matters."
            />
            <CardBody className="space-y-4">
              <div className="rounded-md border border-border p-3">
                <div className="text-sm font-medium text-fg">Reset the results</div>
                <p className="mt-1 text-xs text-muted">
                  Removes every scan with its logs, and every host, service, finding, asset
                  and segmentation result. Keeps the mission, its scope, its team and its
                  networks with their interface, VLAN and addressing, so you do not set the
                  VLANs up again. The mission goes back to the state it was in once the
                  networks were configured and nothing had been scanned.
                </p>
                <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-faint">
                  {stored.map(([label, n]) => (
                    <span key={label}>
                      {formatNumber(n ?? 0)} {label}
                    </span>
                  ))}
                </div>
                <Button
                  variant="danger"
                  size="sm"
                  className="mt-3"
                  onClick={() => setConfirming('reset')}
                >
                  Reset the results
                </Button>
              </div>

              <div className="rounded-md border border-crit/40 bg-crit/5 p-3">
                <div className="text-sm font-medium text-fg">Delete the mission</div>
                <p className="mt-1 text-xs text-muted">
                  Removes everything above and the mission itself: its networks, its scope and
                  who had access to it. Nothing is left to come back to.
                </p>
                <Button
                  variant="danger"
                  size="sm"
                  className="mt-3"
                  onClick={() => setConfirming('delete')}
                >
                  Delete this mission
                </Button>
              </div>
            </CardBody>
          </Card>
        )}
      </div>

      {confirming && mission.data && (
        <ConfirmByName
          kind={confirming}
          missionId={missionId}
          missionName={mission.data.name}
          onClose={() => setConfirming(null)}
          onDone={(message) => {
            setConfirming(null)
            toast.success(message)
            if (confirming === 'delete') {
              navigate('/missions')
            } else {
              void qc.invalidateQueries()
            }
          }}
        />
      )}
    </PageContainer>
  )
}

/**
 * Both actions ask for the mission's name rather than a yes. The server asks
 * for it too on a reset, so a stale tab cannot empty the wrong mission.
 */
function ConfirmByName({
  kind,
  missionId,
  missionName,
  onClose,
  onDone,
}: {
  kind: 'reset' | 'delete'
  missionId: number
  missionName: string
  onClose: () => void
  onDone: (message: string) => void
}) {
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const matches = typed.trim().toLowerCase() === missionName.trim().toLowerCase()

  const run = async () => {
    setBusy(true)
    setError('')
    try {
      if (kind === 'delete') {
        await api.deleteMission(missionId)
        onDone('Mission deleted')
      } else {
        const c = await api.resetMission(missionId, typed.trim())
        onDone(
          `Reset: ${c.scans} scans, ${c.hosts} hosts, ${c.services} services, ${c.findings} findings removed`,
        )
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'The action failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      size="md"
      onClose={onClose}
      title={kind === 'delete' ? `Delete ${missionName}?` : `Reset ${missionName}?`}
    >
      <InlineAlert tone="warn">
        {kind === 'delete'
          ? 'The mission, its networks, its results and its access list are removed. This cannot be undone.'
          : 'Every scan and every result is removed. The mission, its scope, its team and its networks stay. This cannot be undone.'}
      </InlineAlert>
      <div className="mt-4">
        <TextField
          label={`Type ${missionName} to confirm`}
          value={typed}
          autoFocus
          spellCheck={false}
          onChange={(e) => setTyped(e.target.value)}
        />
      </div>
      {error && <p className="mt-2 text-xs text-crit">{error}</p>}
      <div className="mt-4 flex items-center justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" disabled={!matches} loading={busy} onClick={() => void run()}>
          {kind === 'delete' ? 'Delete the mission' : 'Reset the results'}
        </Button>
      </div>
    </Modal>
  )
}
