import { useState } from 'react'
import { useScanAction } from '@/lib/queries'
import { useAuth } from '@/state/auth'
import { useToast } from '@/components/ui/Toast'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/Modal'
import { PauseIcon, PlayIcon, RefreshIcon, StopIcon } from '@/components/icons'
import type { Scan } from '@/types/api'

/**
 * Start / Resume / Pause / Stop. One click each — the API uses the same
 * endpoint for start and resume, and the wording follows the scan's history
 * so a paused scan never reads as if it would restart from scratch.
 */
export default function ScanControls({
  scan,
  missionId,
  size = 'md',
  showRetry = true,
}: {
  scan: Scan
  missionId: number
  size?: 'sm' | 'md' | 'lg'
  showRetry?: boolean
}) {
  const { canWrite } = useAuth()
  const toast = useToast()
  const action = useScanAction(missionId)
  const [confirmStop, setConfirmStop] = useState(false)

  if (!canWrite) return null

  const run = async (kind: 'start' | 'pause' | 'stop' | 'retry-failed') => {
    try {
      await action.mutateAsync({ id: scan.id, action: kind })
      const messages = {
        start: scan.started_at ? 'Scan resumed' : 'Scan started',
        pause: 'Scan paused — nothing is lost',
        stop: 'Scan stopped — collected data is kept',
        'retry-failed': 'Failed work units requeued',
      }
      toast.success(messages[kind])
    } catch (err) {
      toast.error('The action failed', err)
    }
  }

  const busy = action.isPending
  const everStarted = Boolean(scan.started_at)
  const failedUnits = (scan.phases ?? []).reduce((sum, p) => sum + (p.failed ?? 0), 0)

  const canStart =
    scan.status === 'paused' ||
    (scan.status === 'queued' && !everStarted) ||
    ((scan.status === 'failed' || scan.status === 'cancelled') && scan.resumable)
  const canPause = scan.status === 'running' || (scan.status === 'queued' && everStarted)
  const canStop =
    scan.status === 'running' || scan.status === 'queued' || scan.status === 'paused'

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        {canStart && (
          <Button
            variant="success"
            size={size}
            loading={busy}
            icon={<PlayIcon />}
            onClick={() => void run('start')}
          >
            {everStarted ? 'Resume' : 'Start scan'}
          </Button>
        )}
        {canPause && (
          <Button
            variant="warning"
            size={size}
            loading={busy}
            icon={<PauseIcon />}
            onClick={() => void run('pause')}
          >
            Pause
          </Button>
        )}
        {canStop && (
          <Button
            variant="danger"
            size={size}
            disabled={busy}
            icon={<StopIcon />}
            onClick={() => setConfirmStop(true)}
          >
            Stop
          </Button>
        )}
        {showRetry && failedUnits > 0 && (
          <Button
            size={size}
            loading={busy}
            icon={<RefreshIcon />}
            onClick={() => void run('retry-failed')}
            title={`${failedUnits} work units failed and can be requeued`}
          >
            Retry {failedUnits} failed
          </Button>
        )}
      </div>

      <ConfirmDialog
        open={confirmStop}
        onClose={() => setConfirmStop(false)}
        destructive
        title={`Stop scan #${scan.id}?`}
        confirmLabel="Stop the scan"
        busy={busy}
        body={
          <>
            Stopping cancels the remaining work units. Everything already discovered — hosts,
            ports, services, findings — stays in the mission.
            <br />
            <br />
            If you only need to free the link for a moment, use{' '}
            <strong className="text-fg">Pause</strong> instead: a paused scan resumes exactly
            where it stopped, even after the server restarts.
          </>
        }
        onConfirm={async () => {
          await run('stop')
          setConfirmStop(false)
        }}
      />
    </>
  )
}
