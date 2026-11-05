import { useState } from 'react'
import { useScanAction } from '@/lib/queries'
import { useAuth } from '@/state/auth'
import { useToast } from '@/components/ui/Toast'
import { Button } from '@/components/ui/Button'
import { ConfirmDialog } from '@/components/ui/Modal'
import { PauseIcon, PlayIcon, RefreshIcon, StopIcon } from '@/components/icons'
import type { Scan } from '@/types/api'

function failedUnitCount(scan: Scan): number {
  return (scan.phases ?? []).reduce((sum, p) => sum + (p.failed ?? 0), 0)
}

export function canStartScan(scan: Scan): boolean {
  return (
    scan.status === 'paused' ||
    (scan.status === 'queued' && !scan.started_at) ||
    ((scan.status === 'failed' ||
      scan.status === 'cancelled' ||
      // A completed scan is only ever resumable when its plan was cut short.
      scan.status === 'completed') &&
      scan.resumable)
  )
}

export function canPauseScan(scan: Scan): boolean {
  return scan.status === 'running' || (scan.status === 'queued' && Boolean(scan.started_at))
}

export function canStopScan(scan: Scan): boolean {
  return scan.status === 'running' || scan.status === 'queued' || scan.status === 'paused'
}

/**
 * Whether this scan has any control at all, so a table can reserve the room
 * they need on the rows that use it and leave none on the rows that do not. A
 * finished scan showed an empty two-inch gap before Open without this.
 */
export function hasScanControls(scan: Scan, showRetry = true): boolean {
  return (
    canStartScan(scan) ||
    canPauseScan(scan) ||
    canStopScan(scan) ||
    (showRetry && failedUnitCount(scan) > 0)
  )
}

/**
 * Start / Resume / Pause / Stop. One click each - the API uses the same
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
        pause: 'Scan paused - nothing is lost',
        stop: 'Scan stopped - collected data is kept',
        'retry-failed': 'Failed work units requeued',
      }
      toast.success(messages[kind])
    } catch (err) {
      toast.error('The action failed', err)
    }
  }

  // Every control is laid out on the same minimum width, so Resume, Pause and
  // Stop are the same size and whatever follows them in a table row lines up
  // with the rows above and below.
  const width = size === 'sm' ? 'min-w-[6rem]' : size === 'lg' ? 'min-w-[8rem]' : 'min-w-[7rem]'

  const busy = action.isPending
  const everStarted = Boolean(scan.started_at)
  const failedUnits = failedUnitCount(scan)

  const canStart = canStartScan(scan)
  const canPause = canPauseScan(scan)
  const canStop = canStopScan(scan)

  return (
    <>
      <div className="flex items-center gap-2">
        {canStart && (
          <Button
            variant="success"
            size={size}
            className={width}
            loading={busy}
            icon={<PlayIcon />}
            onClick={() => void run('start')}
          >
            {scan.status === 'completed'
              ? 'Finish scan'
              : everStarted
                ? 'Resume'
                : 'Start scan'}
          </Button>
        )}
        {canPause && (
          <Button
            variant="warning"
            size={size}
            className={width}
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
            className={width}
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
            className={width}
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
            Stopping cancels the remaining work units. Everything already discovered - hosts,
            ports, services, findings - stays in the mission.
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
