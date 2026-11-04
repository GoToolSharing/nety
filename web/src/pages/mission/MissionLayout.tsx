import { useEffect, useMemo } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { LiveProvider, useLive } from '@/live/LiveProvider'
import { useAuth } from '@/state/auth'
import { useMission, useMissionSummary, useNetworks, useScans } from '@/lib/queries'
import { cn } from '@/lib/cn'
import { formatDuration, formatNumber } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { ErrorState, Skeleton } from '@/components/ui/Feedback'
import {
  AssetIcon,
  AuditIcon,
  ChevronRightIcon,
  ExportIcon,
  FindingIcon,
  HostIcon,
  MatrixIcon,
  NetworkIcon,
  OverviewIcon,
  ScanIcon,
  ServiceIcon,
  UsersIcon,
  WifiOffIcon,
} from '@/components/icons'

/** The live connection pill in the sidebar: the state of the WebSocket. */
function LiveIndicator() {
  const { status, retryInMs, droppedCount, reconnectNow } = useLive()

  if (status === 'open') {
    return (
      <div className="flex items-center justify-between gap-2 px-3 py-2">
        <span className="inline-flex items-center gap-1.5 text-[11px] text-muted">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
          </span>
          Live
        </span>
        {droppedCount > 0 && (
          <span
            className="text-[11px] text-warn"
            title={`The server dropped events ${droppedCount} time(s) because this browser could not keep up. The affected tables were refetched.`}
          >
            resynced ×{droppedCount}
          </span>
        )}
      </div>
    )
  }

  return (
    <div className="flex items-center justify-between gap-2 px-3 py-2">
      <span className="inline-flex items-center gap-1.5 text-[11px] text-warn">
        <WifiOffIcon width={13} height={13} />
        {status === 'connecting' ? 'Connecting…' : 'Reconnecting…'}
        {retryInMs ? (
          <span className="text-faint">in {formatDuration(retryInMs / 1000)}</span>
        ) : null}
      </span>
      <button
        type="button"
        onClick={reconnectNow}
        className="rounded text-[11px] text-muted underline-offset-2 hover:text-fg hover:underline"
      >
        Retry now
      </button>
    </div>
  )
}

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode
  end?: boolean
  count?: number
  badge?: React.ReactNode
}

function SidebarLink({ item }: { item: NavItem }) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      className={({ isActive }) =>
        cn(
          'group flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors',
          isActive
            ? 'bg-accent/15 font-medium text-fg'
            : 'text-muted hover:bg-elevated hover:text-fg',
        )
      }
    >
      {({ isActive }) => (
        <>
          <span className={cn('shrink-0', isActive ? 'text-accent' : 'text-faint')}>
            {item.icon}
          </span>
          <span className="min-w-0 flex-1 truncate">{item.label}</span>
          {item.badge ??
            (typeof item.count === 'number' && item.count > 0 ? (
              <span className="tabular text-[11px] text-faint">{formatNumber(item.count)}</span>
            ) : null)}
        </>
      )}
    </NavLink>
  )
}

function MissionSidebar({ missionId }: { missionId: number }) {
  const { isAdmin } = useAuth()
  const mission = useMission(missionId)
  const summary = useMissionSummary(missionId)
  const networks = useNetworks(missionId)
  const scans = useScans(missionId)

  const s = summary.data
  const running = (scans.data ?? []).filter(
    (x) => x.status === 'running' || x.status === 'queued',
  ).length

  const items: NavItem[] = [
    { to: '.', label: 'Overview', icon: <OverviewIcon />, end: true },
    {
      to: 'networks',
      label: 'Networks',
      icon: <NetworkIcon />,
      count: networks.data?.length ?? s?.networks?.length,
    },
    {
      to: 'scans',
      label: 'Scans',
      icon: <ScanIcon />,
      count: scans.data?.length ?? s?.scans,
      badge:
        running > 0 ? (
          <Badge tone="accent" className="px-1 py-0 text-[10px]">
            {running} live
          </Badge>
        ) : undefined,
    },
    { to: 'hosts', label: 'Hosts', icon: <HostIcon />, count: s?.hosts },
    { to: 'services', label: 'Services', icon: <ServiceIcon />, count: s?.services },
    { to: 'findings', label: 'Findings', icon: <FindingIcon />, count: s?.findings },
    { to: 'assets', label: 'Assets', icon: <AssetIcon />, count: s?.assets },
    { to: 'matrix', label: 'Segmentation matrix', icon: <MatrixIcon /> },
    { to: 'exports', label: 'Exports', icon: <ExportIcon /> },
  ]

  return (
    <nav
      className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-surface"
      aria-label="Mission sections"
    >
      <div className="border-b border-border px-3 py-3">
        <NavLink
          to="/missions"
          className="mb-1.5 inline-flex items-center gap-1 rounded text-[11px] text-faint hover:text-fg"
        >
          <ChevronRightIcon width={11} height={11} className="rotate-180" />
          All missions
        </NavLink>
        {mission.isLoading ? (
          <Skeleton className="h-4 w-36" />
        ) : (
          <>
            <div className="truncate text-sm font-semibold text-fg" title={mission.data?.name}>
              {mission.data?.name ?? `Mission ${missionId}`}
            </div>
            {mission.data?.client && (
              <div className="truncate text-xs text-muted">{mission.data.client}</div>
            )}
          </>
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto p-2">
        {items.map((item) => (
          <SidebarLink key={item.to} item={item} />
        ))}

        {isAdmin && (
          <>
            <div className="px-2.5 pb-1 pt-4 text-[10px] font-semibold uppercase tracking-wider text-faint">
              Administration
            </div>
            <SidebarLink item={{ to: '/admin/users', label: 'Users', icon: <UsersIcon /> }} />
            <SidebarLink item={{ to: '/admin/audit', label: 'Audit log', icon: <AuditIcon /> }} />
          </>
        )}
      </div>

      <div className="border-t border-border">
        <LiveIndicator />
      </div>
    </nav>
  )
}

export default function MissionLayout() {
  const params = useParams()
  const missionId = Number(params.missionId)
  const mission = useMission(missionId)

  useEffect(() => {
    document.title = mission.data?.name ? `${mission.data.name} · NETY` : 'NETY'
    return () => {
      document.title = 'NETY'
    }
  }, [mission.data?.name])

  const valid = useMemo(() => Number.isFinite(missionId) && missionId > 0, [missionId])

  if (!valid) {
    return <ErrorState title="Invalid mission" error="That mission id is not a number." />
  }

  return (
    <LiveProvider missionId={missionId}>
      <div className="flex h-full min-h-0">
        <MissionSidebar missionId={missionId} />
        <div className="min-w-0 flex-1 overflow-hidden">
          <Outlet context={{ missionId }} />
        </div>
      </div>
    </LiveProvider>
  )
}
