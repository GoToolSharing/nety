import { useEffect, useMemo } from 'react'
import { NavLink, Outlet, useParams } from 'react-router-dom'
import { LiveProvider } from '@/live/LiveProvider'
import { useAuth } from '@/state/auth'
import { useMission, useMissionSummary, useNetworks, useScans } from '@/lib/queries'
import { cn } from '@/lib/cn'
import { formatNumber } from '@/lib/format'
import { lastMissionId, rememberMission } from '@/lib/lastMission'
import { Badge } from '@/components/ui/Badge'
import { ErrorState, Skeleton } from '@/components/ui/Feedback'
import {
  AssetIcon,
  AuditIcon,
  ChevronRightIcon,
  ExportIcon,
  FindingIcon,
  HelpIcon,
  HostIcon,
  MatrixIcon,
  NetworkIcon,
  OverviewIcon,
  ScanIcon,
  ServiceIcon,
  UsersIcon,
} from '@/components/icons'

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

function MissionHeading({ missionId }: { missionId: number }) {
  const mission = useMission(missionId)
  return (
    <>
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
    </>
  )
}

function MissionSections({ missionId }: { missionId: number }) {
  const summary = useMissionSummary(missionId)
  const networks = useNetworks(missionId)
  const scans = useScans(missionId)

  const s = summary.data
  const running = (scans.data ?? []).filter(
    (x) => x.status === 'running' || x.status === 'queued',
  ).length
  const base = `/missions/${missionId}`

  const items: NavItem[] = [
    { to: base, label: 'Overview', icon: <OverviewIcon />, end: true },
    {
      to: `${base}/networks`,
      label: 'Networks',
      icon: <NetworkIcon />,
      count: networks.data?.length ?? (s?.networks ?? []).length,
    },
    {
      to: `${base}/scans`,
      label: 'Scans',
      icon: <ScanIcon />,
      count: scans.data?.length,
      badge:
        running > 0 ? (
          <Badge tone="accent" className="px-1 py-0 text-[10px]">
            {running} live
          </Badge>
        ) : undefined,
    },
    { to: `${base}/hosts`, label: 'Hosts', icon: <HostIcon />, count: s?.hosts },
    { to: `${base}/services`, label: 'Services', icon: <ServiceIcon />, count: s?.services },
    { to: `${base}/findings`, label: 'Findings', icon: <FindingIcon />, count: s?.findings },
    { to: `${base}/assets`, label: 'Assets', icon: <AssetIcon />, count: s?.assets },
    { to: `${base}/matrix`, label: 'Segmentation matrix', icon: <MatrixIcon /> },
    { to: `${base}/exports`, label: 'Exports', icon: <ExportIcon /> },
  ]

  return (
    <>
      {items.map((item) => (
        <SidebarLink key={item.to} item={item} />
      ))}
    </>
  )
}

/**
 * The mission sidebar. It is rendered on every signed-in page, including the
 * ones that sit outside a mission (Help, administration), so the layout never
 * changes shape under the operator. Links are absolute for that reason.
 */
export function MissionSidebar({ missionId }: { missionId: number | null }) {
  const { isAdmin } = useAuth()

  return (
    <nav
      className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-surface"
      aria-label="Mission sections"
    >
      <div className="border-b border-border px-3 py-3">
        {missionId ? (
          <MissionHeading missionId={missionId} />
        ) : (
          <NavLink
            to="/missions"
            className="inline-flex items-center gap-1 rounded text-sm font-semibold text-fg hover:text-accent"
          >
            <ChevronRightIcon width={12} height={12} className="rotate-180" />
            All missions
          </NavLink>
        )}
      </div>

      <div className="min-h-0 flex-1 space-y-0.5 overflow-y-auto p-2">
        {missionId !== null && <MissionSections missionId={missionId} />}

        <div className="px-2.5 pb-1 pt-4 text-[10px] font-semibold uppercase tracking-wider text-faint">
          Reference
        </div>
        <SidebarLink item={{ to: '/help', label: 'Help', icon: <HelpIcon /> }} />

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
    </nav>
  )
}

/** The same two-pane shell for the pages that are not tied to a mission. */
export function SidebarShell() {
  return (
    <div className="flex h-full min-h-0">
      <MissionSidebar missionId={lastMissionId()} />
      <div className="min-w-0 flex-1 overflow-hidden">
        <Outlet />
      </div>
    </div>
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

  useEffect(() => {
    if (valid) rememberMission(missionId)
  }, [valid, missionId])

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
