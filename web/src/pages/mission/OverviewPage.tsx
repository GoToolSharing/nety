import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  useFindings,
  useHosts,
  useMission,
  useMissionSummary,
  useNetworks,
  useScans,
} from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardBody, CardHeader, PageHeader, Stat } from '@/components/ui/Card'
import { CardSkeleton, EmptyState, InlineAlert } from '@/components/ui/Feedback'
import { Badge, ScanStatusBadge, SeverityBadge } from '@/components/ui/Badge'
import { LinkButton } from '@/components/ui/Button'
import { ProgressBar, RelativeTime } from '@/components/common'
import SeverityByNetwork from '@/components/charts/SeverityByNetwork'
import { formatNumber, formatPercent } from '@/lib/format'
import {
  DISMISSED_STATUSES,
  SEVERITIES,
  TRIAGE_STATUSES,
  type Severity,
} from '@/types/api'
import { NetworkIcon, PlusIcon, ScanIcon, TrunkIcon } from '@/components/icons'

export default function OverviewPage() {
  const missionId = useMissionId()
  // This page is the index route of missions/:missionId. A relative "../x"
  // would resolve against that route and land on /missions/x, which is the
  // 404 page, so every link here is built from the mission id.
  const base = `/missions/${missionId}`
  const { canWrite } = useAuth()
  const mission = useMission(missionId)
  const summary = useMissionSummary(missionId)
  const networks = useNetworks(missionId)
  const scans = useScans(missionId)
  const hosts = useHosts(missionId)
  // What is left to deal with, so the findings the operator has skipped or
  // called a false positive are not in the headline list or the tiles. They
  // are still on the findings screen with their status; they have just been
  // dealt with, and the front page is about what has not.
  const findings = useFindings(missionId, {
    triage: TRIAGE_STATUSES.filter((t) => !DISMISSED_STATUSES.includes(t)).join(','),
  })

  const nets = networks.data ?? []
  const scanList = scans.data ?? []
  const findingList = findings.data ?? []

  const severityCounts = useMemo(() => {
    const fromSummary = summary.data?.by_severity
    if (fromSummary && Object.keys(fromSummary).length > 0) {
      return fromSummary as Partial<Record<Severity, number>>
    }
    const counts: Partial<Record<Severity, number>> = {}
    for (const f of findingList) counts[f.severity] = (counts[f.severity] ?? 0) + 1
    return counts
  }, [summary.data, findingList])

  const active = scanList.filter((s) => s.status === 'running' || s.status === 'queued')
  const resumable = scanList.filter(
    (s) => s.resumable && (s.status === 'paused' || s.status === 'failed'),
  )

  const trunkNetworks = nets.filter((n) => n.l2?.dtp_seen)
  const hostCount = summary.data?.hosts ?? hosts.data?.length
  const topFindings = useMemo(
    () =>
      [...findingList]
        .sort((a, b) => {
          const rank: Record<Severity, number> = {
            critical: 4,
            high: 3,
            medium: 2,
            low: 1,
            info: 0,
          }
          const d = rank[b.severity] - rank[a.severity]
          return d !== 0 ? d : b.last_seen.localeCompare(a.last_seen)
        })
        .slice(0, 8),
    [findingList],
  )

  const loading = networks.isLoading || scans.isLoading

  return (
    <PageContainer>
      <PageHeader
        title="Overview"
        description={
          mission.data?.description ||
          'Mission at a glance: what is mapped, what is running and what is exposed.'
        }
        actions={
          canWrite && (
            <>
              <LinkButton
                to={`${base}/networks`}
                variant="secondary"
                icon={<NetworkIcon />}
              >
                Networks
              </LinkButton>
              <LinkButton to={`${base}/scans/new`} variant="primary" icon={<PlusIcon />}>
                New scan
              </LinkButton>
            </>
          )
        }
      />

      {loading ? (
        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      ) : nets.length === 0 ? (
        <Card className="mt-5">
          <EmptyState
            icon={<NetworkIcon width={20} height={20} />}
            title="Create a network for the segment you are plugged into"
            description="A network records the segment you are attached to: its interface, addressing, gateway, DNS and the passive L2 recon of the switch port. Everything else in the mission hangs off it."
            action={
              canWrite && (
                <LinkButton to={`${base}/networks`} variant="primary" icon={<PlusIcon />}>
                  Create a network
                </LinkButton>
              )
            }
          />
        </Card>
      ) : (
        <>
          {trunkNetworks.length > 0 && (
            <InlineAlert
              tone="crit"
              className="mt-5"
              icon={<TrunkIcon />}
              title={`${trunkNetworks.length} port${trunkNetworks.length > 1 ? 's' : ''} negotiate${trunkNetworks.length > 1 ? '' : 's'} trunking (DTP)`}
            >
              {trunkNetworks.map((n) => n.name).join(', ')}, a port that offers DTP lets
              an attacker become a trunk and reach every VLAN it carries. This is a
              finding in itself.{' '}
              <Link to={`${base}/networks`} className="underline underline-offset-2">
                Review the L2 recon
              </Link>
            </InlineAlert>
          )}

          <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Stat
              label="Networks"
              value={nets.length}
              sub={`${scanList.length} scans run`}
            />
            <Stat
              label="Hosts"
              value={hostCount ?? 0}
              sub={
                summary.data?.services
                  ? `${formatNumber(summary.data.services)} services`
                  : undefined
              }
            />
            <Stat
              label="Findings"
              value={summary.data?.findings ?? findingList.length}
              tone={
                (severityCounts.critical ?? 0) + (severityCounts.high ?? 0) > 0
                  ? 'crit'
                  : 'default'
              }
              sub={
                <span className="flex flex-wrap gap-1">
                  {SEVERITIES.filter((s) => (severityCounts[s] ?? 0) > 0).map((s) => (
                    <SeverityBadge key={s} severity={s} />
                  ))}
                </span>
              }
            />
            <Stat
              label="Assets"
              value={summary.data?.assets ?? 0}
              sub="stable machine identities"
            />
          </div>

          <Card className="mt-4">
            <CardHeader
              title="Findings by network"
              description="Which segment carries the exposure, worst first. Each bar is one network, stacked critical first and scaled against the busiest network."
              actions={
                <LinkButton to={`${base}/findings`} size="sm">
                  All findings
                </LinkButton>
              }
            />
            <SeverityByNetwork networks={nets} findings={findingList} />
          </Card>

          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader
                title="Scans"
                description={
                  active.length > 0
                    ? `${active.length} running now`
                    : 'Nothing running right now'
                }
                actions={
                  <LinkButton to={`${base}/scans`} size="sm">
                    All scans
                  </LinkButton>
                }
              />
              {scanList.length === 0 ? (
                <EmptyState
                  icon={<ScanIcon width={18} height={18} />}
                  title="No scan yet"
                  description="Launch a discovery scan on the network you are plugged into to map hosts, ports and services."
                  action={
                    canWrite && (
                      <LinkButton to={`${base}/scans/new`} variant="primary" size="sm">
                        Launch a discovery scan
                      </LinkButton>
                    )
                  }
                />
              ) : (
                <ul className="divide-y divide-border">
                  {[...active, ...resumable, ...scanList]
                    .filter((s, i, arr) => arr.findIndex((x) => x.id === s.id) === i)
                    .slice(0, 5)
                    .map((s) => {
                      const net = nets.find((n) => n.id === s.network_id)
                      return (
                        <li key={s.id}>
                          <Link
                            to={`${base}/scans/${s.id}`}
                            className="block px-4 py-2.5 hover:bg-elevated"
                          >
                            <div className="flex items-center justify-between gap-3">
                              <div className="min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="truncate text-sm font-medium">
                                    #{s.id} · {s.kind}
                                  </span>
                                  <ScanStatusBadge status={s.status} />
                                </div>
                                <div className="truncate text-xs text-muted">
                                  {net?.name ?? `network ${s.network_id}`} ·{' '}
                                  {s.phase || '-'} · <RelativeTime value={s.created_at} />
                                </div>
                              </div>
                              <div className="w-28 shrink-0">
                                <ProgressBar
                                  value={s.progress}
                                  height="h-1.5"
                                  tone={
                                    s.status === 'running'
                                      ? 'accent'
                                      : s.status === 'paused'
                                        ? 'warn'
                                        : s.status === 'completed'
                                          ? 'ok'
                                          : 'muted'
                                  }
                                  striped={s.status === 'running'}
                                  label={`Scan ${s.id} progress`}
                                />
                                <div className="tabular mt-1 text-right text-[11px] text-faint">
                                  {formatPercent(s.progress)}
                                </div>
                              </div>
                            </div>
                          </Link>
                        </li>
                      )
                    })}
                </ul>
              )}
            </Card>

            <Card>
              <CardHeader
                title="Networks"
                description="Each segment or attachment point you declared"
                actions={
                  <LinkButton to={`${base}/networks`} size="sm">
                    Manage
                  </LinkButton>
                }
              />
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Network</th>
                      <th>VLAN</th>
                      <th>Prefixes</th>
                      <th className="text-right">Hosts</th>
                      <th>L2</th>
                    </tr>
                  </thead>
                  <tbody>
                    {nets.map((n) => {
                      const perNet = summary.data?.per_network?.[String(n.id)]
                      const hostsHere =
                        perNet?.hosts ??
                        (hosts.data ?? []).filter((h) => h.network_id === n.id).length
                      return (
                        <tr key={n.id}>
                          <td className="font-medium">
                            <Link
                              to={`${base}/networks#network-${n.id}`}
                              className="hover:underline"
                            >
                              {n.name}
                            </Link>
                          </td>
                          <td className="tabular text-muted">{n.vlan_id || '-'}</td>
                          <td className="font-mono text-[12px] text-muted">
                            {(n.prefixes ?? []).join(', ') || '-'}
                          </td>
                          <td className="tabular text-right">
                            {formatNumber(hostsHere)}
                          </td>
                          <td>
                            {n.l2?.dtp_seen ? (
                              <Badge tone="crit">DTP / trunk</Badge>
                            ) : (n.l2?.neighbors ?? []).length > 0 ? (
                              <Badge tone="info">
                                {(n.l2?.neighbors ?? []).length} neighbour
                                {(n.l2?.neighbors ?? []).length > 1 ? 's' : ''}
                              </Badge>
                            ) : (
                              <span className="text-faint">-</span>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>

          <Card className="mt-4">
            <CardHeader
              title="Most severe findings"
              description="Highest severity first, newest first within a severity"
              actions={
                <LinkButton to={`${base}/findings`} size="sm">
                  All findings
                </LinkButton>
              }
            />
            {topFindings.length === 0 ? (
              <CardBody>
                <p className="text-sm text-muted">
                  No finding yet. Checks run as part of a discovery scan when “Light
                  checks” is enabled.
                </p>
              </CardBody>
            ) : (
              <div className="table-scroll">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Finding</th>
                      <th>Host</th>
                      <th>Port</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topFindings.map((f) => (
                      <tr key={f.id}>
                        <td>
                          <SeverityBadge severity={f.severity} />
                        </td>
                        <td className="max-w-md truncate font-medium" title={f.title}>
                          <Link to={`${base}/findings`} className="hover:underline">
                            {f.title}
                          </Link>
                        </td>
                        <td className="font-mono text-[12px]">{f.ip}</td>
                        <td className="tabular text-muted">
                          {f.port ? `${f.port}/${f.protocol ?? 'tcp'}` : '-'}
                        </td>
                        <td className="text-muted">
                          <RelativeTime value={f.last_seen} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </PageContainer>
  )
}
