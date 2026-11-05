import { useState } from 'react'
import { api } from '@/lib/api'
import { useExportFormats, useMission, useNetworks, useTriageSummary } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardBody, CardHeader, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { Mono } from '@/components/common'
import { Toggle } from '@/components/ui/Field'
import { formatNumber } from '@/lib/format'
import { cn } from '@/lib/cn'
import { DownloadIcon, ExportIcon } from '@/components/icons'
import type { ExportFormat } from '@/types/api'

/** Short, honest descriptions of what each built-in format is good for. */
const FORMAT_BLURB: Record<string, string> = {
  json: 'The whole mission as one JSON document - networks, scans, hosts, services, assets, findings, reachability, matrix and the latest scan diff.',
  'csv-hosts': 'One row per host: IP, MAC, vendor, hostname, OS, network.',
  'csv-services': 'One row per service: address, port, protocol, product, version, TLS and HTTP summary.',
  'csv-findings': 'One row per finding, with severity, evidence and remediation.',
  'csv-reach': 'One row per reachability test: source, target, technique, status.',
  'csv-assets': 'One row per asset with its addresses and identity keys.',
  'csv-matrix': 'The source × target grid: how many services each network could reach in the next.',
  'csv-diff':
    'What the last scan of a network changed against the one before it: hosts that appeared or went away, ports that opened or closed, findings raised or cleared.',
  'nmap-xml': 'Nmap XML, for tools that already ingest nmap output.',
  gnmap: 'Grepable nmap output.',
  'targets-txt': 'Plain list of live addresses - feed it to your next tool.',
  markdown: 'Report-ready Markdown.',
  html: 'Self-contained HTML report you can hand over as is.',
  xlsx: 'Excel workbook with one sheet per table.',
}

function FormatCard({
  format,
  missionId,
  networkId,
  keep,
}: {
  format: ExportFormat
  missionId: number
  networkId: number
  keep: { dismissed: boolean; unreviewed: boolean }
}) {
  const href = api.exportUrl(missionId, format.id, networkId || undefined, keep)
  return (
    <a
      href={href}
      download
      className={cn(
        'card flex items-start gap-3 p-4 transition-colors hover:border-accent/60 hover:bg-elevated',
      )}
    >
      <span className="mt-0.5 shrink-0 text-faint">
        <DownloadIcon width={18} height={18} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-semibold text-fg">{format.title || format.id}</span>
          <Badge tone="neutral">{format.extension || format.id}</Badge>
        </span>
        {FORMAT_BLURB[format.id] && (
          // No blurb means no second line: falling back to the content type
          // here would simply repeat the line below it.
          <span className="mt-1 block text-xs text-muted">{FORMAT_BLURB[format.id]}</span>
        )}
        <span className="mt-1.5 block text-[11px] text-faint">
          <Mono>{format.content_type}</Mono>
        </span>
      </span>
    </a>
  )
}

export default function ExportsPage() {
  const missionId = useMissionId()
  const mission = useMission(missionId)
  const networks = useNetworks(missionId)
  const formats = useExportFormats()
  const summary = useTriageSummary(missionId, 0)
  const [networkId, setNetworkId] = useState(0)
  // An export is usually a deliverable, so two things stay out of it unless
  // asked for: what the operator set aside, and the findings nobody has been
  // through yet.
  const [includeDismissed, setIncludeDismissed] = useState(false)
  const [includeUnreviewed, setIncludeUnreviewed] = useState(false)

  const setAside =
    (summary.data?.counts.skipped ?? 0) +
    (summary.data?.counts.false_positive ?? 0) +
    (summary.data?.findings.counts.skipped ?? 0) +
    (summary.data?.findings.counts.false_positive ?? 0) +
    (summary.data?.hosts.counts.skipped ?? 0)
  const unreviewedFindings = summary.data?.findings.counts.todo ?? 0
  const reviewedFindings = (summary.data?.findings.total ?? 0) - unreviewedFindings

  const scope =
    networkId === 0
      ? 'the whole mission'
      : `the network “${(networks.data ?? []).find((n) => n.id === networkId)?.name ?? networkId}”`

  return (
    <PageContainer>
      <PageHeader
        title="Exports"
        description={`Download ${mission.data?.name ? `“${mission.data.name}”` : 'this mission'} in any format the server supports. Everything is generated locally - nothing leaves the machine.`}
      />

      <Card className="mt-5">
        <CardHeader
          title="Scope"
          description="Export the whole mission, or restrict it to a single network."
        />
        <CardBody>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-sm">
              <span className="text-muted">Export</span>
              <select
                value={networkId}
                onChange={(e) => setNetworkId(Number(e.target.value))}
                className="select-base"
              >
                <option value={0}>The whole mission</option>
                {(networks.data ?? []).map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name}
                    {n.vlan_id ? ` (VLAN ${n.vlan_id})` : ''}
                  </option>
                ))}
              </select>
            </label>
            <span className="text-xs text-faint">Downloads will cover {scope}.</span>
          </div>

          <div className="mt-4 space-y-4 border-t border-border pt-4">
            <div>
              <Toggle
                checked={includeDismissed}
                onChange={setIncludeDismissed}
                label="Include what I set aside"
                hint={
                  includeDismissed
                    ? 'Everything goes in, including skipped hosts and machines with all their services and findings, and anything marked skipped or a false positive. This is the handover version, not the one for the client.'
                    : 'Off: skipped hosts and machines leave with everything attached to them, and services and findings marked skipped or a false positive are left out.'
                }
              />
              {setAside > 0 && !includeDismissed && (
                <p className="mt-2 text-xs text-muted">
                  {formatNumber(setAside)} rows across this mission are set aside and will not
                  be in the download.
                </p>
              )}
            </div>

            <div>
              <Toggle
                checked={includeUnreviewed}
                onChange={setIncludeUnreviewed}
                label="Include the findings I have not reviewed yet"
                hint={
                  includeUnreviewed
                    ? 'Findings still at "to do" go in with the rest, exactly as the checks raised them.'
                    : 'Off: a finding still at "to do" is a check result nobody has read, which is not a verdict to put in front of a client. Services are never filtered this way: the list of open ports is inventory and goes in whole.'
                }
              />
              {unreviewedFindings > 0 && !includeUnreviewed && (
                <p
                  className={cn(
                    'mt-2 text-xs',
                    reviewedFindings === 0 ? 'text-warn' : 'text-muted',
                  )}
                >
                  {reviewedFindings === 0
                    ? `None of the ${formatNumber(unreviewedFindings)} findings has been reviewed yet, so the export would carry no finding at all. Turn this on, or go through them first.`
                    : `${formatNumber(unreviewedFindings)} findings have not been reviewed and will not be in the download. ${formatNumber(reviewedFindings)} will.`}
                </p>
              )}
            </div>

            <p className="text-xs text-faint">
              Whatever is left out, the export says on its own front page how many rows were
              held back and why, so a short file is never a silent one.
            </p>
          </div>
        </CardBody>
      </Card>

      <div className="mt-5">
        <h2 className="panel-title mb-3">Formats</h2>
        {formats.isLoading ? (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
        ) : formats.isError ? (
          <Card>
            <ErrorState
              title="Could not load the export formats"
              error={formats.error}
              retry={() => void formats.refetch()}
            />
          </Card>
        ) : (formats.data ?? []).length === 0 ? (
          <Card>
            <EmptyState
              icon={<ExportIcon width={20} height={20} />}
              title="No export format advertised"
              description="The server returned an empty format list."
            />
          </Card>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {(formats.data ?? []).map((f) => (
              <FormatCard
                key={f.id}
                format={f}
                missionId={missionId}
                networkId={networkId}
                keep={{ dismissed: includeDismissed, unreviewed: includeUnreviewed }}
              />
            ))}
          </div>
        )}
      </div>

      <p className="mt-5 pb-6 text-xs text-faint">
        Exports stream straight from the server with a Content-Disposition header, so a large
        mission does not have to be held in memory by the browser.
      </p>
    </PageContainer>
  )
}
