import { useState } from 'react'
import { api } from '@/lib/api'
import { useExportFormats, useMission, useNetworks } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardBody, CardHeader, PageHeader } from '@/components/ui/Card'
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { Mono } from '@/components/common'
import { cn } from '@/lib/cn'
import { DownloadIcon, ExportIcon } from '@/components/icons'
import type { ExportFormat } from '@/types/api'

/** Short, honest descriptions of what each built-in format is good for. */
const FORMAT_BLURB: Record<string, string> = {
  json: 'The whole mission as one JSON document — networks, scans, hosts, services, assets, findings, reachability and matrix.',
  'csv-hosts': 'One row per host: IP, MAC, vendor, hostname, OS, network.',
  'csv-services': 'One row per service: address, port, protocol, product, version, TLS and HTTP summary.',
  'csv-findings': 'One row per finding, with severity, evidence and remediation.',
  'csv-reach': 'One row per reachability test: source, target, technique, status.',
  'csv-assets': 'One row per asset with its addresses and identity keys.',
  'csv-matrix': 'The source × target grid: how many services each network could reach in the next.',
  'nmap-xml': 'Nmap XML, for tools that already ingest nmap output.',
  gnmap: 'Grepable nmap output.',
  'targets-txt': 'Plain list of live addresses — feed it to your next tool.',
  markdown: 'Report-ready Markdown.',
  html: 'Self-contained HTML report you can hand over as is.',
  xlsx: 'Excel workbook with one sheet per table.',
}

function FormatCard({
  format,
  missionId,
  networkId,
}: {
  format: ExportFormat
  missionId: number
  networkId: number
}) {
  const href = api.exportUrl(missionId, format.id, networkId || undefined)
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
  const [networkId, setNetworkId] = useState(0)

  const scope =
    networkId === 0
      ? 'the whole mission'
      : `the network “${(networks.data ?? []).find((n) => n.id === networkId)?.name ?? networkId}”`

  return (
    <PageContainer>
      <PageHeader
        title="Exports"
        description={`Download ${mission.data?.name ? `“${mission.data.name}”` : 'this mission'} in any format the server supports. Everything is generated locally — nothing leaves the machine.`}
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
              <FormatCard key={f.id} format={f} missionId={missionId} networkId={networkId} />
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
