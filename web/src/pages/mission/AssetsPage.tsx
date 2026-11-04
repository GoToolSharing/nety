import { useEffect, useMemo, useState } from 'react'
import { useAssets, useMergeAssets, useNetworks, usePatchAsset } from '@/lib/queries'
import { useMissionId } from '@/lib/hooks'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, KeyValue, PageHeader } from '@/components/ui/Card'
import { Drawer, ConfirmDialog } from '@/components/ui/Modal'
import { Button } from '@/components/ui/Button'
import { SelectField, TextAreaField, TextField } from '@/components/ui/Field'
import { EmptyState, ErrorState, InlineAlert, TableSkeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { useToast } from '@/components/ui/Toast'
import {
  FilterChips,
  Mono,
  RelativeTime,
  SearchInput,
  SortHeader,
  useSort,
} from '@/components/common'
import { compareIP, formatNumber, humanizeId } from '@/lib/format'
import { cn } from '@/lib/cn'
import { ASSET_KIND_LABELS, AssetKindIcon, AssetIcon, MergeIcon } from '@/components/icons'
import { ASSET_KINDS, type Asset, type AssetKind } from '@/types/api'

type SortKey = 'label' | 'kind' | 'os' | 'domain' | 'ips' | 'last_seen'

function confidenceTone(c: number): 'ok' | 'warn' | 'neutral' {
  if (c >= 80) return 'ok'
  if (c >= 50) return 'warn'
  return 'neutral'
}

function AssetDrawer({
  asset,
  assets,
  networkName,
  onClose,
}: {
  asset: Asset | null
  assets: Asset[]
  networkName: (id: number) => string
  onClose: () => void
}) {
  const missionId = useMissionId()
  const { canWrite } = useAuth()
  const toast = useToast()
  const patch = usePatchAsset(missionId)
  const merge = useMergeAssets(missionId)

  const [label, setLabel] = useState('')
  const [kind, setKind] = useState<AssetKind>('unknown')
  const [tags, setTags] = useState('')
  const [notes, setNotes] = useState('')
  const [mergeSource, setMergeSource] = useState('')
  const [confirmMerge, setConfirmMerge] = useState(false)

  useEffect(() => {
    if (!asset) return
    setLabel(asset.label)
    setKind(asset.kind)
    setTags((asset.tags ?? []).join(', '))
    setNotes(asset.notes ?? '')
    setMergeSource('')
  }, [asset])

  if (!asset) return null

  const dirty =
    label !== asset.label ||
    kind !== asset.kind ||
    tags !== (asset.tags ?? []).join(', ') ||
    notes !== (asset.notes ?? '')

  const save = async () => {
    try {
      await patch.mutateAsync({
        id: asset.id,
        body: {
          label: label.trim(),
          kind,
          tags: tags
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean),
          notes,
        },
      })
      toast.success('Asset updated')
    } catch (err) {
      toast.error('Could not update the asset', err)
    }
  }

  const sourceAsset = assets.find((a) => a.id === Number(mergeSource))

  return (
    <>
      <Drawer
        open
        onClose={onClose}
        width="lg"
        title={
          <span className="flex items-center gap-2">
            <AssetKindIcon kind={asset.kind} width={18} height={18} className="text-accent" />
            {asset.label || `Asset #${asset.id}`}
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone="neutral">{ASSET_KIND_LABELS[asset.kind] ?? asset.kind}</Badge>
            {asset.domain && <span>{asset.domain}</span>}
            {asset.os && <span>· {asset.os}</span>}
          </span>
        }
      >
        <section>
          <h3 className="panel-title mb-1.5">Identity</h3>
          <dl className="rounded-md border border-border bg-elevated/50 px-3 py-2">
            <KeyValue label="Hostname">{asset.hostname || '-'}</KeyValue>
            <KeyValue label="Domain">{asset.domain || '-'}</KeyValue>
            <KeyValue label="OS">{asset.os || '-'}</KeyValue>
            <KeyValue label="Seen">
              <RelativeTime value={asset.last_seen} /> · first{' '}
              <RelativeTime value={asset.first_seen} />
            </KeyValue>
          </dl>
        </section>

        <section className="mt-4">
          <h3 className="panel-title mb-1.5">
            Addresses ({(asset.ips ?? []).length}) - the same machine across VLANs
          </h3>
          <div className="table-scroll rounded-md border border-border">
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Network</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(asset.ips ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={4} className="text-center text-muted">
                      No address recorded.
                    </td>
                  </tr>
                ) : (
                  [...(asset.ips ?? [])]
                    .sort((a, b) => compareIP(a.ip, b.ip))
                    .map((ip) => (
                      <tr key={`${ip.ip}-${ip.network_id}`}>
                        <td>
                          <Mono className="font-medium">{ip.ip}</Mono>
                        </td>
                        <td className="text-muted">{networkName(ip.network_id)}</td>
                        <td className="text-muted">
                          <RelativeTime value={ip.first_seen} />
                        </td>
                        <td className="text-muted">
                          <RelativeTime value={ip.last_seen} />
                        </td>
                      </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="mt-4">
          <h3 className="panel-title mb-1.5">
            Identity keys ({(asset.keys ?? []).length}) - why NETY believes it is the same machine
          </h3>
          <div className="table-scroll rounded-md border border-border">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Kind</th>
                  <th>Value</th>
                  <th>Source</th>
                  <th className="text-right">Confidence</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(asset.keys ?? []).length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center text-muted">
                      No identity evidence collected. Enable identity collection on the scan.
                    </td>
                  </tr>
                ) : (
                  [...(asset.keys ?? [])]
                    .sort((a, b) => b.confidence - a.confidence)
                    .map((k, i) => (
                      <tr key={`${k.kind}-${k.value}-${i}`}>
                        <td>
                          <Badge tone="accent">{k.kind}</Badge>
                        </td>
                        <td className="max-w-[260px] truncate" title={k.value}>
                          <Mono>{k.value}</Mono>
                        </td>
                        <td className="text-muted">
                          <Mono>{k.source || '-'}</Mono>
                        </td>
                        <td className="text-right">
                          <Badge tone={confidenceTone(k.confidence)}>{k.confidence}/100</Badge>
                        </td>
                        <td className="text-muted">
                          <RelativeTime value={k.last_seen} />
                        </td>
                      </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        {canWrite && (
          <>
            <section className="mt-5">
              <h3 className="panel-title mb-1.5">Edit</h3>
              <div className="space-y-3 rounded-md border border-border bg-elevated/50 p-3">
                <div className="grid gap-3 sm:grid-cols-2">
                  <TextField
                    label="Label"
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    hint="Shown everywhere this asset appears."
                  />
                  <SelectField
                    label="Kind"
                    value={kind}
                    onChange={(e) => setKind(e.target.value as AssetKind)}
                  >
                    {ASSET_KINDS.map((k) => (
                      <option key={k} value={k}>
                        {ASSET_KIND_LABELS[k]}
                      </option>
                    ))}
                  </SelectField>
                </div>
                <TextField
                  label="Tags"
                  value={tags}
                  onChange={(e) => setTags(e.target.value)}
                  placeholder="crown-jewel, pci, legacy"
                  hint="Comma-separated."
                />
                <TextAreaField
                  label="Notes"
                  rows={3}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="Anything worth remembering for the report."
                />
                <div className="flex justify-end">
                  <Button
                    variant="primary"
                    disabled={!dirty}
                    loading={patch.isPending}
                    onClick={() => void save()}
                  >
                    Save changes
                  </Button>
                </div>
              </div>
            </section>

            <section className="mt-5 pb-4">
              <h3 className="panel-title mb-1.5">Merge another asset into this one</h3>
              <div className="space-y-3 rounded-md border border-border bg-elevated/50 p-3">
                <p className="text-xs text-muted">
                  Use this when the correlator split one machine in two - for example the same
                  server seen on two VLANs without a shared identity key. The source asset's IPs
                  and keys move here, and the source disappears.
                </p>
                <SelectField
                  label="Asset to merge in (source)"
                  value={mergeSource}
                  onChange={(e) => setMergeSource(e.target.value)}
                >
                  <option value="">Choose an asset…</option>
                  {assets
                    .filter((a) => a.id !== asset.id)
                    .map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.label || `Asset #${a.id}`}
                        {a.hostname ? ` - ${a.hostname}` : ''} (
                        {(a.ips ?? []).map((i) => i.ip).join(', ') || 'no IP'})
                      </option>
                    ))}
                </SelectField>
                <div className="flex justify-end">
                  <Button
                    variant="danger"
                    icon={<MergeIcon />}
                    disabled={!mergeSource}
                    onClick={() => setConfirmMerge(true)}
                  >
                    Merge
                  </Button>
                </div>
              </div>
            </section>
          </>
        )}
      </Drawer>

      <ConfirmDialog
        open={confirmMerge}
        onClose={() => setConfirmMerge(false)}
        destructive
        title="Merge assets?"
        confirmLabel="Merge"
        busy={merge.isPending}
        body={
          <>
            <strong className="text-fg">{sourceAsset?.label || mergeSource}</strong> will be
            merged into <strong className="text-fg">{asset.label || `#${asset.id}`}</strong>. Its
            addresses and identity keys move over and the source asset is removed. This cannot be
            undone.
          </>
        }
        onConfirm={async () => {
          try {
            await merge.mutateAsync({ id: asset.id, source_id: Number(mergeSource) })
            toast.success('Assets merged')
            setConfirmMerge(false)
            setMergeSource('')
          } catch (err) {
            toast.error('Could not merge the assets', err)
          }
        }}
      />
    </>
  )
}

export default function AssetsPage() {
  const missionId = useMissionId()
  const assets = useAssets(missionId)
  const networks = useNetworks(missionId)
  const [query, setQuery] = useState('')
  const [kindFilter, setKindFilter] = useState<AssetKind | 'all'>('all')
  const { sort, onSort } = useSort<SortKey>('label')
  const [selected, setSelected] = useState<Asset | null>(null)

  const netName = (id: number) =>
    (networks.data ?? []).find((n) => n.id === id)?.name ?? `network ${id}`

  const all = assets.data ?? []

  // Keep the drawer in sync when a live event updates the selected asset.
  const selectedLive = selected ? (all.find((a) => a.id === selected.id) ?? selected) : null

  const kindCounts = useMemo(() => {
    const c = new Map<AssetKind, number>()
    for (const a of all) c.set(a.kind, (c.get(a.kind) ?? 0) + 1)
    return c
  }, [all])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const filtered = all.filter((a) => {
      if (kindFilter !== 'all' && a.kind !== kindFilter) return false
      if (!q) return true
      return (
        a.label.toLowerCase().includes(q) ||
        (a.hostname ?? '').toLowerCase().includes(q) ||
        (a.domain ?? '').toLowerCase().includes(q) ||
        (a.os ?? '').toLowerCase().includes(q) ||
        (a.tags ?? []).some((t) => t.toLowerCase().includes(q)) ||
        (a.ips ?? []).some((ip) => ip.ip.includes(q)) ||
        (a.keys ?? []).some((k) => k.value.toLowerCase().includes(q))
      )
    })
    const dir = sort.dir === 'asc' ? 1 : -1
    return filtered.sort((a, b) => {
      switch (sort.key) {
        case 'label':
          return dir * a.label.localeCompare(b.label)
        case 'kind':
          return dir * a.kind.localeCompare(b.kind)
        case 'os':
          return dir * (a.os ?? '').localeCompare(b.os ?? '')
        case 'domain':
          return dir * (a.domain ?? '').localeCompare(b.domain ?? '')
        case 'ips':
          return dir * ((a.ips ?? []).length - (b.ips ?? []).length)
        case 'last_seen':
          return dir * a.last_seen.localeCompare(b.last_seen)
      }
    })
  }, [all, query, kindFilter, sort])

  const multiVlan = all.filter(
    (a) => new Set((a.ips ?? []).map((i) => i.network_id)).size > 1,
  ).length

  return (
    <PageContainer wide>
      <PageHeader
        title="Assets"
        description="Stable machine identities. The same server keeps one entry across days, IP changes and VLANs, so a re-scan does not produce a brand-new inventory."
      />

      {multiVlan > 0 && (
        <InlineAlert tone="info" className="mt-4">
          {multiVlan} asset{multiVlan > 1 ? 's are' : ' is'} present on more than one network -
          a multi-homed machine is often the shortest path across a segment boundary.
        </InlineAlert>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-3">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Label, hostname, IP, identity key…"
          className="w-full max-w-sm"
        />
        <span className="tabular text-xs text-faint">{formatNumber(rows.length)} assets</span>
      </div>

      <FilterChips<AssetKind | 'all'>
        className="mt-3"
        value={kindFilter}
        onChange={setKindFilter}
        options={[
          { value: 'all', label: 'All kinds', count: all.length },
          ...ASSET_KINDS.filter((k) => (kindCounts.get(k) ?? 0) > 0).map((k) => ({
            value: k as AssetKind,
            label: (
              <span className="flex items-center gap-1.5">
                <AssetKindIcon kind={k} width={12} height={12} />
                {ASSET_KIND_LABELS[k]}
              </span>
            ),
            count: kindCounts.get(k) ?? 0,
          })),
        ]}
      />

      <Card className="mt-4">
        {assets.isLoading ? (
          <TableSkeleton rows={10} columns={6} />
        ) : assets.isError ? (
          <ErrorState
            title="Could not load the assets"
            error={assets.error}
            retry={() => void assets.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<AssetIcon width={20} height={20} />}
            title={all.length === 0 ? 'No asset yet' : 'No asset matches those filters'}
            description={
              all.length === 0
                ? 'Assets are built by the identity phase of a discovery scan: SMB server GUIDs, SSH host keys, TLS certificates, NetBIOS names and SNMP engine IDs are correlated into one machine.'
                : 'Clear the search or pick another kind.'
            }
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <SortHeader column="label" label="Asset" sort={sort} onSort={onSort} />
                  <SortHeader column="kind" label="Kind" sort={sort} onSort={onSort} />
                  <SortHeader column="os" label="OS" sort={sort} onSort={onSort} />
                  <SortHeader column="domain" label="Domain" sort={sort} onSort={onSort} />
                  <SortHeader column="ips" label="Addresses" sort={sort} onSort={onSort} />
                  <th>Identity keys</th>
                  <th>Tags</th>
                  <SortHeader column="last_seen" label="Last seen" sort={sort} onSort={onSort} />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => {
                  const nets = new Set((a.ips ?? []).map((i) => i.network_id))
                  return (
                    <tr
                      key={a.id}
                      className="cursor-pointer"
                      tabIndex={0}
                      onClick={() => setSelected(a)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault()
                          setSelected(a)
                        }
                      }}
                    >
                      <td className="font-medium">
                        <span className="flex items-center gap-2">
                          <AssetKindIcon
                            kind={a.kind}
                            width={15}
                            height={15}
                            className="shrink-0 text-faint"
                          />
                          <span className="truncate">{a.label || `Asset #${a.id}`}</span>
                        </span>
                        {a.hostname && a.hostname !== a.label && (
                          <span className="ml-[23px] block text-xs text-faint">{a.hostname}</span>
                        )}
                      </td>
                      <td className="text-muted">{ASSET_KIND_LABELS[a.kind] ?? a.kind}</td>
                      <td className="max-w-[200px] truncate text-muted" title={a.os}>
                        {a.os || '-'}
                      </td>
                      <td className="text-muted">{a.domain || '-'}</td>
                      <td>
                        <span className="flex flex-wrap items-center gap-1">
                          {(a.ips ?? []).slice(0, 3).map((ip) => (
                            <span
                              key={`${ip.ip}-${ip.network_id}`}
                              title={`Seen on ${netName(ip.network_id)}`}
                              className="inline-flex items-center gap-1 rounded border border-border bg-elevated px-1.5 py-0.5 font-mono text-[11px]"
                            >
                              {ip.ip}
                            </span>
                          ))}
                          {(a.ips ?? []).length > 3 && (
                            <span className="text-xs text-faint">
                              +{(a.ips ?? []).length - 3}
                            </span>
                          )}
                          {nets.size > 1 && (
                            <Badge tone="warn" title="Present on several networks">
                              {nets.size} VLANs
                            </Badge>
                          )}
                        </span>
                      </td>
                      <td>
                        <span className="flex flex-wrap gap-1">
                          {[...new Set((a.keys ?? []).map((k) => k.kind))]
                            .slice(0, 3)
                            .map((k) => (
                              <Badge key={k} tone="neutral" title={humanizeId(k)}>
                                {k}
                              </Badge>
                            ))}
                          {(a.keys ?? []).length === 0 && <span className="text-faint">-</span>}
                        </span>
                      </td>
                      <td>
                        <span className="flex flex-wrap gap-1">
                          {(a.tags ?? []).map((t) => (
                            <Badge key={t} tone="accent">
                              {t}
                            </Badge>
                          ))}
                          {(a.tags ?? []).length === 0 && <span className="text-faint">-</span>}
                        </span>
                      </td>
                      <td className={cn('text-muted')}>
                        <RelativeTime value={a.last_seen} />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <AssetDrawer
        asset={selectedLive}
        assets={all}
        networkName={netName}
        onClose={() => setSelected(null)}
      />
    </PageContainer>
  )
}
