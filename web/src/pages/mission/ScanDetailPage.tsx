import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "@/lib/api";
import {
  useFindings,
  useHosts,
  useNetworks,
  useScan,
  useServices,
} from "@/lib/queries";
import { useMissionId, useTicker } from "@/lib/hooks";
import { useLive, useLiveVersion } from "@/live/LiveProvider";
import PageContainer from "@/components/layout/PageContainer";
import { Card, CardHeader, PageHeader } from "@/components/ui/Card";
import {
  Badge,
  ScanStatusBadge,
  SeverityBadge,
  ReachBadge,
} from "@/components/ui/Badge";
import { LinkButton } from "@/components/ui/Button";
import {
  EmptyState,
  ErrorState,
  InlineAlert,
  Skeleton,
} from "@/components/ui/Feedback";
import { Drawer } from "@/components/ui/Modal";
import { Mono, ProgressBar, RelativeTime, Tabs } from "@/components/common";
import ScanControls from "@/components/scan/ScanControls";
import LogPane from "@/components/scan/LogPane";
import ServiceDetail from "@/components/ServiceDetail";
import {
  elapsedSeconds,
  formatDuration,
  formatNumber,
  formatPercent,
  humanizeId,
} from "@/lib/format";
import { cn } from "@/lib/cn";
import {
  ALL_PHASES,
  BYPASS_TECHNIQUES,
  PHASE_LABELS,
  type Finding,
  type Host,
  type PhaseProgress,
  type Scan,
  type Service,
  type WorkPhase,
} from "@/types/api";
import { AlertIcon, BoltIcon, PauseIcon } from "@/components/icons";

// ---------------------------------------------------------------------------
// Phase strip
// ---------------------------------------------------------------------------

function PhaseRow({
  phase,
  running,
}: {
  phase: PhaseProgress;
  running: boolean;
}) {
  const total = phase.total || 0;
  const ratio = total > 0 ? phase.done / total : phase.started ? 1 : 0;
  const isActive = running && phase.active > 0;
  const complete = total > 0 && phase.done >= total;

  return (
    <div className="px-4 py-2.5">
      <div className="flex items-center justify-between gap-3 text-sm">
        <span className="flex min-w-0 items-center gap-2">
          <span
            className={cn(
              "inline-block h-1.5 w-1.5 shrink-0 rounded-full",
              complete
                ? "bg-ok"
                : isActive
                  ? "animate-pulse bg-accent"
                  : phase.started
                    ? "bg-warn"
                    : "bg-border-strong",
            )}
          />
          <span
            className={cn("truncate", phase.started ? "text-fg" : "text-faint")}
          >
            {PHASE_LABELS[phase.phase] ?? humanizeId(phase.phase)}
          </span>
          {phase.failed > 0 && (
            <Badge tone="crit" title={`${phase.failed} work units failed`}>
              {formatNumber(phase.failed)} failed
            </Badge>
          )}
          {isActive && (
            <Badge tone="accent">{formatNumber(phase.active)} in flight</Badge>
          )}
        </span>
        <span className="shrink-0 tabular text-xs text-muted">
          {formatNumber(phase.done)} / {formatNumber(total)}
        </span>
      </div>
      <ProgressBar
        className="mt-1.5"
        height="h-1.5"
        value={ratio}
        striped={isActive}
        tone={
          complete
            ? "ok"
            : isActive
              ? "accent"
              : phase.started
                ? "warn"
                : "muted"
        }
        label={PHASE_LABELS[phase.phase] ?? phase.phase}
      />
    </div>
  );
}

function PhasesCard({ scan }: { scan: Scan }) {
  const given = scan.phases ?? [];
  // Keep the canonical order even if the server has not created every phase.
  const byPhase = new Map<WorkPhase, PhaseProgress>();
  for (const p of given) byPhase.set(p.phase, p);
  const ordered = ALL_PHASES.filter((p) => byPhase.has(p)).map((p) =>
    byPhase.get(p)!,
  );
  const extras = given.filter((p) => !ALL_PHASES.includes(p.phase));
  const rows = [...ordered, ...extras];

  return (
    <Card>
      <CardHeader
        title="Phases"
        description="Each phase is split into persisted work units: a pause or a crash never loses them."
      />
      {rows.length === 0 ? (
        <p className="px-4 py-6 text-center text-sm text-muted">
          Work units are created when the scan starts.
        </p>
      ) : (
        <div className="divide-y divide-border">
          {rows.map((p) => (
            <PhaseRow
              key={p.phase}
              phase={p}
              running={scan.status === "running"}
            />
          ))}
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Live counters
// ---------------------------------------------------------------------------

function Counter({
  label,
  value,
  tone,
}: {
  label: string;
  value: number;
  tone?: "default" | "crit" | "ok" | "accent";
}) {
  return (
    <div className="px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">
        {label}
      </div>
      <div
        className={cn(
          "tabular text-lg font-semibold",
          tone === "crit"
            ? "text-crit"
            : tone === "ok"
              ? "text-ok"
              : tone === "accent"
                ? "text-accent"
                : "text-fg",
        )}
      >
        {formatNumber(value)}
      </div>
    </div>
  );
}

function StatsCard({ scan }: { scan: Scan }) {
  const s = scan.stats ?? ({} as Scan["stats"]);
  const segmentation = scan.kind === "segmentation";
  return (
    <Card>
      <CardHeader
        title="Live counters"
        description="Updated as results are persisted."
      />
      <div className="grid grid-cols-2 divide-x divide-y divide-border sm:grid-cols-3 lg:grid-cols-5">
        <Counter label="Targets" value={s.targets_total ?? 0} />
        <Counter label="Hosts up" value={s.hosts_up ?? 0} tone="accent" />
        <Counter label="Open ports" value={s.ports_open ?? 0} />
        <Counter label="Services" value={s.services ?? 0} />
        <Counter
          label="Findings"
          value={s.findings ?? 0}
          tone={(s.findings ?? 0) > 0 ? "crit" : "default"}
        />
        {segmentation ? (
          <>
            <Counter label="Reach tested" value={s.reach_tested ?? 0} />
            <Counter
              label="Reachable"
              value={s.reach_ok ?? 0}
              tone={(s.reach_ok ?? 0) > 0 ? "crit" : "ok"}
            />
          </>
        ) : (
          <>
            <Counter label="New assets" value={s.new_assets ?? 0} />
            <Counter
              label="Matched assets"
              value={s.matched_assets ?? 0}
              tone="ok"
            />
          </>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Live result tables
// ---------------------------------------------------------------------------

type ResultTab = "hosts" | "services" | "findings" | "reach";

function NewBadge() {
  return (
    <Badge tone="accent" className="px-1 py-0 text-[10px]">
      new
    </Badge>
  );
}

export default function ScanDetailPage() {
  const missionId = useMissionId();
  const { scanId: scanIdParam } = useParams();
  const scanId = Number(scanIdParam);
  const scanQuery = useScan(scanId);
  const networks = useNetworks(missionId);
  const { store } = useLive();
  const version = useLiveVersion();
  const [tab, setTab] = useState<ResultTab>("hosts");
  const [openService, setOpenService] = useState<Service | null>(null);

  const scan = scanQuery.data;
  const running = scan?.status === "running";
  useTicker(1000, running);

  // Seed the log pane with the history the server already holds.
  useEffect(() => {
    let cancelled = false;
    if (!scanId) return;
    void api
      .scanLogs(scanId, 0, 500)
      .then((lines) => {
        if (!cancelled && lines.length > 0) store.seedLogs(scanId, lines);
      })
      .catch(() => {
        /* the log endpoint may not be available; the live stream still works */
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, store]);

  useEffect(() => () => store.release(scanId), [scanId, store]);

  // Rows persisted before this page was opened, merged with the live stream.
  const hostsQuery = useHosts(missionId);
  const findingsQuery = useFindings(missionId);
  const servicesQuery = useServices(missionId, { limit: 500 });

  const buffers = store.buffers(scanId);
  // `version` is read so this component re-renders when the store changes.
  void version;

  const liveHosts = buffers ? [...buffers.hosts.values()] : [];
  const liveServices = buffers ? [...buffers.services.values()] : [];
  const liveFindings = buffers ? [...buffers.findings.values()] : [];
  const liveReach = buffers ? buffers.reach : [];
  const seen = buffers?.seen;
  /** A row counts as "new" for 15 s after it streamed in. */
  const isFresh = (id: number): boolean => {
    const t = seen?.get(id);
    return t !== undefined && Date.now() - t < 15_000;
  };

  const hosts = useMemo(() => {
    const map = new Map<number, Host>();
    for (const h of hostsQuery.data ?? [])
      if (h.last_scan_id === scanId) map.set(h.id, h);
    for (const h of liveHosts) map.set(h.id, h);
    return [...map.values()].sort((a, b) => b.id - a.id);
  }, [hostsQuery.data, liveHosts, scanId]);

  const services = useMemo(() => {
    const map = new Map<number, Service>();
    for (const s of servicesQuery.data?.items ?? []) {
      if (s.last_scan_id === scanId) map.set(s.id, s);
    }
    for (const s of liveServices) map.set(s.id, s);
    return [...map.values()].sort((a, b) => b.id - a.id);
  }, [servicesQuery.data, liveServices, scanId]);

  const findings = useMemo(() => {
    const map = new Map<number, Finding>();
    for (const f of findingsQuery.data ?? [])
      if (f.last_scan_id === scanId) map.set(f.id, f);
    for (const f of liveFindings) map.set(f.id, f);
    return [...map.values()].sort((a, b) => b.id - a.id);
  }, [findingsQuery.data, liveFindings, scanId]);

  const reach = useMemo(() => [...liveReach].reverse(), [liveReach]);

  const netName = useMemo(() => {
    const m = new Map<number, string>();
    for (const n of networks.data ?? []) m.set(n.id, n.name);
    return m;
  }, [networks.data]);

  const logs = buffers?.logs ?? [];

  if (scanQuery.isLoading) {
    return (
      <PageContainer>
        <Skeleton className="h-9 w-64" />
        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-40 lg:col-span-2" />
          <Skeleton className="h-40" />
        </div>
      </PageContainer>
    );
  }

  if (scanQuery.isError || !scan) {
    return (
      <PageContainer>
        <ErrorState
          title="Could not load this scan"
          error={scanQuery.error}
          retry={() => void scanQuery.refetch()}
        />
      </PageContainer>
    );
  }

  const elapsed = elapsedSeconds(scan.started_at, scan.finished_at ?? null);
  const doneUnits = (scan.phases ?? []).reduce((n, p) => n + p.done, 0);
  const totalUnits = (scan.phases ?? []).reduce((n, p) => n + p.total, 0);

  const tabs: { id: ResultTab; label: string; count: number }[] = [
    { id: "hosts", label: "Hosts", count: hosts.length },
    { id: "services", label: "Services", count: services.length },
    { id: "findings", label: "Findings", count: findings.length },
    ...(scan.kind === "segmentation"
      ? [{ id: "reach" as const, label: "Reachability", count: reach.length }]
      : []),
  ];

  return (
    <PageContainer wide>
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-2.5">
            Scan #{scan.id}
            <span className="text-base font-normal capitalize text-muted">
              {scan.kind}
            </span>
            <ScanStatusBadge status={scan.status} />
            {scan.options?.profile && (
              <Badge tone="neutral">{scan.options.profile} profile</Badge>
            )}
          </span>
        }
        description={
          <span>
            On{" "}
            <Link to="../networks" className="text-accent hover:underline">
              {netName.get(scan.network_id) ?? `network ${scan.network_id}`}
            </Link>{" "}
            · created <RelativeTime value={scan.created_at} />
            {scan.started_at && (
              <>
                {" "}
                · started <RelativeTime value={scan.started_at} />
              </>
            )}
            {elapsed !== null && (
              <>
                {" "}
                · {scan.finished_at ? "ran for" : "running for"}{" "}
                <span className="tabular">{formatDuration(elapsed)}</span>
              </>
            )}
          </span>
        }
        actions={<ScanControls scan={scan} missionId={missionId} size="lg" />}
      />

      {scan.status === "paused" && (
        <InlineAlert
          tone="warn"
          className="mt-4"
          icon={<PauseIcon />}
          title="Paused — nothing is lost"
        >
          {formatNumber(doneUnits)} of {formatNumber(totalUnits)} work units are
          done and stored. Resuming continues with the pending ones only;
          in-flight probes were allowed to finish before the scan stopped. The
          scan survives a server restart in this state.
        </InlineAlert>
      )}

      {(scan.status === "failed" || scan.status === "cancelled") &&
        scan.resumable && (
          <InlineAlert
            tone="info"
            className="mt-4"
            title={scan.status === "failed" ? "Interrupted" : "Stopped"}
          >
            {formatNumber(doneUnits)} of {formatNumber(totalUnits)} work units
            completed and all their results are kept. Press{" "}
            <strong className="text-fg">Resume</strong> to replay only the
            pending tail.
          </InlineAlert>
        )}

      {scan.error && (
        <InlineAlert
          tone="crit"
          className="mt-4"
          title="Scan error"
          icon={<AlertIcon />}
        >
          {scan.error}
        </InlineAlert>
      )}

      {/* progress + phases + counters */}
      {/* items-start: the phase list grows with the number of phases, and
          without this the progress card stretches to match it and shows a
          large empty area. */}
      <div className="mt-5 grid items-start gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <div className="px-4 py-4">
              <div className="flex flex-wrap items-end justify-between gap-3">
                <div>
                  <div className="panel-title">Current phase</div>
                  <div className="mt-0.5 text-lg font-semibold">
                    {scan.phase ||
                      (scan.status === "completed"
                        ? "Finished"
                        : "Waiting to start")}
                  </div>
                </div>
                <div className="text-right">
                  <div className="tabular text-3xl font-semibold text-accent">
                    {formatPercent(scan.progress, 1)}
                  </div>
                  <div className="text-xs text-muted">
                    {running && scan.eta_seconds ? (
                      <>
                        ETA{" "}
                        <span className="tabular">
                          {formatDuration(scan.eta_seconds)}
                        </span>
                      </>
                    ) : scan.status === "completed" && elapsed !== null ? (
                      <>completed in {formatDuration(elapsed)}</>
                    ) : totalUnits > 0 ? (
                      <>
                        {formatNumber(doneUnits)} / {formatNumber(totalUnits)}{" "}
                        work units
                      </>
                    ) : (
                      "—"
                    )}
                  </div>
                </div>
              </div>
              <ProgressBar
                className="mt-3"
                height="h-2.5"
                value={scan.progress}
                striped={running}
                tone={
                  scan.status === "completed"
                    ? "ok"
                    : scan.status === "failed"
                      ? "crit"
                      : scan.status === "paused"
                        ? "warn"
                        : "accent"
                }
                label="Overall scan progress"
              />
            </div>
          </Card>

          {/* Stacked beneath the progress card so the column fills the height of
            the phase list instead of leaving a gap beside it. */}
          <StatsCard scan={scan} />
        </div>

        <PhasesCard scan={scan} />
      </div>

      {/* log + results */}
      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Card className="overflow-hidden">
          <LogPane lines={logs} height="h-[420px]" />
        </Card>

        <Card className="flex min-h-0 flex-col overflow-hidden">
          <div className="px-3 pt-2">
            <Tabs tabs={tabs} active={tab} onChange={setTab} />
          </div>
          <div className="h-[420px] min-h-0 overflow-auto">
            {tab === "hosts" && (
              <ResultTable
                empty="Hosts appear here the moment discovery answers."
                head={["IP", "MAC / vendor", "Hostname", "OS", "Found by"]}
                rows={hosts.map((h) => ({
                  key: h.id,
                  fresh: isFresh(h.id),
                  cells: [
                    <span key="ip" className="flex items-center gap-1.5">
                      <Mono>{h.ip}</Mono>
                      {isFresh(h.id) && <NewBadge />}
                    </span>,
                    <span key="mac" className="text-muted">
                      {h.mac ? <Mono>{h.mac}</Mono> : "—"}
                      {h.vendor ? (
                        <span className="ml-1 text-faint">{h.vendor}</span>
                      ) : null}
                    </span>,
                    h.hostname || "—",
                    h.os || "—",
                    (h.discovered_by ?? []).join(", ") || "—",
                  ],
                }))}
              />
            )}

            {tab === "services" && (
              <ResultTable
                empty="Services fill in as ports open and the fingerprinter identifies them."
                head={["Endpoint", "Service", "Product", "Confidence", ""]}
                rows={services.map((s) => ({
                  key: s.id,
                  fresh: isFresh(s.id),
                  cells: [
                    <span key="ep" className="flex items-center gap-1.5">
                      <Mono>
                        {s.ip}:{s.port}
                      </Mono>
                      <span className="text-faint">/{s.protocol}</span>
                      {isFresh(s.id) && <NewBadge />}
                    </span>,
                    <span key="name" className="flex items-center gap-1.5">
                      {s.name || <span className="text-faint">unknown</span>}
                      {s.tunnel && <Badge tone="info">{s.tunnel}</Badge>}
                    </span>,
                    <span key="prod" className="text-muted">
                      {[s.product, s.version].filter(Boolean).join(" ") || "—"}
                    </span>,
                    <span key="conf" className="tabular text-muted">
                      {s.confidence}
                    </span>,
                    <button
                      key="open"
                      type="button"
                      onClick={() => setOpenService(s)}
                      className="rounded text-xs text-accent hover:underline"
                    >
                      Details
                    </button>,
                  ],
                }))}
              />
            )}

            {tab === "findings" && (
              <ResultTable
                empty="Findings appear as the check phase runs."
                head={["Severity", "Title", "Host", "Port"]}
                rows={findings.map((f) => ({
                  key: f.id,
                  fresh: isFresh(f.id),
                  cells: [
                    <SeverityBadge key="sev" severity={f.severity} />,
                    <span key="title" className="flex items-center gap-1.5">
                      {f.title}
                      {isFresh(f.id) && <NewBadge />}
                    </span>,
                    <Mono key="ip">{f.ip}</Mono>,
                    f.port ? `${f.port}/${f.protocol ?? "tcp"}` : "—",
                  ],
                }))}
              />
            )}

            {tab === "reach" && (
              <ResultTable
                empty="Reachability results stream in as each service is retried."
                head={["Target", "Technique", "Status", "Detail"]}
                rows={reach.map((r, i) => ({
                  key: r.id || -i,
                  fresh: false,
                  cells: [
                    <span key="t" className="flex items-center gap-1.5">
                      <Mono>
                        {r.ip}
                        {r.port ? `:${r.port}` : ""}
                      </Mono>
                      <span className="text-faint">
                        {netName.get(r.target_network_id) ??
                          r.target_network_id}
                      </span>
                    </span>,
                    <span key="tech" className="flex items-center gap-1.5">
                      <Mono className="text-muted">{r.technique}</Mono>
                      {BYPASS_TECHNIQUES.has(r.technique) && (
                        <Badge
                          tone="warn"
                          title="Not plain routing: this is a bypass technique"
                        >
                          <BoltIcon width={10} height={10} />
                          bypass
                        </Badge>
                      )}
                      {r.vlan_id ? (
                        <Badge tone="accent">vlan {r.vlan_id}</Badge>
                      ) : null}
                    </span>,
                    <ReachBadge key="st" status={r.status} />,
                    <span key="d" className="text-muted">
                      {r.detail || "—"}
                    </span>,
                  ],
                }))}
              />
            )}
          </div>
        </Card>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2 pb-6 text-xs text-muted">
        <span>Full tables:</span>
        <LinkButton to="../hosts" size="sm">
          Hosts
        </LinkButton>
        <LinkButton to="../services" size="sm">
          Services
        </LinkButton>
        <LinkButton to="../findings" size="sm">
          Findings
        </LinkButton>
        {scan.kind === "segmentation" && (
          <LinkButton to="../matrix" size="sm">
            Segmentation matrix
          </LinkButton>
        )}
      </div>

      <Drawer
        open={!!openService}
        onClose={() => setOpenService(null)}
        title={
          openService
            ? `${openService.ip}:${openService.port}/${openService.protocol}`
            : ""
        }
        subtitle={openService?.name}
      >
        {openService && <ServiceDetail service={openService} />}
      </Drawer>
    </PageContainer>
  );
}

/** Compact table used by the live result tabs. */
function ResultTable({
  head,
  rows,
  empty,
}: {
  head: string[];
  rows: { key: number; cells: React.ReactNode[]; fresh?: boolean }[];
  empty: string;
}) {
  if (rows.length === 0) {
    return (
      <EmptyState title="Nothing yet" description={empty} className="py-12" />
    );
  }
  return (
    <div className="table-scroll">
      <table className="data-table">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.key} className={r.fresh ? "animate-row-in" : undefined}>
              {r.cells.map((c, i) => (
                <td key={i}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
