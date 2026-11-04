import { KeyValue } from '@/components/ui/Card'
import { Badge, PortStateBadge } from '@/components/ui/Badge'
import { CopyButton, Mono, RelativeTime } from '@/components/common'
import { formatBytes, formatNumber } from '@/lib/format'
import { cn } from '@/lib/cn'
import type { Service } from '@/types/api'

function Section({
  title,
  children,
  tone,
}: {
  title: string
  children: React.ReactNode
  tone?: 'default' | 'warn'
}) {
  return (
    <section className="mt-4 first:mt-0">
      <h3
        className={cn(
          'mb-1.5 text-xs font-semibold uppercase tracking-wider',
          tone === 'warn' ? 'text-warn' : 'text-muted',
        )}
      >
        {title}
      </h3>
      <div className="rounded-md border border-border bg-elevated/50 px-3 py-2">{children}</div>
    </section>
  )
}

function Chips({ values, tone }: { values: string[]; tone?: 'neutral' | 'accent' }) {
  if (values.length === 0) return <span className="text-faint">-</span>
  return (
    <span className="flex flex-wrap gap-1">
      {values.map((v) => (
        <Badge key={v} tone={tone ?? 'neutral'}>
          {v}
        </Badge>
      ))}
    </span>
  )
}

/** Everything the fingerprinter learned about one service. */
/**
 * Banners are stored with their control characters escaped, so nothing hostile
 * from a scanned host can reach a terminal, a CSV or this page. That keeps the
 * data safe but turns a multi-line HTTP response into one unreadable line, so
 * the escapes are turned back into real whitespace for display only.
 */
function readableBanner(banner: string): string {
  return banner
    .replace(/\\r\\n/g, '\n')
    .replace(/\\r/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '    ')
}

export default function ServiceDetail({ service }: { service: Service }) {
  const s = service
  const title = [s.product, s.version].filter(Boolean).join(' ')

  return (
    <div>
      <Section title="Service">
        <dl>
          <KeyValue label="Endpoint" mono>
            <span className="flex items-center gap-1">
              {s.ip}:{s.port}/{s.protocol}
              <CopyButton value={`${s.ip}:${s.port}`} label="Copy address and port" />
            </span>
          </KeyValue>
          <KeyValue label="State">
            <span className="flex flex-wrap items-center gap-1.5">
              <PortStateBadge state={s.state} />
              {s.reason && <span className="text-xs text-muted">{s.reason}</span>}
              {s.tunnel && <Badge tone="info">{s.tunnel.toUpperCase()}</Badge>}
            </span>
          </KeyValue>
          <KeyValue label="Service">
            {s.name || <span className="text-faint">unknown</span>}
            {title ? <span className="text-muted"> - {title}</span> : null}
            {s.extra_info ? <span className="text-faint"> ({s.extra_info})</span> : null}
          </KeyValue>
          <KeyValue label="Confidence">
            <span className="flex items-center gap-2">
              <span className="tabular">{s.confidence}/100</span>
              {s.method && <Badge tone="neutral">{s.method}</Badge>}
            </span>
          </KeyValue>
          {s.os_type && <KeyValue label="OS hint">{s.os_type}</KeyValue>}
          {(s.cpes ?? []).length > 0 && (
            <KeyValue label="CPE" mono>
              <Chips values={s.cpes ?? []} />
            </KeyValue>
          )}
          <KeyValue label="Seen">
            <RelativeTime value={s.last_seen} /> · first{' '}
            <RelativeTime value={s.first_seen} /> · scan #{s.last_scan_id}
          </KeyValue>
        </dl>
      </Section>

      {s.banner && (
        <Section title="Banner">
          <pre className="log-pane max-h-48 overflow-auto whitespace-pre-wrap break-all text-fg">
            {readableBanner(s.banner)}
          </pre>
        </Section>
      )}

      {s.tls && (
        <Section
          title="TLS certificate"
          tone={s.tls.expired || s.tls.self_signed ? 'warn' : 'default'}
        >
          <dl>
            <KeyValue label="Protocol">
              <span className="flex flex-wrap items-center gap-1.5">
                <Badge tone="accent">{s.tls.version}</Badge>
                <Mono className="text-muted">{s.tls.cipher_suite}</Mono>
                {s.tls.alpn && <Badge tone="neutral">ALPN {s.tls.alpn}</Badge>}
              </span>
            </KeyValue>
            <KeyValue label="Subject CN">{s.tls.subject_cn || '-'}</KeyValue>
            <KeyValue label="Subject" mono>
              {s.tls.subject || '-'}
            </KeyValue>
            <KeyValue label="Issuer" mono>
              {s.tls.issuer || '-'}
            </KeyValue>
            <KeyValue label="Validity">
              <span className="flex flex-wrap items-center gap-1.5">
                <RelativeTime value={s.tls.not_before} prefix="from " />
                <span className="text-faint">→</span>
                <RelativeTime value={s.tls.not_after} prefix="until " />
                {s.tls.expired && <Badge tone="crit">Expired</Badge>}
                {s.tls.self_signed && <Badge tone="warn">Self-signed</Badge>}
              </span>
            </KeyValue>
            <KeyValue label="Key / signature">
              {s.tls.key_algo} {s.tls.key_bits ? `${formatNumber(s.tls.key_bits)} bits` : ''} ·{' '}
              {s.tls.sig_algo}
            </KeyValue>
            <KeyValue label="SANs">
              <Chips values={s.tls.sans ?? []} tone="accent" />
            </KeyValue>
            <KeyValue label="Serial" mono>
              {s.tls.serial || '-'}
            </KeyValue>
            <KeyValue label="SHA-256" mono>
              <span className="flex items-center gap-1 break-all">
                {s.tls.sha256 || '-'}
                {s.tls.sha256 && <CopyButton value={s.tls.sha256} label="Copy fingerprint" />}
              </span>
            </KeyValue>
            {s.tls.jarm && (
              <KeyValue label="JARM" mono>
                {s.tls.jarm}
              </KeyValue>
            )}
          </dl>
        </Section>
      )}

      {s.http && (
        <Section title="HTTP">
          <dl>
            <KeyValue label="URL" mono>
              <span className="flex items-center gap-1 break-all">
                {s.http.url}
                {s.http.url && <CopyButton value={s.http.url} label="Copy URL" />}
              </span>
            </KeyValue>
            <KeyValue label="Status">
              <span className="flex flex-wrap items-center gap-1.5">
                <Badge
                  tone={
                    s.http.status_code >= 500
                      ? 'crit'
                      : s.http.status_code >= 400
                        ? 'warn'
                        : s.http.status_code >= 300
                          ? 'info'
                          : 'ok'
                  }
                >
                  {s.http.status_code}
                </Badge>
                {s.http.location && <Mono className="text-muted">→ {s.http.location}</Mono>}
              </span>
            </KeyValue>
            <KeyValue label="Title">{s.http.title || <span className="text-faint">-</span>}</KeyValue>
            <KeyValue label="Server">
              {s.http.server || '-'}
              {s.http.powered_by ? (
                <span className="text-muted"> · {s.http.powered_by}</span>
              ) : null}
            </KeyValue>
            <KeyValue label="Content">
              {s.http.content_type || '-'}
              {s.http.content_length ? (
                <span className="text-muted"> · {formatBytes(s.http.content_length)}</span>
              ) : null}
            </KeyValue>
            <KeyValue label="Technologies">
              <Chips values={s.http.technologies ?? []} tone="accent" />
            </KeyValue>
            {(s.http.auth_schemes ?? []).length > 0 && (
              <KeyValue label="Auth schemes">
                <Chips values={s.http.auth_schemes ?? []} />
              </KeyValue>
            )}
            {s.http.favicon_mmh3 && (
              <KeyValue label="Favicon mmh3" mono>
                {s.http.favicon_mmh3}
              </KeyValue>
            )}
          </dl>

          {s.http.headers && Object.keys(s.http.headers).length > 0 && (
            <details className="mt-2 border-t border-border pt-2">
              <summary className="cursor-pointer text-xs text-muted hover:text-fg">
                Response headers ({Object.keys(s.http.headers).length})
              </summary>
              <div className="log-pane mt-2 max-h-60 overflow-auto">
                {Object.entries(s.http.headers).map(([k, v]) => (
                  <div key={k} className="flex gap-2 break-all">
                    <span className="text-accent">{k}:</span>
                    <span className="text-fg">{v}</span>
                  </div>
                ))}
              </div>
            </details>
          )}
        </Section>
      )}

      {s.ssh && (
        <Section title="SSH">
          <dl>
            <KeyValue label="Banner" mono>
              {s.ssh.banner || '-'}
            </KeyValue>
            <KeyValue label="Host keys">
              {(s.ssh.host_keys ?? []).length === 0 ? (
                <span className="text-faint">-</span>
              ) : (
                <div className="space-y-1">
                  {(s.ssh.host_keys ?? []).map((k) => (
                    <div key={`${k.type}-${k.sha256}`} className="flex items-center gap-1.5">
                      <Badge tone="accent">{k.type}</Badge>
                      <Mono className="break-all text-muted">{k.sha256}</Mono>
                      <CopyButton value={k.sha256} label="Copy host key fingerprint" />
                    </div>
                  ))}
                </div>
              )}
            </KeyValue>
            <KeyValue label="Key exchange">
              <Chips values={s.ssh.kex_algos ?? []} />
            </KeyValue>
            <KeyValue label="Ciphers">
              <Chips values={s.ssh.ciphers ?? []} />
            </KeyValue>
            <KeyValue label="MACs">
              <Chips values={s.ssh.macs ?? []} />
            </KeyValue>
            {(s.ssh.auth_methods ?? []).length > 0 && (
              <KeyValue label="Auth methods">
                <Chips values={s.ssh.auth_methods ?? []} />
              </KeyValue>
            )}
          </dl>
        </Section>
      )}

      {s.extra && Object.keys(s.extra).length > 0 && (
        <Section title="Protocol facts">
          <dl>
            {Object.entries(s.extra).map(([k, v]) => (
              <KeyValue key={k} label={k} mono>
                {v}
              </KeyValue>
            ))}
          </dl>
        </Section>
      )}
    </div>
  )
}
