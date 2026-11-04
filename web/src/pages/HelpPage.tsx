import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import PageContainer from '@/components/layout/PageContainer'
import { Card, CardHeader, PageHeader } from '@/components/ui/Card'
import { InlineAlert, Skeleton } from '@/components/ui/Feedback'
import { Mono } from '@/components/common'
import { TrunkIcon } from '@/components/icons'
import { TechniqueDetail, TechniqueFlags } from '@/components/TechniqueDetail'
import { techniqueAnchor, useTechniqueGuides, type TechniqueGuide } from '@/lib/techniques'

function TechniqueEntry({ t }: { t: TechniqueGuide }) {
  return (
    <section
      id={techniqueAnchor(t.id)}
      className="scroll-mt-4 border-b border-border px-4 py-4 last:border-b-0 target:bg-accent/5"
    >
      <header className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-fg">
          {t.title} <Mono className="ml-1 font-normal text-faint">{t.id}</Mono>
        </h3>
        <TechniqueFlags t={t} />
      </header>
      <TechniqueDetail t={t} />
    </section>
  )
}

export default function HelpPage() {
  const { list, isLoading } = useTechniqueGuides()
  const { hash } = useLocation()

  useEffect(() => {
    document.title = 'Help · NETY'
    return () => {
      document.title = 'NETY'
    }
  }, [])

  // Arriving from the matrix with #technique-<id>: jump to that entry once the
  // list has rendered.
  useEffect(() => {
    if (!hash || isLoading) return
    const el = document.getElementById(hash.slice(1))
    el?.scrollIntoView({ block: 'start' })
  }, [hash, isLoading])

  const routed = list.filter((t) => !t.l2_active)
  const layer2 = list.filter((t) => t.l2_active)

  return (
    <PageContainer>
      <PageHeader
        title="Segmentation bypass techniques"
        description="A segmentation scan replays every service discovered elsewhere from where you are plugged in, once per technique. This page says what each technique does, why it gets through where a plain connection does not, what a hit proves to the client, and how to reproduce it by hand."
      />

      <Card className="mt-5">
        <CardHeader
          title="Reading a result"
          description="The same three outcomes are used everywhere in the matrix."
        />
        <div className="grid gap-3 px-4 py-3 text-sm sm:grid-cols-3">
          <div>
            <div className="font-medium text-crit">Reachable</div>
            <p className="mt-0.5 text-muted">
              The service answered. If it answered through a technique other than a direct
              connection, the filtering exists but can be walked around.
            </p>
          </div>
          <div>
            <div className="font-medium text-warn">Closed (routed)</div>
            <p className="mt-0.5 text-muted">
              The packet reached the host, which refused it. Nothing blocked the crossing: the
              port simply is not listening.
            </p>
          </div>
          <div>
            <div className="font-medium text-ok">Filtered</div>
            <p className="mt-0.5 text-muted">
              Nothing came back, or an ICMP prohibited answer did. For this technique, the
              boundary held.
            </p>
          </div>
        </div>
      </Card>

      {isLoading ? (
        <Card className="mt-4 p-4">
          <Skeleton className="h-4 w-48" />
        </Card>
      ) : (
        <>
          <Card className="mt-4">
            <CardHeader
              title="Routing-level techniques"
              description="Run from the machine as it is plugged in. They send ordinary traffic and disturb nothing on the switch."
            />
            {routed.map((t) => (
              <TechniqueEntry key={t.id} t={t} />
            ))}
          </Card>

          <Card className="mt-4">
            <CardHeader
              title="Layer-2 techniques"
              description="These act on the switch port itself. They are off by default and have to be opted into per scan."
            />
            <div className="px-4 pt-4">
              <InlineAlert
                tone="warn"
                icon={<TrunkIcon />}
                title="Off by default, and not harmless"
              >
                These techniques change the state of the switch port: they create tagged
                sub-interfaces, negotiate a trunk or emit double-tagged frames. On a badly
                configured switch that can flap the port, trip port security or raise an alert
                in the monitoring. Enable them only with the client informed, during an agreed
                window, by ticking “Allow active L2 techniques” when launching a segmentation
                scan.
              </InlineAlert>
            </div>
            {layer2.map((t) => (
              <TechniqueEntry key={t.id} t={t} />
            ))}
          </Card>
        </>
      )}

      <p className="mt-4 text-xs text-faint">
        The placeholders in the commands above are the ones NETY fills in itself: the interface
        you declared on the network, the target address and port from the service inventory, and
        the VLAN id of the target network.
      </p>
    </PageContainer>
  )
}
