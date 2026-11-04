import PageContainer from '@/components/layout/PageContainer'
import { PageHeader } from '@/components/ui/Card'
import MissionTeam from '@/components/MissionTeam'
import { useMissionId } from '@/lib/hooks'

/**
 * A mission is private to its members. Creating an account grants access to
 * nothing, which is the kind of thing you only discover by being confused by
 * it, so giving access has its own entry in the sidebar rather than hiding at
 * the bottom of the overview.
 */
export default function TeamPage() {
  const missionId = useMissionId()
  return (
    <PageContainer>
      <PageHeader
        title="Team"
        description="Who can open this mission. An operator who is not a member does not see it in their list and cannot reach it at all. Administrators always have access."
      />
      <div className="mt-5 max-w-3xl">
        <MissionTeam missionId={missionId} />
      </div>
    </PageContainer>
  )
}
