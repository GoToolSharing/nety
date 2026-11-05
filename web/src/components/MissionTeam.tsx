import { useEffect, useState } from 'react'
import { useAuth } from '@/state/auth'
import { useMissionMembers, useSetMissionMembers, useUsers } from '@/lib/queries'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Modal } from '@/components/ui/Modal'
import { useToast } from '@/components/ui/Toast'
import { UsersIcon } from '@/components/icons'
import { Skeleton } from '@/components/ui/Feedback'
import { cn } from '@/lib/cn'

/**
 * Who can see this mission.
 *
 * A mission is private to its members: an operator who is not one of them does
 * not see it in the list and cannot open it. Creating an account therefore does
 * not grant access to anything, which is easy to miss, so the team is shown on
 * the overview with the way to change it right there.
 */
export default function MissionTeam({ missionId }: { missionId: number }) {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const members = useMissionMembers(missionId)
  // Listing every account is admin-only, so the roster comes from the members
  // endpoint: an operator must see their own team.
  const users = useUsers(isAdmin)
  const [editing, setEditing] = useState(false)

  const roster = members.data?.members ?? []
  const outsiders = isAdmin ? (users.data ?? []).length - roster.length : 0

  return (
    <Card>
      <CardHeader
        title="Team"
        description="Who can open this mission. Everyone else cannot see it at all."
        actions={
          isAdmin ? (
            <Button size="sm" variant="secondary" onClick={() => setEditing(true)}>
              Manage
            </Button>
          ) : undefined
        }
      />
      <div className="px-4 py-3">
        {members.isLoading ? (
          <Skeleton className="h-5 w-48" />
        ) : roster.length === 0 ? (
          <p className="text-xs text-muted">
            Nobody is assigned yet.
            {isAdmin ? ' Use Manage to give your team access.' : ''}
          </p>
        ) : (
          <ul className="flex flex-wrap gap-1.5">
            {roster.map((u) => (
              <li
                key={u.id}
                className="inline-flex items-center gap-1.5 rounded border border-border bg-elevated px-2 py-1 text-xs"
              >
                <UsersIcon width={12} height={12} className="text-faint" />
                <span className="font-medium text-fg">
                  {u.display_name || u.username}
                </span>
                <Badge tone={u.role === 'admin' ? 'accent' : 'neutral'}>{u.role}</Badge>
              </li>
            ))}
          </ul>
        )}
        {isAdmin && outsiders > 0 && roster.length > 0 && (
          <p className="mt-2 text-[11px] text-faint">
            {outsiders} other account{outsiders > 1 ? 's' : ''} cannot see this mission.
          </p>
        )}
      </div>

      {editing && <TeamModal missionId={missionId} onClose={() => setEditing(false)} />}
    </Card>
  )
}

function TeamModal({ missionId, onClose }: { missionId: number; onClose: () => void }) {
  const users = useUsers(true)
  const members = useMissionMembers(missionId)
  const save = useSetMissionMembers(missionId)
  const toast = useToast()
  const [selected, setSelected] = useState<Set<number>>(new Set())

  useEffect(() => {
    if (members.data) setSelected(new Set(members.data.ids))
  }, [members.data])

  const toggle = (id: number) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const submit = async () => {
    try {
      await save.mutateAsync([...selected])
      toast.success('Team updated')
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not update the team')
    }
  }

  return (
    <Modal open title="Who can open this mission" onClose={onClose} size="md">
      <p className="mb-3 text-xs text-muted">
        Members see the mission in their list and can open it. An operator who is not a
        member cannot reach it at all. Administrators always have access, whether or not
        they are ticked here.
      </p>

      {users.isLoading ? (
        <Skeleton className="h-32 w-full" />
      ) : (
        <ul className="max-h-72 overflow-y-auto rounded-md border border-border">
          {(users.data ?? []).map((u) => {
            const on = selected.has(u.id)
            return (
              <li key={u.id} className="border-b border-border/60 last:border-b-0">
                <label
                  className={cn(
                    'flex cursor-pointer items-center gap-3 px-3 py-2 text-sm hover:bg-elevated',
                    on && 'bg-elevated',
                  )}
                >
                  <input
                    type="checkbox"
                    checked={on}
                    onChange={() => toggle(u.id)}
                    className="h-3.5 w-3.5 accent-[rgb(var(--c-accent))]"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium text-fg">
                      {u.display_name || u.username}
                    </span>
                    <span className="block text-[11px] text-muted">{u.username}</span>
                  </span>
                  <Badge tone={u.role === 'admin' ? 'accent' : 'neutral'}>{u.role}</Badge>
                  {u.disabled && <Badge tone="warn">disabled</Badge>}
                </label>
              </li>
            )
          })}
        </ul>
      )}

      <div className="mt-4 flex items-center justify-end gap-2">
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="primary" loading={save.isPending} onClick={() => void submit()}>
          Save
        </Button>
      </div>
    </Modal>
  )
}
