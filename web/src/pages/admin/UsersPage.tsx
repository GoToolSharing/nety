import { useMemo, useState } from 'react'
import {
  useCreateUser,
  useDeleteUser,
  usePatchUser,
  useResetUserPassword,
  useUsers,
} from '@/lib/queries'
import { useAuth } from '@/state/auth'
import PageContainer from '@/components/layout/PageContainer'
import { Card, PageHeader } from '@/components/ui/Card'
import { Button, IconButton } from '@/components/ui/Button'
import { ConfirmDialog, Modal } from '@/components/ui/Modal'
import { Checkbox, SelectField, TextField } from '@/components/ui/Field'
import { EmptyState, ErrorState, InlineAlert, TableSkeleton } from '@/components/ui/Feedback'
import { Badge } from '@/components/ui/Badge'
import { RelativeTime, SearchInput } from '@/components/common'
import { useToast } from '@/components/ui/Toast'
import { LockIcon, PlusIcon, TrashIcon, UsersIcon } from '@/components/icons'
import { ROLES, type Role, type User } from '@/types/api'

const ROLE_BLURB: Record<Role, string> = {
  admin: 'Everything, including user management and mission deletion.',
  operator: 'Runs scans on the missions they belong to.',
  viewer: 'Read-only on the missions they belong to.',
}

function CreateUserModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const create = useCreateUser()
  const toast = useToast()
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState<Role>('operator')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setError(null)
    if (!username.trim()) {
      setError('A username is required.')
      return
    }
    if (password.length < 12) {
      setError('The initial password must be at least 12 characters long.')
      return
    }
    try {
      await create.mutateAsync({
        username: username.trim(),
        display_name: displayName.trim() || username.trim(),
        role,
        password,
      })
      toast.success('User created', 'They will be asked to choose their own password.')
      setUsername('')
      setDisplayName('')
      setPassword('')
      setRole('operator')
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create the user.')
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New user"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={create.isPending} onClick={() => void submit()}>
            Create user
          </Button>
        </>
      }
    >
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        {error && <InlineAlert tone="crit">{error}</InlineAlert>}
        <TextField
          label="Username"
          required
          data-autofocus
          autoComplete="off"
          spellCheck={false}
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <TextField
          label="Display name"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Falls back to the username"
        />
        <SelectField
          label="Role"
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
          hint={ROLE_BLURB[role]}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </SelectField>
        <TextField
          label="Initial password"
          type="password"
          required
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="At least 12 characters. The user is forced to change it on first sign-in."
        />
        <button type="submit" className="hidden" aria-hidden="true" />
      </form>
    </Modal>
  )
}

function ResetPasswordModal({
  user,
  onClose,
}: {
  user: User | null
  onClose: () => void
}) {
  const reset = useResetUserPassword()
  const toast = useToast()
  const [password, setPassword] = useState('')
  const [mustChange, setMustChange] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    if (!user) return
    setError(null)
    if (password.length < 12) {
      setError('The password must be at least 12 characters long.')
      return
    }
    try {
      await reset.mutateAsync({ id: user.id, password, mustChange })
      toast.success('Password reset', `${user.username} can sign in with the new password.`)
      setPassword('')
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reset the password.')
    }
  }

  return (
    <Modal
      open={!!user}
      onClose={onClose}
      size="sm"
      title={`Reset the password of ${user?.username ?? ''}`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={reset.isPending} onClick={() => void submit()}>
            Reset password
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {error && <InlineAlert tone="crit">{error}</InlineAlert>}
        <TextField
          label="New password"
          type="password"
          data-autofocus
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint="At least 12 characters. Hand it over out of band."
        />
        <Checkbox
          label="Force a password change on next sign-in"
          checked={mustChange}
          onChange={(e) => setMustChange(e.target.checked)}
        />
      </div>
    </Modal>
  )
}

export default function UsersPage() {
  const { user: me } = useAuth()
  const users = useUsers()
  const patch = usePatchUser()
  const remove = useDeleteUser()
  const toast = useToast()
  const [query, setQuery] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [resetting, setResetting] = useState<User | null>(null)
  const [deleting, setDeleting] = useState<User | null>(null)

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (users.data ?? [])
      .filter(
        (u) =>
          !q ||
          u.username.toLowerCase().includes(q) ||
          u.display_name.toLowerCase().includes(q) ||
          u.role.includes(q),
      )
      .sort((a, b) => a.username.localeCompare(b.username))
  }, [users.data, query])

  const update = async (u: User, body: { role?: Role; disabled?: boolean }) => {
    try {
      await patch.mutateAsync({ id: u.id, body })
      toast.success('User updated')
    } catch (err) {
      toast.error('Could not update the user', err)
    }
  }

  return (
    <PageContainer>
      <PageHeader
        title="Users"
        description="Accounts that can sign in to this NETY instance."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => setCreateOpen(true)}>
            New user
          </Button>
        }
      />

      <div className="mt-5">
        <SearchInput
          value={query}
          onChange={setQuery}
          placeholder="Username, name, role…"
          className="w-full max-w-sm"
        />
      </div>

      <Card className="mt-4">
        {users.isLoading ? (
          <TableSkeleton rows={6} columns={6} />
        ) : users.isError ? (
          <ErrorState
            title="Could not load the users"
            error={users.error}
            retry={() => void users.refetch()}
          />
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<UsersIcon width={20} height={20} />}
            title="No user matches that filter"
            description="Clear the search to see every account."
          />
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Display name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last sign-in</th>
                  <th>Created</th>
                  <th className="w-px">Actions</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((u) => {
                  const isMe = me?.id === u.id
                  return (
                    <tr key={u.id}>
                      <td className="font-medium">
                        {u.username}
                        {isMe && (
                          <Badge tone="accent" className="ml-1.5">
                            you
                          </Badge>
                        )}
                      </td>
                      <td className="text-muted">{u.display_name || '—'}</td>
                      <td>
                        <select
                          aria-label={`Role of ${u.username}`}
                          value={u.role}
                          disabled={isMe}
                          onChange={(e) => void update(u, { role: e.target.value as Role })}
                          className="input-base h-7 w-auto py-0 text-xs"
                          title={isMe ? 'You cannot change your own role' : ROLE_BLURB[u.role]}
                        >
                          {ROLES.map((r) => (
                            <option key={r} value={r}>
                              {r}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        <span className="flex flex-wrap items-center gap-1.5">
                          {u.disabled ? (
                            <Badge tone="crit">Disabled</Badge>
                          ) : (
                            <Badge tone="ok">Active</Badge>
                          )}
                          {u.must_change_password && (
                            <Badge tone="warn" title="Must choose a new password on next sign-in">
                              must change pw
                            </Badge>
                          )}
                        </span>
                      </td>
                      <td className="text-muted">
                        {u.last_login_at ? (
                          <RelativeTime value={u.last_login_at} />
                        ) : (
                          <span className="text-faint">never</span>
                        )}
                      </td>
                      <td className="text-muted">
                        <RelativeTime value={u.created_at} />
                      </td>
                      <td>
                        <div className="flex items-center justify-end gap-1.5">
                          <Button size="sm" onClick={() => setResetting(u)} icon={<LockIcon width={13} height={13} />}>
                            Reset
                          </Button>
                          <Button
                            size="sm"
                            disabled={isMe}
                            onClick={() => void update(u, { disabled: !u.disabled })}
                            title={isMe ? 'You cannot disable your own account' : undefined}
                          >
                            {u.disabled ? 'Enable' : 'Disable'}
                          </Button>
                          <IconButton
                            label={`Delete ${u.username}`}
                            disabled={isMe}
                            onClick={() => setDeleting(u)}
                          >
                            <TrashIcon />
                          </IconButton>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <CreateUserModal open={createOpen} onClose={() => setCreateOpen(false)} />
      <ResetPasswordModal user={resetting} onClose={() => setResetting(null)} />

      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        destructive
        title={`Delete ${deleting?.username ?? 'user'}?`}
        confirmLabel="Delete user"
        busy={remove.isPending}
        body="The account and its sessions are removed. Missions and results they created stay in place."
        onConfirm={async () => {
          if (!deleting) return
          try {
            await remove.mutateAsync(deleting.id)
            toast.success('User deleted')
            setDeleting(null)
          } catch (err) {
            toast.error('Could not delete the user', err)
          }
        }}
      />
    </PageContainer>
  )
}
