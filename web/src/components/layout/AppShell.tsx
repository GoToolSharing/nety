import { useState } from 'react'
import { Link, Outlet } from 'react-router-dom'
import { useAuth } from '@/state/auth'
import { useTheme } from '@/state/theme'
import { useServerStatus } from '@/lib/queries'
import { Button, IconButton } from '@/components/ui/Button'
import { Modal } from '@/components/ui/Modal'
import { TextField } from '@/components/ui/Field'
import { InlineAlert } from '@/components/ui/Feedback'
import { useToast } from '@/components/ui/Toast'
import { Badge } from '@/components/ui/Badge'
import { AlertIcon, LockIcon, LogoutIcon, MoonIcon, SunIcon } from '@/components/icons'
import { formatDuration } from '@/lib/format'

function Logo() {
  return (
    <Link to="/missions" className="flex items-center gap-2 rounded" aria-label="NETY home">
      <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
        <rect width="32" height="32" rx="7" fill="rgb(var(--c-accent))" opacity="0.14" />
        <path
          d="M8 23V9l16 14V9"
          stroke="rgb(var(--c-accent))"
          strokeWidth="3"
          fill="none"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <span className="text-[15px] font-semibold tracking-tight">NETY</span>
    </Link>
  )
}

function ChangePasswordModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { changePassword } = useAuth()
  const toast = useToast()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setError(null)
    if (next.length < 12) {
      setError('Choose a new password of at least 12 characters.')
      return
    }
    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      await changePassword(current, next)
      toast.success('Password changed')
      setCurrent('')
      setNext('')
      setConfirm('')
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the password.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Change your password"
      size="sm"
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} loading={busy}>
            Change password
          </Button>
        </>
      }
    >
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        {error && <InlineAlert tone="crit">{error}</InlineAlert>}
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          data-autofocus
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          hint="At least 12 characters."
        />
        <TextField
          label="Confirm new password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <button type="submit" className="hidden" aria-hidden="true" />
      </form>
    </Modal>
  )
}

export default function AppShell() {
  const { user, logout } = useAuth()
  const { theme, toggle } = useTheme()
  const status = useServerStatus()
  const [pwOpen, setPwOpen] = useState(false)

  const privileged = status.data?.raw_sockets

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex h-12 shrink-0 items-center gap-4 border-b border-border bg-surface px-4">
        <Logo />

        <div className="ml-auto flex items-center gap-2">
          {privileged === false && (
            <Badge
              tone="warn"
              title="The server is running without CAP_NET_RAW / CAP_NET_ADMIN: SYN scanning, ARP discovery and L2 techniques fall back to connect mode or are unavailable."
            >
              <AlertIcon width={12} height={12} />
              Unprivileged
            </Badge>
          )}
          {status.data?.version && (
            <span
              className="hidden text-xs text-faint lg:inline"
              title={
                status.data.uptime_seconds
                  ? `Up for ${formatDuration(status.data.uptime_seconds)}`
                  : undefined
              }
            >
              v{status.data.version}
            </span>
          )}

          <IconButton
            label={theme === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme'}
            onClick={toggle}
          >
            {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          </IconButton>

          <div className="hidden items-center gap-2 border-l border-border pl-3 sm:flex">
            <div className="text-right leading-tight">
              <div className="text-xs font-medium text-fg">
                {user?.display_name || user?.username}
              </div>
              <div className="text-[11px] capitalize text-faint">{user?.role}</div>
            </div>
          </div>

          <IconButton label="Change your password" onClick={() => setPwOpen(true)}>
            <LockIcon />
          </IconButton>
          <IconButton label="Sign out" onClick={() => void logout()}>
            <LogoutIcon />
          </IconButton>
        </div>
      </header>

      <main className="min-h-0 flex-1 overflow-hidden">
        <Outlet />
      </main>

      <ChangePasswordModal open={pwOpen} onClose={() => setPwOpen(false)} />
    </div>
  )
}
