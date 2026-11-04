import { useState } from 'react'
import { useAuth } from '@/state/auth'
import { Button } from '@/components/ui/Button'
import { TextField } from '@/components/ui/Field'
import { InlineAlert } from '@/components/ui/Feedback'
import { useToast } from '@/components/ui/Toast'

/**
 * Shown instead of the application when the account carries
 * `must_change_password`. There is deliberately no way around it except
 * signing out.
 */
export default function ForcePasswordChange() {
  const { user, changePassword, logout } = useAuth()
  const toast = useToast()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (next.length < 12) {
      setError('The new password must be at least 12 characters long.')
      return
    }
    if (next === current) {
      setError('The new password must be different from the current one.')
      return
    }
    if (next !== confirm) {
      setError('The two new passwords do not match.')
      return
    }
    setBusy(true)
    try {
      await changePassword(current, next)
      toast.success('Password updated', 'You can now use NETY.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the password.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center overflow-auto bg-bg px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-5 text-center">
          <h1 className="text-lg font-semibold">Choose a new password</h1>
          <p className="mt-1 text-sm text-muted">
            {user?.display_name || user?.username}, this account still uses the password it was
            created with. Set your own before continuing.
          </p>
        </div>

        <form onSubmit={submit} className="card space-y-4 p-5" noValidate>
          {error && <InlineAlert tone="crit">{error}</InlineAlert>}
          <TextField
            label="Current password"
            type="password"
            autoComplete="current-password"
            autoFocus
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
          <TextField
            label="New password"
            type="password"
            autoComplete="new-password"
            value={next}
            onChange={(e) => setNext(e.target.value)}
            hint="At least 12 characters. A passphrase works well."
          />
          <TextField
            label="Confirm new password"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
          <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy}>
            Set password and continue
          </Button>
        </form>

        <div className="mt-3 text-center">
          <button
            type="button"
            onClick={() => void logout()}
            className="rounded text-xs text-muted underline-offset-2 hover:text-fg hover:underline"
          >
            Sign out instead
          </button>
        </div>
      </div>
    </div>
  )
}
