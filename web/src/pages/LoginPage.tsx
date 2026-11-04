import { useEffect, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ApiError } from '@/lib/api'
import { useAuth } from '@/state/auth'
import { useTheme } from '@/state/theme'
import { useServerStatus } from '@/lib/queries'
import { Button, IconButton, Spinner } from '@/components/ui/Button'
import { TextField } from '@/components/ui/Field'
import { InlineAlert } from '@/components/ui/Feedback'
import { MoonIcon, NetyMark, SunIcon } from '@/components/icons'

export default function LoginPage() {
  const { user, loading, login } = useAuth()
  const { theme, toggle } = useTheme()
  const navigate = useNavigate()
  const location = useLocation()
  const status = useServerStatus()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    document.title = 'Sign in · NETY'
  }, [])

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner className="h-5 w-5 text-muted" />
      </div>
    )
  }
  if (user) {
    const from = (location.state as { from?: string } | null)?.from
    return <Navigate to={from && from !== '/login' ? from : '/missions'} replace />
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!username || !password) {
      setError('Enter your username and password.')
      return
    }
    setBusy(true)
    try {
      await login(username, password)
      const from = (location.state as { from?: string } | null)?.from
      navigate(from && from !== '/login' ? from : '/missions', { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401 || err.code === 'unauthorized') {
          setError('Invalid username or password.')
        } else if (err.status === 403 || err.code === 'forbidden') {
          setError('This account is disabled. Ask an administrator to re-enable it.')
        } else if (err.status === 429 || err.code === 'busy') {
          setError('Too many attempts. Wait a moment and try again.')
        } else if (err.status === 0) {
          setError('Cannot reach the NETY server. Is it running on this host?')
        } else {
          setError(err.message)
        }
      } else {
        setError('Sign-in failed.')
      }
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="relative flex h-full items-center justify-center overflow-auto bg-bg px-4 py-10">
      {/* Decorative grid, purely presentational. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-[0.35]"
        style={{
          backgroundImage:
            'linear-gradient(rgb(var(--c-border)) 1px, transparent 1px), linear-gradient(90deg, rgb(var(--c-border)) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
          maskImage: 'radial-gradient(ellipse at center, black 10%, transparent 70%)',
          WebkitMaskImage: 'radial-gradient(ellipse at center, black 10%, transparent 70%)',
        }}
      />

      <div className="absolute right-4 top-4">
        <IconButton
          label={theme === 'dark' ? 'Switch to the light theme' : 'Switch to the dark theme'}
          onClick={toggle}
        >
          {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
        </IconButton>
      </div>

      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <NetyMark size={52} />
          <div>
            <h1 className="text-xl font-semibold tracking-tight">NETY</h1>
            <p className="mt-1 text-sm text-muted">Internal network audit platform</p>
          </div>
        </div>

        <form onSubmit={submit} className="card space-y-4 p-5" noValidate>
          {error && (
            <InlineAlert tone="crit" className="animate-fade-in">
              {error}
            </InlineAlert>
          )}

          <TextField
            label="Username"
            name="username"
            autoComplete="username"
            autoFocus
            spellCheck={false}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            error={error && !username ? 'Required' : null}
          />
          <TextField
            label="Password"
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            error={error && !password ? 'Required' : null}
          />

          <Button type="submit" variant="primary" size="lg" className="w-full" loading={busy}>
            Sign in
          </Button>
        </form>

        <p className="mt-4 text-center text-[11px] text-faint">
          {status.data?.version ? `NETY ${status.data.version}` : 'NETY'} · sessions are
          cookie-based and bound to this host
        </p>
      </div>
    </div>
  )
}
