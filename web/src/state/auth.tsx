import { createContext, useContext, useEffect, useMemo, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ApiError, UNAUTHORIZED_EVENT, api } from '@/lib/api'
import { qk } from '@/lib/queries'
import type { SessionInfo, User } from '@/types/api'

interface AuthContextValue {
  user: User | null
  loading: boolean
  /** True once the first /auth/me call has settled. */
  ready: boolean
  isAdmin: boolean
  canWrite: boolean
  login: (username: string, password: string) => Promise<SessionInfo>
  logout: () => Promise<void>
  changePassword: (current: string, next: string) => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()

  const session = useQuery({
    queryKey: qk.session,
    queryFn: async (): Promise<SessionInfo | null> => {
      try {
        return await api.me()
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) return null
        throw err
      }
    },
    retry: false,
    staleTime: 60_000,
  })

  // Any 401 from anywhere drops the session, which bounces to /login.
  useEffect(() => {
    const onUnauthorized = () => {
      qc.setQueryData(qk.session, null)
    }
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized)
  }, [qc])

  const loginMutation = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      api.login(username, password),
    onSuccess: (data) => {
      qc.setQueryData(qk.session, data)
    },
  })

  const logoutMutation = useMutation({
    mutationFn: () => api.logout(),
    onSettled: () => {
      qc.setQueryData(qk.session, null)
      qc.clear()
    },
  })

  const user = session.data?.user ?? null

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading: session.isLoading,
      ready: !session.isLoading,
      isAdmin: user?.role === 'admin',
      canWrite: user?.role === 'admin' || user?.role === 'operator',
      login: (username, password) => loginMutation.mutateAsync({ username, password }),
      logout: async () => {
        await logoutMutation.mutateAsync()
      },
      changePassword: async (current, next) => {
        await api.changePassword(current, next)
        await qc.invalidateQueries({ queryKey: qk.session })
      },
    }),
    [user, session.isLoading, loginMutation, logoutMutation, qc],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside an AuthProvider')
  return ctx
}
