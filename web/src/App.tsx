import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useAuth } from '@/state/auth'
import { Spinner } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/Feedback'
import { LinkButton } from '@/components/ui/Button'
import LoginPage from '@/pages/LoginPage'
import ForcePasswordChange from '@/pages/ForcePasswordChange'
import MissionsPage from '@/pages/MissionsPage'
import MissionLayout, { SidebarShell } from '@/pages/mission/MissionLayout'
import OverviewPage from '@/pages/mission/OverviewPage'
import NetworksPage from '@/pages/mission/NetworksPage'
import ScansPage from '@/pages/mission/ScansPage'
import ScanLauncherPage from '@/pages/mission/ScanLauncherPage'
import ScanDetailPage from '@/pages/mission/ScanDetailPage'
import HostsPage from '@/pages/mission/HostsPage'
import ServicesPage from '@/pages/mission/ServicesPage'
import FindingsPage from '@/pages/mission/FindingsPage'
import AssetsPage from '@/pages/mission/AssetsPage'
import MatrixPage from '@/pages/mission/MatrixPage'
import ExportsPage from '@/pages/mission/ExportsPage'
import TeamPage from '@/pages/mission/TeamPage'
import HelpPage from '@/pages/HelpPage'
import UsersPage from '@/pages/admin/UsersPage'
import AuditPage from '@/pages/admin/AuditPage'
import AppShell from '@/components/layout/AppShell'

function FullPageLoader() {
  return (
    <div className="flex h-full items-center justify-center text-muted">
      <Spinner className="h-5 w-5" />
      <span className="sr-only">Loading NETY…</span>
    </div>
  )
}

function RequireAuth({ children }: { children: JSX.Element }) {
  const { user, loading } = useAuth()
  const location = useLocation()

  if (loading) return <FullPageLoader />
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  // A forced password change blocks everything else, by design.
  if (user.must_change_password) return <ForcePasswordChange />
  return children
}

function RequireAdmin({ children }: { children: JSX.Element }) {
  const { isAdmin } = useAuth()
  if (!isAdmin) {
    return (
      <EmptyState
        title="Administrators only"
        description="This section is restricted to accounts with the admin role."
        action={
          <LinkButton to="/missions" variant="secondary">
            Back to missions
          </LinkButton>
        }
      />
    )
  }
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/missions" replace />} />
        <Route path="missions" element={<MissionsPage />} />
        <Route path="missions/:missionId" element={<MissionLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="networks" element={<NetworksPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/new" element={<ScanLauncherPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="hosts" element={<HostsPage />} />
          <Route path="services" element={<ServicesPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="matrix" element={<MatrixPage />} />
          <Route path="exports" element={<ExportsPage />} />
          <Route path="team" element={<TeamPage />} />
        </Route>
        {/* Outside a mission, but kept inside the same two-pane layout so the
            sidebar never disappears from under the operator. */}
        <Route element={<SidebarShell />}>
          <Route path="help" element={<HelpPage />} />
          <Route
            path="admin/users"
            element={
              <RequireAdmin>
                <UsersPage />
              </RequireAdmin>
            }
          />
          <Route
            path="admin/audit"
            element={
              <RequireAdmin>
                <AuditPage />
              </RequireAdmin>
            }
          />
        </Route>
        <Route
          path="*"
          element={
            <EmptyState
              title="Page not found"
              description="That route does not exist in NETY."
              action={
                <LinkButton to="/missions" variant="primary">
                  Back to missions
                </LinkButton>
              }
            />
          }
        />
      </Route>
    </Routes>
  )
}
