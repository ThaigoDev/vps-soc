import { Suspense, lazy, useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { getToken, setToken, UnauthorizedError } from './api'
import { AlertProvider, EmergencyBanner } from './components/Alerts'
import { Shell } from './components/Layout'
import { useLiveUpdates } from './live'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Incidents from './pages/Incidents'
import IncidentDetail from './pages/IncidentDetail'
import Events from './pages/Events'
import Hosts from './pages/Hosts'
import ResponsePage from './pages/Response'
import Services from './pages/Services'
import ServiceDetail from './pages/ServiceDetail'
import Reports from './pages/Reports'
import Help from './pages/Help'
import ClientReport from './pages/ClientReport'

// Heavy (three.js) and public: loaded only when opened, no login needed.
const Presentation = lazy(() => import('./pages/Presentation'))

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken())
  const queryClient = useQueryClient()
  const { pathname } = useLocation()
  useLiveUpdates(authed && pathname !== '/apresentacao')

  // Any 401 from the API sends the user back to the login screen.
  useEffect(() => {
    return queryClient.getQueryCache().subscribe((e) => {
      if (e.type === 'updated' && e.query.state.error instanceof UnauthorizedError) setAuthed(false)
    })
  }, [queryClient])

  if (pathname === '/apresentacao') {
    return (
      <Suspense fallback={<div className="flex min-h-screen items-center justify-center text-sm text-muted">Carregando apresentação…</div>}>
        <Presentation />
      </Suspense>
    )
  }

  if (!authed) return <Login onLogin={() => setAuthed(true)} />

  const logout = () => {
    setToken(null)
    queryClient.clear()
    setAuthed(false)
  }

  return (
    <AlertProvider>
      <Shell onLogout={logout}>
        <EmergencyBanner />
        <main className="w-full max-w-[1400px] px-4 py-6 lg:px-8 print:max-w-none print:p-0">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/services" element={<Services />} />
            <Route path="/services/:hostId/:name" element={<ServiceDetail />} />
            <Route path="/response" element={<ResponsePage />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/client-report" element={<ClientReport />} />
            <Route path="/help" element={<Help />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </Shell>
    </AlertProvider>
  )
}
