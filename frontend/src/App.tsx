import { useEffect, useRef, useState } from 'react'
import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { useIsFetching, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Boxes, LogOut, Moon, Radar, Server, Shield, ShieldCheck, Siren, Sun } from 'lucide-react'
import { api, getToken, setToken, UnauthorizedError, type Summary } from './api'
import { AlertControls, AlertProvider, EmergencyBanner, useAlertSettings } from './components/Alerts'
import { threatLevel } from './components/ui'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Incidents from './pages/Incidents'
import IncidentDetail from './pages/IncidentDetail'
import Events from './pages/Events'
import Hosts from './pages/Hosts'
import ResponsePage from './pages/Response'
import Services from './pages/Services'
import ServiceDetail from './pages/ServiceDetail'

const nav = [
  { to: '/', label: 'Situação', Icon: Radar, end: true },
  { to: '/incidents', label: 'Incidentes', Icon: Siren },
  { to: '/services', label: 'Serviços', Icon: Boxes },
  { to: '/response', label: 'Resposta', Icon: ShieldCheck },
  { to: '/events', label: 'Eventos', Icon: Activity },
  { to: '/hosts', label: 'Ativos', Icon: Server },
]

export default function App() {
  const [authed, setAuthed] = useState(() => !!getToken())
  const queryClient = useQueryClient()

  // Any 401 from the API sends the user back to the login screen.
  useEffect(() => {
    return queryClient.getQueryCache().subscribe((e) => {
      if (e.type === 'updated' && e.query.state.error instanceof UnauthorizedError) setAuthed(false)
    })
  }, [queryClient])

  if (!authed) return <Login onLogin={() => setAuthed(true)} />

  const logout = () => {
    setToken(null)
    queryClient.clear()
    setAuthed(false)
  }

  return (
    <AlertProvider>
      <div className="min-h-screen">
        <header className="sticky top-0 z-30 border-b border-line bg-page">
          <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2">
            <div className="flex items-center gap-2">
              <Shield size={20} className="text-hud" aria-hidden />
              <div className="leading-tight">
                <p className="font-mono text-sm font-bold tracking-widest">VPS-SOC</p>
                <p className="hud-label text-[9px] text-muted">Centro de operações de segurança</p>
              </div>
            </div>
            <ThreatChip />
            <div className="ml-auto flex items-center gap-3">
              <LinkStatus />
              <Clocks />
              <AlertControls />
              <ThemeToggle />
              <button onClick={logout} className="rounded-sm border border-line p-1.5 text-ink2 hover:bg-raised" title="Sair" aria-label="Sair">
                <LogOut size={14} aria-hidden />
              </button>
            </div>
          </div>
          <nav className="mx-auto flex max-w-[1600px] gap-1 overflow-x-auto px-4">
            {nav.map(({ to, label, Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  `hud-label flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 ${
                    isActive ? 'border-hud font-semibold text-ink' : 'border-transparent text-muted hover:text-ink2'
                  }`
                }
              >
                <Icon size={14} aria-hidden />
                {label}
              </NavLink>
            ))}
          </nav>
        </header>
        <EmergencyBanner />
        <main className="mx-auto max-w-[1600px] px-4 py-4">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/events" element={<Events />} />
            <Route path="/hosts" element={<Hosts />} />
            <Route path="/response" element={<ResponsePage />} />
            <Route path="/services" element={<Services />} />
            <Route path="/services/:hostId/:name" element={<ServiceDetail />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </AlertProvider>
  )
}

function ThreatChip() {
  const q = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary'), refetchInterval: 10_000 })
  if (!q.data) return null
  const t = threatLevel(q.data.openIncidents)
  return (
    <div className={`flex items-center gap-2 border px-2.5 py-1 ${t.level <= 1 ? 'alarm-pulse' : ''}`} style={{ borderColor: t.color }} title={t.hint}>
      <t.Icon size={14} style={{ color: t.color }} aria-hidden />
      <span className="hud-label text-muted">Ameaça</span>
      <span className="hud-label font-bold" style={{ color: t.color }}>{t.level} · {t.label}</span>
    </div>
  )
}

/** Green while the API answers; red when the last refresh failed. */
function LinkStatus() {
  const fetching = useIsFetching()
  const q = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary'), refetchInterval: 10_000 })
  const down = q.isError
  const { play } = useAlertSettings()
  const wasDown = useRef(false)
  useEffect(() => {
    if (down && !wasDown.current) play('linkLost') // the backend stopped answering
    wasDown.current = down
  }, [down, play])
  return (
    <span className="hud-label hidden items-center gap-1.5 text-muted md:flex" title={down ? 'Sem resposta do backend' : 'Conectado ao backend'}>
      <span className={`inline-block h-2 w-2 rounded-full ${down ? '' : 'live-dot'}`} style={{ background: down ? 'var(--critical)' : 'var(--good)' }} aria-hidden />
      {down ? 'Sem link' : fetching ? 'Sincronizando' : 'Ao vivo'}
    </span>
  )
}

/** Dark (operations wall) by default; light for daytime/printing. Remembered per browser. */
function ThemeToggle() {
  const [light, setLight] = useState(() => document.documentElement.dataset.theme === 'light')
  const toggle = () => {
    const next = !light
    setLight(next)
    if (next) document.documentElement.dataset.theme = 'light'
    else delete document.documentElement.dataset.theme
    try {
      localStorage.setItem('vps-soc-theme', next ? 'light' : 'dark')
    } catch {
      /* storage unavailable: the choice lasts for this tab only */
    }
  }
  return (
    <button onClick={toggle} className="rounded-sm border border-line p-1.5 text-ink2 hover:bg-raised"
      title={light ? 'Mudar para tema escuro' : 'Mudar para tema claro'} aria-label={light ? 'Mudar para tema escuro' : 'Mudar para tema claro'}>
      {light ? <Moon size={14} aria-hidden /> : <Sun size={14} aria-hidden />}
    </button>
  )
}

function Clocks() {
  const [now, setNow] = useState(() => new Date())
  useEffect(() => {
    const t = window.setInterval(() => setNow(new Date()), 1_000)
    return () => window.clearInterval(t)
  }, [])
  const local = now.toLocaleTimeString('pt-BR', { hour12: false })
  const utc = now.toISOString().slice(11, 19)
  return (
    <div className="hidden font-mono text-xs leading-tight sm:block">
      <p className="tnum text-ink">{local} <span className="text-muted">LOCAL</span></p>
      <p className="tnum text-muted">{utc} UTC</p>
    </div>
  )
}
