import { useEffect, useRef, useState, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useIsFetching, useQuery } from '@tanstack/react-query'
import {
  Activity, BarChart3, Boxes, FileText, Presentation, HelpCircle, LayoutDashboard, LogOut, Menu, Moon, Server, Shield, ShieldCheck, Siren, Sun, X,
} from 'lucide-react'
import { api, type Host, type ServiceView, type Summary } from '../api'
import { AlertMenu, useAlertSettings } from './Alerts'
import { useLiveState } from '../live'
import { useKpis } from './SocMetrics'
import { threatLevel } from './ui'

type Badge = { n: number; tone: 'critical' | 'warning' } | null

interface NavItem {
  to: string
  label: string
  Icon: typeof Shield
  end?: boolean
  badge?: () => Badge
}

/** Shared queries (same keys as the pages, so React Query sends one request each). */
function useNavCounts() {
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary'), refetchInterval: 10_000 })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: 10_000 })
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services'), refetchInterval: 10_000 })
  const kpis = useKpis(30)
  return { summary, hosts, services, kpis }
}

export function Shell({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  useEffect(() => setOpen(false), [location.pathname])

  return (
    <div className="min-h-screen lg:flex">
      {/* Desktop sidebar */}
      <aside className="no-print sticky top-0 hidden h-screen w-60 shrink-0 border-r border-line bg-surface lg:flex lg:flex-col">
        <Sidebar onLogout={onLogout} />
      </aside>

      {/* Mobile drawer */}
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <button className="absolute inset-0 bg-black/50" onClick={() => setOpen(false)} aria-label="Fechar menu" />
          <aside className="relative flex h-full w-72 max-w-[85vw] flex-col border-r border-line bg-surface">
            <button onClick={() => setOpen(false)} className="absolute right-3 top-3 rounded-md p-1.5 text-muted hover:bg-raised" aria-label="Fechar menu">
              <X size={18} aria-hidden />
            </button>
            <Sidebar onLogout={onLogout} />
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="no-print sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-page/90 px-4 py-2.5 backdrop-blur">
          <button onClick={() => setOpen(true)} className="rounded-md p-1.5 text-ink2 hover:bg-raised lg:hidden" aria-label="Abrir menu">
            <Menu size={20} aria-hidden />
          </button>
          <span className="flex items-center gap-2 font-semibold lg:hidden">
            <Shield size={18} className="text-hud" aria-hidden /> VPS-SOC
          </span>
          <div className="ml-auto flex items-center gap-2">
            <LinkStatus />
            <AlertMenu />
            <ThemeToggle />
          </div>
        </header>
        {children}
      </div>
    </div>
  )
}

function Sidebar({ onLogout }: { onLogout: () => void }) {
  const { summary, hosts, services, kpis } = useNavCounts()
  const t = summary.data ? threatLevel(summary.data.openIncidents) : null
  const s = summary.data

  const groups: { title?: string; items: NavItem[] }[] = [
    {
      items: [
        { to: '/', label: 'Visão geral', Icon: LayoutDashboard, end: true },
      ],
    },
    {
      title: 'Monitorar',
      items: [
        {
          to: '/incidents', label: 'Incidentes', Icon: Siren,
          badge: () => (s && s.totalOpenIncidents > 0
            ? { n: s.totalOpenIncidents, tone: (s.openIncidents.CRITICAL || s.openIncidents.HIGH) ? 'critical' : 'warning' }
            : null),
        },
        { to: '/events', label: 'Eventos', Icon: Activity },
      ],
    },
    {
      title: 'Infraestrutura',
      items: [
        {
          to: '/hosts', label: 'Servidores', Icon: Server,
          badge: () => {
            const off = hosts.data?.filter((h) => h.status !== 'ONLINE').length ?? 0
            return off ? { n: off, tone: 'critical' } : null
          },
        },
        {
          to: '/services', label: 'Aplicações', Icon: Boxes,
          badge: () => {
            const down = services.data?.filter((x) => x.health === 'DOWN').length ?? 0
            const degraded = services.data?.filter((x) => x.health === 'DEGRADED').length ?? 0
            return down ? { n: down + degraded, tone: 'critical' } : degraded ? { n: degraded, tone: 'warning' } : null
          },
        },
      ],
    },
    {
      title: 'Proteção',
      items: [
        {
          to: '/response', label: 'Resposta automática', Icon: ShieldCheck,
          badge: () => {
            const n = kpis.data?.actionsAwaitingApproval ?? 0
            return n ? { n, tone: 'warning' } : null
          },
        },
      ],
    },
    {
      title: 'Análise',
      items: [
        { to: '/reports', label: 'Relatórios', Icon: BarChart3 },
        { to: '/client-report', label: 'Relatório do cliente', Icon: FileText },
      ],
    },
  ]

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-5 pb-4 pt-5">
        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-raised">
          <Shield size={20} className="text-hud" aria-hidden />
        </span>
        <div className="leading-tight">
          <p className="font-semibold tracking-tight">VPS-SOC</p>
          <p className="text-xs text-muted">Monitor de segurança</p>
        </div>
      </div>

      {t && (
        <NavLink to="/" className="mx-3 mb-3 flex items-center gap-2 rounded-lg border px-3 py-2 text-sm hover:bg-raised"
          style={{ borderColor: `color-mix(in srgb, ${t.color} 50%, transparent)`, background: `color-mix(in srgb, ${t.color} 10%, transparent)` }}
          title={t.hint}>
          <t.Icon size={16} style={{ color: t.color }} aria-hidden />
          <span className="min-w-0">
            <span className="block text-xs text-muted">Situação</span>
            <span className="block truncate font-semibold">{t.label}</span>
          </span>
        </NavLink>
      )}

      <nav className="flex-1 overflow-y-auto px-3" aria-label="Navegação principal">
        {groups.map((g, i) => (
          <div key={i} className={i > 0 ? 'mt-4' : ''}>
            {g.title && <p className="mb-1 px-2 text-xs font-semibold uppercase tracking-wider text-muted">{g.title}</p>}
            <ul className="space-y-0.5">
              {g.items.map((item) => {
                const b = item.badge?.()
                return (
                  <li key={item.to}>
                    <NavLink to={item.to} end={item.end}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm ${isActive ? 'bg-raised font-semibold text-ink' : 'text-ink2 hover:bg-raised hover:text-ink'}`}>
                      {({ isActive }) => (
                        <>
                          <item.Icon size={17} className={isActive ? 'text-hud' : 'text-muted'} aria-hidden />
                          <span className="flex-1">{item.label}</span>
                          {b && (
                            <span className="tnum min-w-[1.5rem] rounded-full px-1.5 py-0.5 text-center text-xs font-semibold text-white"
                              style={{ background: b.tone === 'critical' ? 'var(--critical)' : 'var(--warning)' }}>
                              {b.n}
                            </span>
                          )}
                        </>
                      )}
                    </NavLink>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="border-t border-line p-3">
        <a href="/apresentacao" target="_blank" rel="noreferrer"
          className="flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-ink2 hover:bg-raised hover:text-ink">
          <Presentation size={17} className="text-muted" aria-hidden /> Apresentação do projeto
        </a>
        <NavLink to="/help"
          className={({ isActive }) => `flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm ${isActive ? 'bg-raised font-semibold text-ink' : 'text-ink2 hover:bg-raised hover:text-ink'}`}>
          <HelpCircle size={17} className="text-muted" aria-hidden /> Ajuda e glossário
        </NavLink>
        <button onClick={onLogout} className="mt-0.5 flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm text-ink2 hover:bg-raised hover:text-ink">
          <LogOut size={17} className="text-muted" aria-hidden /> Sair
        </button>
      </div>
    </div>
  )
}

/** "Ao vivo" while the live stream is open; otherwise says the data refreshes on a timer. */
function LinkStatus() {
  const fetching = useIsFetching()
  const q = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary'), refetchInterval: 10_000 })
  const live = useLiveState()
  const down = q.isError
  const { play } = useAlertSettings()
  const wasDown = useRef(false)
  useEffect(() => {
    if (down && !wasDown.current) play('linkLost') // the backend stopped answering
    wasDown.current = down
  }, [down, play])
  const label = down ? 'Sem conexão' : live === 'live' ? 'Ao vivo' : fetching ? 'Atualizando…' : 'Atualiza a cada 10 s'
  const title = down
    ? 'O painel não consegue falar com o backend. Os dados podem estar desatualizados.'
    : live === 'live'
      ? 'Conectado em tempo real: incidentes, ações e eventos aparecem no instante em que acontecem.'
      : 'Sem conexão em tempo real no momento; o painel se atualiza sozinho a cada poucos segundos.'
  const color = down ? 'var(--critical)' : live === 'live' ? 'var(--good)' : 'var(--warning)'
  return (
    <span className={`hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs sm:flex ${down ? 'border-critical text-critical' : 'border-line text-ink2'}`} title={title}>
      <span className={`inline-block h-2 w-2 rounded-full ${live === 'live' && !down ? 'live-dot' : ''}`} style={{ background: color }} aria-hidden />
      {label}
    </span>
  )
}

/** Dark by default; light for daytime/printing. Remembered per browser. */
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
  const label = light ? 'Usar tema escuro' : 'Usar tema claro'
  return (
    <button onClick={toggle} className="rounded-md border border-line p-1.5 text-ink2 hover:bg-raised" title={label} aria-label={label}>
      {light ? <Moon size={16} aria-hidden /> : <Sun size={16} aria-hidden />}
    </button>
  )
}
