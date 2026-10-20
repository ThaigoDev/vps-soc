import type { ReactNode } from 'react'
import { AlertOctagon, AlertTriangle, CircleDot, Info, ShieldAlert } from 'lucide-react'
import type { IncidentStatus, Severity } from '../api'

export function Card({ title, action, children, className = '', fill = false }: {
  title?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
  /** Stretch the body to the card height (e.g. a chart next to a taller panel). */
  fill?: boolean
}) {
  return (
    <section className={`panel border border-line bg-surface ${fill ? 'flex flex-col' : ''} ${className}`}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-2 border-b border-line px-4 py-2.5">
          <h2 className="hud-label flex items-center gap-2 font-semibold text-hud">{title}</h2>
          {action}
        </header>
      )}
      <div className={fill ? 'flex min-h-0 flex-1 flex-col p-4' : 'p-4'}>{children}</div>
    </section>
  )
}

/** Shared recharts tooltip look. */
export const chartTooltip = {
  contentStyle: { background: 'var(--raised)', border: '1px solid var(--axis)', borderRadius: 2, fontSize: 12, color: 'var(--ink)' },
  labelStyle: { color: 'var(--ink)', fontWeight: 600 },
  itemStyle: { color: 'var(--ink-2)' },
}

export const severityRank: Record<Severity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

export interface ThreatLevel {
  level: 1 | 2 | 3 | 4 | 5
  label: string
  color: string
  Icon: typeof Info
  hint: string
}

/** Readiness-style threat level from the worst active incident (1 = worst). */
export function threatLevel(open: Partial<Record<Severity, number>> | undefined): ThreatLevel {
  if (open?.CRITICAL) return { level: 1, label: 'Crítico', color: 'var(--critical)', Icon: AlertOctagon, hint: 'Ataque em andamento ou comprometimento provável' }
  if (open?.HIGH) return { level: 2, label: 'Alto', color: 'var(--serious)', Icon: ShieldAlert, hint: 'Atividade hostil confirmada, responder agora' }
  if (open?.MEDIUM) return { level: 3, label: 'Elevado', color: 'var(--warning)', Icon: AlertTriangle, hint: 'Atividade suspeita para investigar' }
  if (open?.LOW) return { level: 4, label: 'Guarda', color: 'var(--good)', Icon: CircleDot, hint: 'Ruído de baixo risco' }
  return { level: 5, label: 'Normal', color: 'var(--good)', Icon: CircleDot, hint: 'Nenhum incidente ativo' }
}

export const severityStyle: Record<Severity, { color: string; label: string; Icon: typeof Info }> = {
  CRITICAL: { color: 'var(--critical)', label: 'Crítico', Icon: AlertOctagon },
  HIGH: { color: 'var(--serious)', label: 'Alto', Icon: ShieldAlert },
  MEDIUM: { color: 'var(--warning)', label: 'Médio', Icon: AlertTriangle },
  LOW: { color: 'var(--good)', label: 'Baixo', Icon: CircleDot },
  INFO: { color: 'var(--muted)', label: 'Info', Icon: Info },
}

/** Severity always ships icon + label, never color alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const { color, label, Icon } = severityStyle[severity]
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide text-ink" style={{ borderColor: color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
      <Icon size={13} style={{ color }} aria-hidden />
      {label}
    </span>
  )
}

const statusLabel: Record<IncidentStatus, string> = {
  OPEN: 'Aberto',
  ACKNOWLEDGED: 'Em análise',
  RESOLVED: 'Resolvido',
  FALSE_POSITIVE: 'Falso positivo',
}

export function StatusBadge({ status }: { status: IncidentStatus }) {
  const active = status === 'OPEN' || status === 'ACKNOWLEDGED'
  return (
    <span className={`whitespace-nowrap rounded px-1.5 py-0.5 text-xs ${active ? 'bg-raised font-medium text-ink' : 'text-muted'}`}>
      {statusLabel[status]}
    </span>
  )
}

export function RiskBar({ value }: { value: number }) {
  const color = value >= 85 ? 'var(--critical)' : value >= 60 ? 'var(--serious)' : value >= 35 ? 'var(--warning)' : 'var(--good)'
  return (
    <div className="flex items-center gap-2" title={`Risco ${value}/100`}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-raised">
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="tnum text-xs text-ink2">{value}</span>
    </div>
  )
}

export function timeAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.max(s, 0)}s atrás`
  if (s < 3600) return `${Math.floor(s / 60)} min atrás`
  if (s < 86400) return `${Math.floor(s / 3600)} h atrás`
  return `${Math.floor(s / 86400)} d atrás`
}

export function fmtTime(iso: string): string {
  return new Date(iso).toLocaleString('pt-BR', { dateStyle: 'short', timeStyle: 'medium' })
}

export function fmtBytes(n?: number): string {
  if (!n) return '-'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(1)} ${units[i]}`
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="py-6 text-center text-sm text-muted">{children}</p>
}

export function ErrorNote({ error }: { error: unknown }) {
  return <p className="py-4 text-sm text-critical">{error instanceof Error ? error.message : 'Erro ao carregar'}</p>
}

export const eventTypeLabel: Record<string, string> = {
  SSH_FAILED_LOGIN: 'Falha de login SSH',
  SSH_INVALID_USER: 'Usuário SSH inválido',
  SSH_LOGIN_SUCCESS: 'Login SSH',
  SUDO_COMMAND: 'Comando sudo',
  SUDO_AUTH_FAILURE: 'Falha de senha sudo',
  SUDO_DENIED: 'Sudo negado',
  PORT_OPENED: 'Porta aberta',
  PORT_CLOSED: 'Porta fechada',
  PORT_BASELINE: 'Baseline de portas',
  AGENT_STARTED: 'Agente iniciado',
  FILE_CREATED: 'Arquivo criado',
  FILE_MODIFIED: 'Arquivo alterado',
  FILE_DELETED: 'Arquivo removido',
  FILE_BASELINE: 'Baseline de arquivos',
  PROCESS_SUSPICIOUS: 'Processo suspeito',
  RESPONSE_EXECUTED: 'Resposta automática',
}
