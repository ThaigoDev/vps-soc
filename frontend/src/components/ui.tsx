import type { ReactNode } from 'react'
import { AlertOctagon, AlertTriangle, CheckCircle2, CircleDot, Info, ShieldAlert } from 'lucide-react'
import type { IncidentStatus, Severity } from '../api'

export function Card({ title, description, action, children, className = '', fill = false, flush = false }: {
  title?: ReactNode
  /** One plain sentence under the title: what this block shows and why it matters. */
  description?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
  /** Stretch the body to the card height (e.g. a chart next to a taller panel). */
  fill?: boolean
  /** No inner padding (tables and lists that run edge to edge). */
  flush?: boolean
}) {
  const pad = flush ? '' : 'p-4'
  return (
    <section className={`rounded-xl border border-line bg-surface ${fill ? 'flex flex-col' : ''} ${className}`}>
      {(title || action) && (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b border-line px-4 py-3">
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">{title}</h2>
            {description && <p className="mt-0.5 text-xs text-muted">{description}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={fill ? `flex min-h-0 flex-1 flex-col ${pad}` : pad}>{children}</div>
    </section>
  )
}

/** Title + plain-language explanation at the top of every page. */
export function PageHeader({ title, description, actions, icon: Icon }: {
  title: string
  description: ReactNode
  actions?: ReactNode
  icon?: typeof Info
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="flex items-center gap-2 text-xl font-semibold tracking-tight text-ink">
          {Icon && <Icon size={20} className="text-hud" aria-hidden />}
          {title}
        </h1>
        <p className="mt-1 max-w-3xl text-sm text-ink2">{description}</p>
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** Segmented control for a handful of mutually exclusive filters. */
export function Segmented<T extends string | number>({ value, onChange, options, label }: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: string }[]
  label: string
}) {
  return (
    <div role="group" aria-label={label} className="inline-flex rounded-lg border border-line bg-page p-0.5 text-xs">
      {options.map((o) => (
        <button key={String(o.value)} onClick={() => onChange(o.value)} aria-pressed={o.value === value}
          className={`rounded-md px-2.5 py-1 font-medium ${o.value === value ? 'bg-raised text-ink shadow-sm' : 'text-muted hover:text-ink2'}`}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** Small "?" with a plain explanation on hover/focus. */
export function Hint({ text }: { text: string }) {
  return (
    <span tabIndex={0} title={text} aria-label={text}
      className="inline-flex h-4 w-4 cursor-help items-center justify-center rounded-full border border-line text-xs font-semibold text-muted hover:text-ink">
      ?
    </span>
  )
}

/** Previous / next pager used by every paginated table. */
export function Pager({ page, totalPages, onPage, summary }: { page: number; totalPages: number; onPage: (p: number) => void; summary?: ReactNode }) {
  if (totalPages <= 1 && !summary) return null
  return (
    <div className="flex items-center justify-end gap-2 border-t border-line px-4 py-3 text-sm">
      {summary && <span className="mr-auto text-xs text-muted">{summary}</span>}
      {totalPages > 1 && (
        <>
          <button disabled={page === 0} onClick={() => onPage(page - 1)} className="rounded-md border border-line px-2.5 py-1 hover:bg-raised disabled:opacity-40">Anterior</button>
          <span className="tnum text-xs text-muted">Página {page + 1} de {totalPages}</span>
          <button disabled={page + 1 >= totalPages} onClick={() => onPage(page + 1)} className="rounded-md border border-line px-2.5 py-1 hover:bg-raised disabled:opacity-40">Próxima</button>
        </>
      )}
    </div>
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
  /** Plain sentence for the overview banner. */
  headline: string
  color: string
  Icon: typeof Info
  hint: string
}

/** Overall situation from the worst active incident (1 = worst, 5 = all clear). */
export function threatLevel(open: Partial<Record<Severity, number>> | undefined): ThreatLevel {
  if (open?.CRITICAL) return { level: 1, label: 'Crítico', headline: 'Ataque em andamento: aja agora', color: 'var(--critical)', Icon: AlertOctagon, hint: 'Há incidente crítico aberto: invasão provável ou ataque ativo.' }
  if (open?.HIGH) return { level: 2, label: 'Alto', headline: 'Atividade hostil detectada', color: 'var(--serious)', Icon: ShieldAlert, hint: 'Há incidente de severidade alta aberto. Responda o quanto antes.' }
  if (open?.MEDIUM) return { level: 3, label: 'Elevado', headline: 'Algo suspeito para investigar', color: 'var(--warning)', Icon: AlertTriangle, hint: 'Há incidente médio aberto. Não é urgente, mas precisa de análise.' }
  if (open?.LOW) return { level: 4, label: 'Baixo', headline: 'Tudo sob controle', color: 'var(--good)', Icon: CircleDot, hint: 'Só há avisos de baixo risco abertos.' }
  return { level: 5, label: 'Normal', headline: 'Tudo tranquilo', color: 'var(--good)', Icon: CheckCircle2, hint: 'Nenhum incidente aberto.' }
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
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium text-ink" style={{ borderColor: `color-mix(in srgb, ${color} 55%, transparent)`, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
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
    <span className={`whitespace-nowrap rounded-full px-2 py-0.5 text-xs ${active ? 'bg-raised font-medium text-ink' : 'text-muted'}`}>
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
  SERVICE_STATUS_CHANGED: 'App PM2 mudou de status',
  SERVICE_RESTARTED: 'App PM2 reiniciou',
  SERVICE_ADDED: 'App PM2 adicionado',
  SERVICE_REMOVED: 'App PM2 removido',
}
