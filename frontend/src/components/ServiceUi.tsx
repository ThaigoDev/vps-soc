import { AlertTriangle, CheckCircle2, HelpCircle, Info, XCircle } from 'lucide-react'
import type { SecurityCheck, ServiceHealth, VulnLevel } from '../api'
import { CommandBlock } from './ResponseUi'

export const healthStyle: Record<ServiceHealth, { label: string; color: string; Icon: typeof CheckCircle2 }> = {
  HEALTHY: { label: 'Saudável', color: 'var(--good)', Icon: CheckCircle2 },
  DEGRADED: { label: 'Degradado', color: 'var(--warning)', Icon: AlertTriangle },
  DOWN: { label: 'Fora do ar', color: 'var(--critical)', Icon: XCircle },
  UNKNOWN: { label: 'Sem dados', color: 'var(--muted)', Icon: HelpCircle },
}

/** Health always ships icon + label, never color alone. */
export function HealthBadge({ health }: { health: ServiceHealth }) {
  const h = healthStyle[health]
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide text-ink"
      style={{ borderColor: h.color, background: `color-mix(in srgb, ${h.color} 14%, transparent)` }}>
      <h.Icon size={12} style={{ color: h.color }} aria-hidden />
      {h.label}
    </span>
  )
}

/** The pm2 status word, as `pm2 list` prints it. */
export function Pm2Status({ status }: { status: string }) {
  const color = status === 'online' ? 'var(--good)' : status === 'errored' ? 'var(--critical)' : status === 'stopped' ? 'var(--muted)' : 'var(--warning)'
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs">
      <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} aria-hidden />
      {status}
    </span>
  )
}

export function fmtUptime(startedAt?: string, status?: string): string {
  if (!startedAt || status !== 'online') return '—'
  const s = Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}

export function fmtMb(bytes?: number): string {
  if (!bytes) return '0 MB'
  const mb = bytes / 1048576
  return mb >= 1024 ? `${(mb / 1024).toFixed(2)} GB` : `${mb.toFixed(1)} MB`
}

export const healthOrder: Record<ServiceHealth, number> = { DOWN: 0, DEGRADED: 1, UNKNOWN: 2, HEALTHY: 3 }

export function scoreColor(score: number): string {
  return score >= 80 ? 'var(--good)' : score >= 50 ? 'var(--warning)' : 'var(--critical)'
}

/** 0–100 security score; the label carries the meaning, the color only reinforces it. */
export function ScoreBadge({ score, size = 'sm' }: { score: number; size?: 'sm' | 'lg' }) {
  const label = score >= 80 ? 'Boa' : score >= 50 ? 'Atenção' : 'Ruim'
  const color = scoreColor(score)
  if (size === 'lg') {
    return (
      <div className="flex items-baseline gap-2">
        <span className="tnum font-mono text-5xl font-bold" style={{ color }}>{score}</span>
        <span className="text-sm text-muted">/ 100</span>
        <span className="hud-label ml-1 text-[11px] font-bold" style={{ color }}>{label}</span>
      </div>
    )
  }
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs" title={`Nota de segurança ${score}/100 (${label})`}>
      <span className="tnum font-bold" style={{ color }}>{score}</span>
      <span className="text-[10px] text-muted">{label}</span>
    </span>
  )
}

export const vulnStyle: Record<VulnLevel, { label: string; color: string; short: string }> = {
  CRITICAL: { label: 'Crítica', short: 'C', color: 'var(--critical)' },
  HIGH: { label: 'Alta', short: 'A', color: 'var(--serious)' },
  MEDIUM: { label: 'Média', short: 'M', color: 'var(--warning)' },
  LOW: { label: 'Baixa', short: 'B', color: 'var(--good)' },
  UNKNOWN: { label: 'Sem nota', short: '?', color: 'var(--muted)' },
}

export function VulnBadge({ level }: { level: VulnLevel }) {
  const v = vulnStyle[level]
  return (
    <span className="inline-flex whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase text-ink"
      style={{ borderColor: v.color, background: `color-mix(in srgb, ${v.color} 14%, transparent)` }}>
      {v.label}
    </span>
  )
}

/** Compact "2 C · 5 A" counts; nothing when clean. */
export function VulnCounts({ counts }: { counts?: Partial<Record<VulnLevel, number>> }) {
  const order: VulnLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM']
  const shown = order.filter((l) => (counts?.[l] ?? 0) > 0)
  if (!counts) return <span className="text-xs text-muted">—</span>
  if (shown.length === 0) return <span className="text-xs text-good">nenhuma</span>
  return (
    <span className="flex flex-wrap gap-1 font-mono text-[11px]">
      {shown.map((l) => (
        <span key={l} className="rounded-sm border px-1" style={{ borderColor: vulnStyle[l].color }} title={`${counts[l]} ${vulnStyle[l].label.toLowerCase()}(s)`}>
          {counts[l]} {vulnStyle[l].label.toLowerCase()}
        </span>
      ))}
    </span>
  )
}

const checkIcon = {
  OK: { Icon: CheckCircle2, color: 'var(--good)', label: 'ok' },
  WARN: { Icon: AlertTriangle, color: 'var(--warning)', label: 'atenção' },
  FAIL: { Icon: XCircle, color: 'var(--critical)', label: 'falha' },
  INFO: { Icon: Info, color: 'var(--muted)', label: 'info' },
}

export function SecurityChecklist({ checks }: { checks: SecurityCheck[] }) {
  const order = { FAIL: 0, WARN: 1, INFO: 2, OK: 3 }
  return (
    <ul className="space-y-3">
      {[...checks].sort((a, b) => order[a.status] - order[b.status]).map((c) => {
        const s = checkIcon[c.status]
        return (
          <li key={c.key} className="flex gap-2.5">
            <s.Icon size={16} className="mt-0.5 shrink-0" style={{ color: s.color }} aria-label={s.label} />
            <div className="min-w-0 flex-1">
              <p className={`text-sm ${c.status === 'FAIL' ? 'font-semibold' : ''}`}>{c.label}</p>
              <p className="text-xs text-ink2">{c.detail}</p>
              {c.fix && c.status !== 'OK' && (looksLikeCommand(c.fix) ? <CommandBlock command={c.fix} /> : <p className="mt-1 text-xs text-hud">{c.fix}</p>)}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function looksLikeCommand(s: string) {
  return /^(cd |sudo |chmod |npm |pm2 |nvm |echo )/.test(s)
}
