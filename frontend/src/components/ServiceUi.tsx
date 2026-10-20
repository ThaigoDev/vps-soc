import { AlertTriangle, CheckCircle2, HelpCircle, XCircle } from 'lucide-react'
import type { ServiceHealth } from '../api'

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
