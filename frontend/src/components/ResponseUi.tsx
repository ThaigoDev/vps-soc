import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Ban, Boxes, Check, CheckCircle2, Clock, Copy, Cpu, Eraser, Hourglass, RotateCcw, ShieldCheck, Unlock, X, XCircle } from 'lucide-react'
import { api, type ActionStatus, type ActionType, type Policy, type ResponseAction } from '../api'
import { ErrorNote, fmtTime, timeAgo } from './ui'
import { useAlertSettings } from './Alerts'

const statusStyle: Record<ActionStatus, { label: string; color: string; Icon: typeof Check }> = {
  PROPOSED: { label: 'Aguardando aprovação', color: 'var(--warning)', Icon: Hourglass },
  PENDING: { label: 'Na fila do agente', color: 'var(--hud)', Icon: Clock },
  SENT: { label: 'Executando', color: 'var(--hud)', Icon: Clock },
  SUCCEEDED: { label: 'Executada', color: 'var(--good)', Icon: CheckCircle2 },
  FAILED: { label: 'Falhou', color: 'var(--critical)', Icon: XCircle },
  REJECTED: { label: 'Recusada pelo agente', color: 'var(--serious)', Icon: XCircle },
  DISMISSED: { label: 'Descartada', color: 'var(--muted)', Icon: X },
  EXPIRED: { label: 'Expirada', color: 'var(--muted)', Icon: Clock },
}

export const actionIcon: Record<ActionType, typeof Ban> = {
  BLOCK_IP: Ban,
  UNBLOCK_IP: Unlock,
  KILL_PROCESS: Cpu,
  DISK_CLEANUP: Eraser,
  RESTART_SERVICE: RotateCcw,
  PM2_RESTART: Boxes,
}

export const policyLabel: Record<Policy, string> = {
  AUTO: 'Automático',
  APPROVAL: 'Com aprovação',
  OFF: 'Desligado',
}

/** Status always ships icon + label, never color alone. */
export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const s = statusStyle[status]
  return (
    <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-sm border px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase tracking-wide text-ink"
      style={{ borderColor: s.color, background: `color-mix(in srgb, ${s.color} 12%, transparent)` }}>
      <s.Icon size={12} style={{ color: s.color }} aria-hidden />
      {s.label}
    </span>
  )
}

export function useActionMutations() {
  const qc = useQueryClient()
  const refresh = () => {
    for (const key of ['actions', 'blocks', 'incident', 'incidents', 'summary', 'kpis']) qc.invalidateQueries({ queryKey: [key] })
  }
  const approve = useMutation({ mutationFn: (id: number) => api<ResponseAction>(`/response/actions/${id}/approve`, { method: 'POST' }), onSuccess: refresh })
  const dismiss = useMutation({ mutationFn: (id: number) => api<ResponseAction>(`/response/actions/${id}/dismiss`, { method: 'POST' }), onSuccess: refresh })
  return { approve, dismiss, refresh }
}

/** One response action: what, why, who decided, outcome, and approve/dismiss when it waits. */
export function ActionCard({ a, showIncident = false }: { a: ResponseAction; showIncident?: boolean }) {
  const { approve, dismiss } = useActionMutations()
  const { play } = useAlertSettings()
  const Icon = actionIcon[a.type]
  const who = a.origin === 'AGENT' ? 'pelo agente (guarda local)' : a.mode === 'AUTO' ? 'automático' : 'manual'
  const busy = approve.isPending || dismiss.isPending
  return (
    <li className="border border-line bg-page p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Icon size={15} className="text-hud" aria-hidden />
        <span className="font-semibold">{a.label}</span>
        <ActionStatusBadge status={a.status} />
        <span className="hud-label text-[10px] text-muted">#{a.id} · {who} · {a.hostId}</span>
        {showIncident && a.incidentId && (
          <Link to={`/incidents/${a.incidentId}`} className="hud-label text-[10px] text-hud hover:underline">incidente #{a.incidentId}</Link>
        )}
        <span className="ml-auto text-xs text-muted" title={fmtTime(a.completedAt ?? a.createdAt)}>{timeAgo(a.completedAt ?? a.createdAt)}</span>
      </div>
      {a.reason && <p className="mt-1.5 text-sm text-ink2">{a.reason}</p>}
      {a.result && <p className="mt-1 break-words font-mono text-xs text-ink">{a.result}</p>}
      {a.status === 'PROPOSED' && (
        <div className="mt-2 flex gap-2">
          <button onClick={() => { play('click'); approve.mutate(a.id) }} disabled={busy}
            className="hud-label flex items-center gap-1 rounded-sm border border-good px-2.5 py-1 text-[11px] font-semibold text-ink hover:bg-raised disabled:opacity-50">
            <ShieldCheck size={13} aria-hidden /> Aprovar e executar
          </button>
          <button onClick={() => dismiss.mutate(a.id)} disabled={busy}
            className="hud-label flex items-center gap-1 rounded-sm border border-line px-2.5 py-1 text-[11px] text-ink2 hover:bg-raised disabled:opacity-50">
            <X size={13} aria-hidden /> Descartar
          </button>
        </div>
      )}
      {(approve.error || dismiss.error) && <ErrorNote error={approve.error ?? dismiss.error} />}
    </li>
  )
}

/** A shell command with a copy button (commands are meant to be pasted in the VPS terminal). */
export function CommandBlock({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard blocked: the text is selectable anyway */
    }
  }
  return (
    <div className="mt-1.5 flex items-start gap-2 border border-line bg-page px-2.5 py-1.5">
      <code className="min-w-0 flex-1 whitespace-pre-wrap break-all font-mono text-xs text-ink">{command}</code>
      <button onClick={copy} className="shrink-0 text-muted hover:text-ink" title="Copiar comando" aria-label="Copiar comando">
        {copied ? <Check size={14} className="text-good" aria-hidden /> : <Copy size={14} aria-hidden />}
      </button>
    </div>
  )
}

export function fmtDuration(seconds?: number | null): string {
  if (seconds === undefined || seconds === null) return '—'
  const s = Math.round(seconds)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}min ${s % 60 ? `${s % 60}s` : ''}`.trim()
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}min`
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`
}
