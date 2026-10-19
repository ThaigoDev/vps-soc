import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, ExternalLink } from 'lucide-react'
import { api, type Incident, type IncidentStatus, type SecurityEvent } from '../api'
import { Card, Empty, ErrorNote, RiskBar, SeverityBadge, StatusBadge, eventTypeLabel, fmtTime } from '../components/ui'

interface Detail {
  incident: Incident
  events: SecurityEvent[]
}

const actions: { status: IncidentStatus; label: string }[] = [
  { status: 'ACKNOWLEDGED', label: 'Assumir análise' },
  { status: 'RESOLVED', label: 'Resolver' },
  { status: 'FALSE_POSITIVE', label: 'Falso positivo' },
  { status: 'OPEN', label: 'Reabrir' },
]

export default function IncidentDetail() {
  const { id } = useParams()
  const qc = useQueryClient()
  const [note, setNote] = useState('')
  const q = useQuery({ queryKey: ['incident', id], queryFn: () => api<Detail>(`/incidents/${id}`), refetchInterval: 10_000 })

  const change = useMutation({
    mutationFn: (status: IncidentStatus) =>
      api<Incident>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify({ status, note: note || undefined }) }),
    onSuccess: () => {
      setNote('')
      qc.invalidateQueries({ queryKey: ['incident', id] })
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['summary'] })
    },
  })

  if (q.error) return <ErrorNote error={q.error} />
  if (!q.data) return null
  const { incident: i, events } = q.data

  return (
    <div className="space-y-4">
      <Link to="/incidents" className="inline-flex items-center gap-1 text-sm text-ink2 hover:text-accent">
        <ArrowLeft size={14} aria-hidden /> Incidentes
      </Link>

      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={i.severity} />
          <StatusBadge status={i.status} />
          <span className="text-xs text-muted">#{i.id} · {i.ruleId}</span>
        </div>
        <h1 className="mt-2 text-xl font-semibold">{i.title}</h1>
        {i.description && <p className="mt-1 text-sm text-ink2">{i.description}</p>}

        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-6">
          <Field label="Risco"><RiskBar value={i.riskScore} /></Field>
          <Field label="Host">{i.hostId}</Field>
          <Field label="IP de origem"><span className="font-mono text-xs">{i.sourceIp ?? '-'}</span></Field>
          <Field label="Usuário"><span className="font-mono text-xs">{i.username ?? '-'}</span></Field>
          <Field label="Primeiro evento">{fmtTime(i.firstSeen)}</Field>
          <Field label="Último evento">{fmtTime(i.lastSeen)}</Field>
        </dl>

        {i.techniques.length > 0 && (
          <div className="mt-4">
            <p className="mb-1.5 text-xs text-muted">MITRE ATT&CK</p>
            <div className="flex flex-wrap gap-2">
              {i.techniques.map((t) => (
                <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded border border-line bg-raised px-2 py-1 text-xs hover:border-accent">
                  <span className="font-mono font-semibold">{t.id}</span> {t.name}
                  <ExternalLink size={11} className="text-muted" aria-hidden />
                </a>
              ))}
            </div>
          </div>
        )}

        {i.resolutionNote && <p className="mt-4 text-sm text-ink2">Nota: {i.resolutionNote}</p>}

        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-4">
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Nota (opcional): ex. IP bloqueado no firewall"
            className="min-w-[220px] flex-1 rounded border border-line bg-page px-3 py-1.5 text-sm outline-none focus:border-accent"
          />
          {actions
            .filter((a) => a.status !== i.status && (a.status === 'OPEN') !== (i.status === 'OPEN' || i.status === 'ACKNOWLEDGED'))
            .map((a) => (
              <button
                key={a.status}
                onClick={() => change.mutate(a.status)}
                disabled={change.isPending}
                className="rounded border border-line px-3 py-1.5 text-sm hover:bg-raised disabled:opacity-50"
              >
                {a.label}
              </button>
            ))}
        </div>
        {change.error && <ErrorNote error={change.error} />}
      </Card>

      <Card title={`Linha do tempo (${events.length} eventos)`}>
        {events.length === 0 && <Empty>Sem eventos vinculados (incidente de estado do host).</Empty>}
        <ol className="relative ml-2 border-l border-line">
          {events.map((e) => (
            <li key={e.id} className="mb-3 ml-4">
              <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full border-2 border-surface bg-accent" aria-hidden />
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="tnum text-xs text-muted">{fmtTime(e.occurredAt)}</span>
                <SeverityBadge severity={e.severity} />
                <span className="font-medium">{eventTypeLabel[e.type] ?? e.type}</span>
                {e.username && <span className="font-mono text-xs text-ink2">{e.username}</span>}
                {e.sourceIp && <span className="font-mono text-xs text-ink2">{e.sourceIp}</span>}
              </div>
              {e.message && <p className="mt-0.5 break-all font-mono text-xs text-muted">{e.message}</p>}
            </li>
          ))}
        </ol>
      </Card>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-muted">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}
