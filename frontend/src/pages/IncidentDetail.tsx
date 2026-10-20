import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ArrowLeft, Ban, BookOpen, ExternalLink, Fingerprint, Globe, ListChecks, ShieldCheck, Target, Zap } from 'lucide-react'
import { api, type Incident, type IncidentDetailData, type IncidentStatus, type IpProfile, type ResponseAction } from '../api'
import { Card, Empty, ErrorNote, RiskBar, SeverityBadge, StatusBadge, eventTypeLabel, fmtTime, timeAgo } from '../components/ui'
import { ActionCard, CommandBlock } from '../components/ResponseUi'

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
  const q = useQuery({ queryKey: ['incident', id], queryFn: () => api<IncidentDetailData>(`/incidents/${id}`), refetchInterval: 5_000 })

  const change = useMutation({
    mutationFn: (status: IncidentStatus) =>
      api<Incident>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify({ status, note: note || undefined }) }),
    onSuccess: () => {
      setNote('')
      for (const key of ['incident', 'incidents', 'summary', 'kpis']) qc.invalidateQueries({ queryKey: [key] })
    },
  })

  if (q.error) return <ErrorNote error={q.error} />
  if (!q.data) return null
  const { incident: i, events, explanation: ex, ip, actions: acts } = q.data
  const active = i.status === 'OPEN' || i.status === 'ACKNOWLEDGED'

  return (
    <div className="space-y-4">
      <Link to="/incidents" className="hud-label inline-flex items-center gap-1 text-[11px] text-ink2 hover:text-hud">
        <ArrowLeft size={13} aria-hidden /> Incidentes
      </Link>

      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={i.severity} />
          <StatusBadge status={i.status} />
          {i.containedAt && (
            <span className="inline-flex items-center gap-1 rounded-sm border border-good px-1.5 py-0.5 font-mono text-[11px] font-semibold uppercase text-ink">
              <ShieldCheck size={12} className="text-good" aria-hidden /> Contido {timeAgo(i.containedAt)}
            </span>
          )}
          <span className="hud-label text-[10px] text-muted">#{i.id} · {i.ruleId}</span>
        </div>
        <h1 className="mt-2 text-xl font-semibold">{i.title}</h1>
        {ex.summary && <p className="mt-2 max-w-4xl text-[15px] leading-relaxed text-ink">{ex.summary}</p>}

        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-3 lg:grid-cols-6">
          <Field label="Risco"><RiskBar value={i.riskScore} /></Field>
          <Field label="Host">{i.hostId}</Field>
          <Field label="IP de origem"><span className="font-mono text-xs">{i.sourceIp ?? '—'}</span></Field>
          <Field label="Usuário"><span className="font-mono text-xs">{i.username ?? '—'}</span></Field>
          <Field label="Primeiro evento">{fmtTime(i.firstSeen)}</Field>
          <Field label="Último evento">{fmtTime(i.lastSeen)}</Field>
        </dl>

        {i.techniques.length > 0 && (
          <div className="mt-4">
            <p className="hud-label mb-1.5 text-[10px] text-muted">MITRE ATT&amp;CK</p>
            <div className="flex flex-wrap gap-2">
              {i.techniques.map((t) => (
                <a key={t.id} href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-sm border border-line bg-raised px-2 py-1 text-xs hover:border-hud">
                  <span className="font-mono font-semibold">{t.id}</span> {t.name}
                  <ExternalLink size={11} className="text-muted" aria-hidden />
                </a>
              ))}
            </div>
          </div>
        )}

        {i.resolutionNote && <p className="mt-4 text-sm text-ink2"><span className="hud-label text-[10px] text-muted">Nota · </span>{i.resolutionNote}</p>}

        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-4">
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Nota (opcional): o que você verificou ou fez"
            className="min-w-[220px] flex-1 rounded-sm border border-line bg-page px-3 py-1.5 text-sm outline-none focus:border-hud"
          />
          {actions
            .filter((a) => a.status !== i.status && (a.status === 'OPEN') !== active)
            .map((a) => (
              <button key={a.status} onClick={() => change.mutate(a.status)} disabled={change.isPending}
                className="rounded-sm border border-line px-3 py-1.5 text-sm hover:bg-raised disabled:opacity-50">
                {a.label}
              </button>
            ))}
        </div>
        {change.error && <ErrorNote error={change.error} />}
      </Card>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {ex.impact && (
            <Card title={<><AlertTriangle size={13} aria-hidden /> Por que isso importa</>}>
              <p className="text-sm leading-relaxed text-ink">{ex.impact}</p>
              {ex.riskFactors.length > 0 && (
                <ul className="mt-3 space-y-1 border-t border-line pt-3 text-sm text-ink2">
                  {ex.riskFactors.map((r) => (
                    <li key={r} className="flex gap-2"><span className="text-hud" aria-hidden>›</span>{r}</li>
                  ))}
                </ul>
              )}
            </Card>
          )}

          <ResponsePanel i={i} acts={acts} text={ex.response} ip={ip} />

          {ex.recommendations.length > 0 && (
            <Card title={<><ListChecks size={13} aria-hidden /> Próximos passos</>}>
              <ol className="space-y-4">
                {ex.recommendations.map((s, n) => (
                  <li key={s.title} className="flex gap-3">
                    <span className="tnum flex h-6 w-6 shrink-0 items-center justify-center border border-hud font-mono text-xs font-bold text-hud">{n + 1}</span>
                    <div className="min-w-0 flex-1">
                      <p className="font-semibold">{s.title}</p>
                      {s.detail && <p className="mt-0.5 text-sm text-ink2">{s.detail}</p>}
                      {s.command && <CommandBlock command={s.command} />}
                    </div>
                  </li>
                ))}
              </ol>
              <p className="mt-4 border-t border-line pt-3 text-xs text-muted">
                Rode os comandos no terminal da VPS (hPanel → Terminal ou SSH). Nada aqui é executado sozinho: as ações automáticas aparecem em “Resposta”.
              </p>
            </Card>
          )}

          <Card title={`Linha do tempo (${events.length} eventos)`}>
            {events.length === 0 && <Empty>Sem eventos vinculados: é um incidente de estado do host (saúde ou postura).</Empty>}
            <ol className="relative ml-2 border-l border-line">
              {events.map((e) => (
                <li key={e.id} className="mb-3 ml-4">
                  <span className="absolute -left-[5px] mt-1.5 h-2.5 w-2.5 rounded-full border-2 border-surface bg-hud" aria-hidden />
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="tnum font-mono text-xs text-muted">{fmtTime(e.occurredAt)}</span>
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

        <div className="space-y-4">
          {ex.evidence.length > 0 && (
            <Card title={<><Fingerprint size={13} aria-hidden /> Evidências</>}>
              <dl className="space-y-2.5 text-sm">
                {ex.evidence.map((f) => (
                  <div key={f.label}>
                    <dt className="hud-label text-[10px] text-muted">{f.label}</dt>
                    <dd className="mt-0.5 break-words">{f.value}</dd>
                  </div>
                ))}
              </dl>
            </Card>
          )}
          {ip && <IpCard ip={ip} hostId={i.hostId} incidentId={i.id} />}
          {ex.falsePositive && (
            <Card title={<><BookOpen size={13} aria-hidden /> Pode ser falso positivo?</>}>
              <p className="text-sm leading-relaxed text-ink2">{ex.falsePositive}</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}

function ResponsePanel({ i, acts, text, ip }: { i: Incident; acts: ResponseAction[]; text?: string; ip?: IpProfile }) {
  return (
    <Card title={<><Zap size={13} aria-hidden /> Resposta do SOC</>}>
      {i.containmentNote && (
        <p className="mb-3 flex gap-2 border-l-2 border-good pl-3 text-sm text-ink">
          <ShieldCheck size={16} className="mt-0.5 shrink-0 text-good" aria-hidden />
          <span className="whitespace-pre-line">{i.containmentNote}</span>
        </p>
      )}
      {acts.length > 0 && <ul className="space-y-2">{acts.map((a) => <ActionCard key={a.id} a={a} showIncident={a.incidentId !== i.id} />)}</ul>}
      {acts.length === 0 && !i.containmentNote && <p className="text-sm text-ink2">{text}</p>}
      {ip && ip.kind === 'PUBLIC' && !ip.protectedBy && !ip.blockedUntil && (
        <p className="mt-3 text-xs text-muted">
          Quer agir manualmente? Use “Bloquear IP” no cartão do IP ao lado.
        </p>
      )}
    </Card>
  )
}

function IpCard({ ip, hostId, incidentId }: { ip: IpProfile; hostId: string; incidentId: number }) {
  const qc = useQueryClient()
  const [hours, setHours] = useState(24)
  const block = useMutation({
    mutationFn: () => api('/response/blocks', { method: 'POST', body: JSON.stringify({ hostId, ip: ip.ip, ttlHours: hours, incidentId, reason: `Bloqueio manual a partir do incidente #${incidentId}` }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident'] }),
  })
  const canBlock = !ip.protectedBy && !ip.blockedUntil
  return (
    <Card title={<><Globe size={13} aria-hidden /> Perfil do IP</>}>
      <p className="font-mono text-lg font-semibold">{ip.ip}</p>
      <p className="text-xs text-ink2">{ip.kindLabel}{ip.trustedSource ? ' · origem confiável' : ''}</p>
      {ip.blockedUntil && (
        <p className="mt-2 flex items-center gap-1.5 text-sm font-semibold">
          <Ban size={14} className="text-critical" aria-hidden /> Bloqueado até {fmtTime(ip.blockedUntil)}
          <span className="font-normal text-muted">({ip.blockOrigin === 'AGENT' ? 'agente' : 'SOC'})</span>
        </p>
      )}
      {ip.protectedBy && (
        <p className="mt-2 flex items-center gap-1.5 text-sm"><ShieldCheck size={14} className="text-good" aria-hidden /> Faixa protegida ({ip.protectedBy}): nunca é bloqueada</p>
      )}
      <dl className="mt-3 grid grid-cols-2 gap-3 text-sm">
        <Stat label="Falhas de login" value={ip.failures} />
        <Stat label="Logins com sucesso" value={ip.successes} alert={ip.successes > 0 && ip.failures > 0} />
        <Stat label="Usuários testados" value={ip.usernamesTried} />
        <Stat label="Incidentes" value={ip.incidents} />
      </dl>
      {ip.firstSeen && <p className="mt-3 text-xs text-muted">Visto pela 1ª vez {fmtTime(ip.firstSeen)} · último {timeAgo(ip.lastSeen!)}</p>}
      {ip.topUsernames.length > 0 && (
        <div className="mt-3">
          <p className="hud-label mb-1 text-[10px] text-muted"><Target size={11} className="mr-1 inline" aria-hidden />Usuários mais tentados</p>
          <div className="flex flex-wrap gap-1">
            {ip.topUsernames.map((u) => (
              <span key={u.username} className="rounded-sm border border-line bg-raised px-1.5 py-0.5 font-mono text-[11px]">{u.username || '(vazio)'} · {u.attempts}</span>
            ))}
          </div>
        </div>
      )}
      <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-3">
        <Link to={`/events?ip=${encodeURIComponent(ip.ip)}`} className="hud-label text-[10px] text-hud hover:underline">Todos os eventos</Link>
        <a href={`https://www.abuseipdb.com/check/${encodeURIComponent(ip.ip)}`} target="_blank" rel="noreferrer" className="hud-label inline-flex items-center gap-1 text-[10px] text-hud hover:underline">
          AbuseIPDB <ExternalLink size={10} aria-hidden />
        </a>
        {canBlock && (
          <span className="ml-auto flex items-center gap-1">
            <select value={hours} onChange={(e) => setHours(Number(e.target.value))} className="rounded-sm border border-line bg-page px-1 py-1 text-xs" aria-label="Duração do bloqueio">
              <option value={1}>1 h</option>
              <option value={24}>24 h</option>
              <option value={168}>7 dias</option>
              <option value={720}>30 dias</option>
            </select>
            <button onClick={() => block.mutate()} disabled={block.isPending}
              className="hud-label flex items-center gap-1 rounded-sm border border-critical px-2 py-1 text-[10px] font-semibold text-ink hover:bg-raised disabled:opacity-50">
              <Ban size={12} aria-hidden /> Bloquear IP
            </button>
          </span>
        )}
      </div>
      {block.error && <ErrorNote error={block.error} />}
    </Card>
  )
}

function Stat({ label, value, alert }: { label: string; value: number; alert?: boolean }) {
  return (
    <div>
      <dt className="hud-label text-[10px] text-muted">{label}</dt>
      <dd className={`tnum font-mono text-xl font-bold ${alert ? 'text-critical' : ''}`}>{value.toLocaleString('pt-BR')}</dd>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="hud-label text-[10px] text-muted">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}
