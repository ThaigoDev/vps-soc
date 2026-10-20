import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowLeft, Boxes, History, RotateCcw, Siren } from 'lucide-react'
import { api, type ServiceDetail as Detail } from '../api'
import { Card, Empty, ErrorNote, SeverityBadge, StatusBadge, chartTooltip, eventTypeLabel, fmtTime, timeAgo } from '../components/ui'
import { CommandBlock } from '../components/ResponseUi'
import { HealthBadge, Pm2Status, fmtMb, fmtUptime, healthStyle } from '../components/ServiceUi'

export default function ServiceDetail() {
  const { hostId = '', name = '' } = useParams()
  const qc = useQueryClient()
  const [hours, setHours] = useState(24)
  const q = useQuery({
    queryKey: ['service', hostId, name, hours],
    queryFn: () => api<Detail>(`/services/${encodeURIComponent(hostId)}/${encodeURIComponent(name)}?hours=${hours}`),
    refetchInterval: 10_000,
  })
  const restart = useMutation({
    mutationFn: () => api(`/services/${encodeURIComponent(hostId)}/${encodeURIComponent(name)}/restart`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actions'] })
      qc.invalidateQueries({ queryKey: ['service'] })
    },
  })

  if (q.error) return <ErrorNote error={q.error} />
  if (!q.data) return null
  const { service: s, samples, events, incidents } = q.data
  const a = s.pm2
  const asUser = a.user && a.user !== 'root' ? `sudo -u ${a.user} ` : ''
  const chart = samples.map((p) => ({
    label: new Date(p.t).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
    cpu: p.cpu ?? null,
    mem: p.memoryMb !== undefined && p.memoryMb !== null ? Math.round(p.memoryMb * 10) / 10 : null,
  }))

  return (
    <div className="space-y-4">
      <Link to="/services" className="hud-label inline-flex items-center gap-1 text-[11px] text-ink2 hover:text-hud">
        <ArrowLeft size={13} aria-hidden /> Serviços
      </Link>

      <Card>
        <div className="flex flex-wrap items-center gap-2">
          <HealthBadge health={s.health} />
          <Pm2Status status={a.status} />
          <span className="hud-label text-[10px] text-muted">pm2 id {a.pmId} · {s.hostId}</span>
          <button onClick={() => { if (window.confirm(`Reiniciar ${a.name} com pm2 restart?`)) restart.mutate() }} disabled={restart.isPending || !s.hostOnline}
            className="hud-label ml-auto flex items-center gap-1 rounded-sm border border-line px-2.5 py-1 text-[11px] text-ink hover:bg-raised disabled:opacity-50">
            <RotateCcw size={13} aria-hidden /> Reiniciar (pm2 restart)
          </button>
        </div>
        <h1 className="mt-2 flex items-center gap-2 text-xl font-semibold"><Boxes size={20} className="text-hud" aria-hidden /> {a.name}</h1>
        <ul className="mt-2 space-y-0.5 text-sm">
          {s.reasons.map((r) => (
            <li key={r} className="flex gap-2"><span style={{ color: healthStyle[s.health].color }} aria-hidden>›</span>{r}</li>
          ))}
        </ul>
        {restart.isSuccess && <p className="mt-2 text-sm text-good">Reinício enviado ao agente: acompanhe em Resposta.</p>}
        {restart.error && <ErrorNote error={restart.error} />}

        <dl className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 text-sm sm:grid-cols-4 lg:grid-cols-8">
          <Field label="Uptime">{fmtUptime(a.startedAt, a.status)}</Field>
          <Field label="Reinícios">{a.restarts} <span className="text-muted">({s.restartsLastHour} na última hora)</span></Field>
          <Field label="Instáveis">{a.unstableRestarts}</Field>
          <Field label="CPU">{a.cpuPercent.toFixed(1)}%</Field>
          <Field label="Memória">{fmtMb(a.memoryBytes)} <span className="text-muted">({s.memoryPercent.toFixed(1)}% RAM)</span></Field>
          <Field label="PID">{a.pid || '—'}</Field>
          <Field label="Portas">{a.ports?.length ? a.ports.join(', ') : '—'}</Field>
          <Field label="Modo">{a.mode ?? 'fork'}</Field>
        </dl>
        <dl className="mt-3 grid gap-x-6 gap-y-2 border-t border-line pt-3 text-xs sm:grid-cols-2">
          <Field label="Script"><span className="font-mono">{a.execPath ?? '—'}</span></Field>
          <Field label="Diretório"><span className="font-mono">{a.cwd ?? '—'}</span></Field>
          <Field label="Usuário · PM2_HOME"><span className="font-mono">{a.user} · {a.pm2Home}</span></Field>
          <Field label="Node · versão do app"><span className="font-mono">{a.nodeVersion ?? '?'} · {a.version || '—'}</span></Field>
          <Field label="Log de erro"><span className="font-mono">{a.errLogPath ?? '—'}</span></Field>
          <Field label="Iniciado em">{a.startedAt ? fmtTime(a.startedAt) : '—'}</Field>
        </dl>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          <CommandBlock command={`${asUser}pm2 logs ${a.name} --lines 100 --nostream`} />
          <CommandBlock command={`${asUser}pm2 describe ${a.name}`} />
        </div>
      </Card>

      <Card title="Uso nas últimas horas"
        action={
          <div className="flex gap-1 font-mono text-[11px]">
            {[6, 24, 72].map((h) => (
              <button key={h} onClick={() => setHours(h)} className={`rounded-sm border px-2 py-0.5 ${h === hours ? 'border-hud text-ink' : 'border-transparent text-muted'}`}>{h}h</button>
            ))}
          </div>
        }>
        {chart.length < 2 ? <Empty>Ainda sem histórico suficiente (uma amostra a cada 30 s).</Empty> : (
          <div className="grid gap-4 lg:grid-cols-2">
            <MiniChart data={chart} dataKey="cpu" label="CPU %" />
            <MiniChart data={chart} dataKey="mem" label="Memória MB" />
          </div>
        )}
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={<><Siren size={13} aria-hidden /> Incidentes deste app ({incidents.length})</>}>
          {incidents.length === 0 && <Empty>Nenhum incidente ligado a este app.</Empty>}
          <ul className="divide-y divide-line">
            {incidents.map((i) => (
              <li key={i.id}>
                <Link to={`/incidents/${i.id}`} className="flex items-center gap-2 py-2 hover:bg-raised">
                  <SeverityBadge severity={i.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm">{i.title}</span>
                  <StatusBadge status={i.status} />
                  <span className="w-20 text-right text-xs text-muted">{timeAgo(i.lastSeen)}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card title={<><History size={13} aria-hidden /> Histórico no PM2 · 7 dias</>}>
          {events.length === 0 && <Empty>Sem mudanças de status ou reinícios registrados.</Empty>}
          <ol className="space-y-3">
            {events.map((e) => {
              const tail = Array.isArray(e.metadata?.errLogTail) ? (e.metadata!.errLogTail as string[]) : []
              return (
                <li key={e.id}>
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <span className="tnum font-mono text-xs text-muted">{fmtTime(e.occurredAt)}</span>
                    <span className="font-medium">{eventTypeLabel[e.type] ?? e.type}</span>
                    <span className="text-xs text-ink2">{e.message}</span>
                  </div>
                  {tail.length > 0 && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-xs text-hud">Log de erro no momento ({tail.length} linhas)</summary>
                      <pre className="mt-1 max-h-48 overflow-auto border border-line bg-page p-2 font-mono text-[11px] text-ink2">{tail.join('\n')}</pre>
                    </details>
                  )}
                </li>
              )
            })}
          </ol>
        </Card>
      </div>
    </div>
  )
}

function MiniChart({ data, dataKey, label }: { data: Record<string, unknown>[]; dataKey: string; label: string }) {
  return (
    <div>
      <p className="hud-label mb-1 text-[10px] text-muted">{label}</p>
      <div className="h-40">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 4, right: 4, left: -16, bottom: 0 }}>
            <CartesianGrid vertical={false} stroke="var(--line)" />
            <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={40} />
            <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} />
            <Tooltip cursor={{ stroke: 'var(--axis)' }} {...chartTooltip} />
            <Line dataKey={dataKey} name={label} stroke="var(--s1)" strokeWidth={2} dot={false} isAnimationActive={false} connectNulls
              activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="hud-label text-[10px] text-muted">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  )
}
