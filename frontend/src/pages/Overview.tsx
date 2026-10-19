import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Crosshair, Server, Terminal } from 'lucide-react'
import { api, qs, type Host, type Incident, type Page, type SecurityEvent, type Severity, type SourceIpStats, type Summary, type TimelineBucket } from '../api'
import { MitreMatrix } from '../components/MitreMatrix'
import { Card, Empty, ErrorNote, RiskBar, SeverityBadge, chartTooltip, eventTypeLabel, severityStyle, threatLevel, timeAgo } from '../components/ui'

const REFRESH = 10_000

// Categorical slots 1..6 in validated order (adjacent pairs checked on the dark surface);
// color follows the category, never its rank.
const series = [
  { key: 'authFailures', label: 'Falhas de autenticação', color: 'var(--s1)' },
  { key: 'authSuccesses', label: 'Logins', color: 'var(--s2)' },
  { key: 'privilege', label: 'Privilégio (sudo)', color: 'var(--s3)' },
  { key: 'network', label: 'Rede (portas)', color: 'var(--s4)' },
  { key: 'other', label: 'Agente', color: 'var(--s5)' },
  { key: 'integrity', label: 'Arquivos / processos', color: 'var(--s6)' },
] as const

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function useActiveIncidents() {
  // Same key as the alert watcher, so both share one request.
  return useQuery({
    queryKey: ['incidents', 'alert-watch'],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status: 'OPEN,ACKNOWLEDGED', size: 100 })}`),
    refetchInterval: 5_000,
  })
}

export default function Overview() {
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary'), refetchInterval: REFRESH })
  const active = useActiveIncidents()

  return (
    <div className="space-y-4">
      {summary.error && <ErrorNote error={summary.error} />}
      {summary.data && <Headline s={summary.data} />}
      <div className="grid gap-4 xl:grid-cols-3">
        <Timeline className="xl:col-span-2" />
        <SeverityPanel s={summary.data} />
      </div>
      <Card title={<><Crosshair size={13} aria-hidden /> Matriz MITRE ATT&amp;CK · incidentes ativos</>}>
        {active.error && <ErrorNote error={active.error} />}
        {active.data && <MitreMatrix incidents={active.data.content} />}
      </Card>
      <div className="grid gap-4 xl:grid-cols-3">
        <IncidentQueue incidents={active.data?.content} className="xl:col-span-2" />
        <TopIps />
      </div>
      <div className="grid gap-4 xl:grid-cols-3">
        <AssetHealth />
        <LiveFeed className="xl:col-span-2" />
      </div>
    </div>
  )
}

// ---- headline ------------------------------------------------------------------------------

function Headline({ s }: { s: Summary }) {
  const t = threatLevel(s.openIncidents)
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(0,2.2fr)]">
      <section className={`panel border bg-surface p-4 ${t.level === 1 ? 'alarm-pulse' : ''}`} style={{ borderColor: t.color }}>
        <p className="hud-label text-muted">Nível de ameaça</p>
        <div className="mt-2 flex items-center gap-4">
          <span className="tnum font-mono text-6xl font-bold leading-none" style={{ color: t.color }}>{t.level}</span>
          <div>
            <p className="flex items-center gap-1.5 text-xl font-semibold uppercase tracking-wide">
              <t.Icon size={20} style={{ color: t.color }} aria-hidden />
              {t.label}
            </p>
            <p className="mt-0.5 text-xs text-ink2">{t.hint}</p>
          </div>
        </div>
        <LevelScale level={t.level} />
      </section>
      <section className="panel border border-line bg-surface p-4">
        <p className="hud-label text-muted">Postura de segurança</p>
        <ScoreArc score={s.securityScore} />
      </section>
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Stat label="Incidentes ativos" value={s.totalOpenIncidents} tone={s.totalOpenIncidents > 0 ? 'var(--serious)' : undefined} />
        <Stat label="Críticos" value={s.openIncidents.CRITICAL ?? 0} tone={(s.openIncidents.CRITICAL ?? 0) > 0 ? 'var(--critical)' : undefined} />
        <Stat label="Hosts online" value={`${s.hostsOnline}/${s.hostsTotal}`} tone={s.hostsOnline < s.hostsTotal ? 'var(--critical)' : undefined} />
        <Stat label="Falhas de login · 24h" value={s.authFailures24h} />
        <Stat label="IPs atacantes · 24h" value={s.attackerIps24h} />
        <Stat label="Eventos · 24h" value={s.events24h} />
      </div>
    </div>
  )
}

/** Five segments, 5 (normal) to 1 (critical), the current one highlighted. */
function LevelScale({ level }: { level: number }) {
  const colors = ['var(--critical)', 'var(--serious)', 'var(--warning)', 'var(--good)', 'var(--good)']
  return (
    <div className="mt-4 flex gap-1" aria-hidden>
      {[5, 4, 3, 2, 1].map((n) => (
        <div key={n} className="flex-1">
          <div className="h-1.5" style={{ background: colors[n - 1], opacity: n === level ? 1 : 0.18 }} />
          <p className={`mt-1 text-center font-mono text-[10px] ${n === level ? 'text-ink' : 'text-muted'}`}>{n}</p>
        </div>
      ))}
    </div>
  )
}

function ScoreArc({ score }: { score: number }) {
  const color = score >= 80 ? 'var(--good)' : score >= 50 ? 'var(--warning)' : 'var(--critical)'
  const label = score >= 80 ? 'Saudável' : score >= 50 ? 'Em risco' : 'Crítica'
  // Half circle, radius 70, length π·r.
  const len = Math.PI * 70
  return (
    <div className="mt-1 flex flex-col items-center">
      <svg viewBox="0 0 180 104" className="w-full max-w-[220px]" role="img" aria-label={`Security score ${score} de 100, ${label}`}>
        <path d="M20 94 A70 70 0 0 1 160 94" fill="none" stroke="var(--raised)" strokeWidth="12" strokeLinecap="round" />
        <path d="M20 94 A70 70 0 0 1 160 94" fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${(len * Math.max(score, 0)) / 100} ${len}`} />
        <text x="90" y="82" textAnchor="middle" fill="var(--ink)" fontSize="34" fontWeight="700" fontFamily="ui-monospace, monospace">{score}</text>
        <text x="90" y="100" textAnchor="middle" fill="var(--muted)" fontSize="10" fontFamily="ui-monospace, monospace">/ 100</text>
      </svg>
      <p className="hud-label mt-1 font-semibold" style={{ color }}>{label}</p>
    </div>
  )
}

function Stat({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <div className="panel border border-line bg-surface p-3" style={tone ? { borderColor: tone } : undefined}>
      <p className="hud-label text-[10px] text-muted">{label}</p>
      <p className="tnum mt-1 font-mono text-3xl font-bold" style={tone ? { color: tone } : undefined}>
        {typeof value === 'number' ? value.toLocaleString('pt-BR') : value}
      </p>
    </div>
  )
}

// ---- charts ----------------------------------------------------------------------------------

function Timeline({ className }: { className?: string }) {
  const [hours, setHours] = useState(24)
  const [asTable, setAsTable] = useState(false)
  const q = useQuery({
    queryKey: ['timeline', hours],
    queryFn: () => api<TimelineBucket[]>(`/dashboard/timeline?hours=${hours}`),
    refetchInterval: REFRESH * 3,
  })
  const data = q.data?.map((b) => ({ ...b, label: new Date(b.hour).toLocaleString('pt-BR', hours > 24 ? { day: '2-digit', hour: '2-digit' } : { hour: '2-digit', minute: '2-digit' }) }))
  return (
    <Card
      className={className}
      title="Atividade por hora"
      action={
        <div className="flex gap-1">
          <button onClick={() => setAsTable(!asTable)} aria-pressed={asTable}
            className={`hud-label mr-2 rounded-sm border px-2 py-0.5 text-[10px] ${asTable ? 'border-hud text-ink' : 'border-line text-muted hover:text-ink2'}`}>
            {asTable ? 'Gráfico' : 'Tabela'}
          </button>
          {[24, 72, 168].map((h) => (
            <button key={h} onClick={() => setHours(h)} aria-pressed={h === hours}
              className={`hud-label rounded-sm border px-2 py-0.5 text-[10px] ${h === hours ? 'border-hud text-ink' : 'border-line text-muted hover:text-ink2'}`}>
              {h === 168 ? '7d' : `${h}h`}
            </button>
          ))}
        </div>
      }
    >
      {q.error && <ErrorNote error={q.error} />}
      {asTable && data && <TimelineTable rows={data} />}
      <div className={asTable ? 'hidden' : 'h-72'}>
        {data && (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -16, bottom: 0 }} barCategoryGap={2}>
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={24} />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip cursor={{ fill: 'var(--raised)' }} {...chartTooltip} />
              <Legend iconType="square" iconSize={10} wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
              {series.map((s, i) => (
                <Bar key={s.key} dataKey={s.key} name={s.label} stackId="a" fill={s.color} stroke="var(--surface)" strokeWidth={1}
                  radius={i === series.length - 1 ? [4, 4, 0, 0] : 0} maxBarSize={28} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}

/** Same data as the chart, for exact numbers and for colors that are hard to tell apart. */
function TimelineTable({ rows }: { rows: (TimelineBucket & { label: string })[] }) {
  const busy = rows.filter((r) => series.some((s) => r[s.key] > 0)).reverse()
  if (busy.length === 0) return <Empty>Sem eventos no período.</Empty>
  return (
    <div className="-mx-4 h-72 overflow-auto">
      <table className="w-full min-w-[640px] text-xs">
        <thead className="sticky top-0 bg-surface">
          <tr className="text-left text-muted">
            <th className="px-4 pb-2 font-normal">Hora</th>
            {series.map((s) => (
              <th key={s.key} className="pb-2 pr-3 text-right font-normal">
                <span className="mr-1 inline-block h-2 w-2" style={{ background: s.color }} aria-hidden />{s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="tnum font-mono">
          {busy.map((r) => (
            <tr key={r.hour} className="border-t border-line">
              <td className="px-4 py-1 text-ink2">{r.label}</td>
              {series.map((s) => (
                <td key={s.key} className={`py-1 pr-3 text-right ${r[s.key] ? 'text-ink' : 'text-muted'}`}>{r[s.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Open incidents by severity: status colors, always with icon + label. */
function SeverityPanel({ s }: { s?: Summary }) {
  const counts = SEVERITIES.map((sev) => ({ sev, n: s?.openIncidents[sev] ?? 0 }))
  const max = Math.max(1, ...counts.map((c) => c.n))
  return (
    <Card title="Incidentes ativos por severidade">
      <ul className="space-y-3">
        {counts.map(({ sev, n }) => {
          const st = severityStyle[sev]
          return (
            <li key={sev} title={`${st.label}: ${n} incidente(s) ativo(s)`}>
              <div className="mb-1 flex items-center justify-between text-sm">
                <span className="flex items-center gap-1.5">
                  <st.Icon size={14} style={{ color: st.color }} aria-hidden />
                  {st.label}
                </span>
                <span className="tnum font-mono font-semibold">{n}</span>
              </div>
              <div className="h-2.5 bg-raised">
                <div className="h-full rounded-r-[4px]" style={{ width: `${(n / max) * 100}%`, background: st.color, minWidth: n > 0 ? 4 : 0 }} />
              </div>
            </li>
          )
        })}
      </ul>
      {s && (
        <p className="mt-4 border-t border-line pt-3 text-xs text-ink2">
          Score atual {s.securityScore}/100. Cada incidente aberto tira 40 / 20 / 5 / 1 pontos (crítico / alto / médio / baixo).
        </p>
      )}
    </Card>
  )
}

// ---- tables & feeds ------------------------------------------------------------------------

function IncidentQueue({ incidents, className }: { incidents?: Incident[]; className?: string }) {
  const sorted = [...(incidents ?? [])].sort((a, b) =>
    (a.status === 'OPEN' ? 0 : 1) - (b.status === 'OPEN' ? 0 : 1) || b.riskScore - a.riskScore).slice(0, 10)
  return (
    <Card className={className} title="Fila de resposta" action={<Link to="/incidents" className="hud-label text-[10px] text-hud hover:underline">Todos</Link>}>
      {incidents && incidents.length === 0 && <Empty>Nenhum incidente ativo. Situação normal.</Empty>}
      {sorted.length > 0 && (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="hud-label text-left text-[10px] text-muted">
                <th className="px-4 pb-2 font-normal">Sev</th>
                <th className="pb-2 font-normal">Incidente</th>
                <th className="pb-2 font-normal">Host</th>
                <th className="pb-2 font-normal">Estado</th>
                <th className="pb-2 font-normal">Risco</th>
                <th className="px-4 pb-2 text-right font-normal">Último</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((i) => (
                <tr key={i.id} className="border-t border-line hover:bg-raised">
                  <td className="px-4 py-1.5"><SeverityBadge severity={i.severity} /></td>
                  <td className="max-w-0 py-1.5">
                    <Link to={`/incidents/${i.id}`} className="block truncate hover:text-hud">{i.title}</Link>
                  </td>
                  <td className="py-1.5 font-mono text-xs text-ink2">{i.hostId}</td>
                  <td className="py-1.5">
                    <span className={`hud-label text-[10px] ${i.status === 'OPEN' ? 'font-bold text-critical' : 'text-ink2'}`}>
                      {i.status === 'OPEN' ? 'Sem resposta' : 'Em análise'}
                    </span>
                  </td>
                  <td className="py-1.5"><RiskBar value={i.riskScore} /></td>
                  <td className="tnum px-4 py-1.5 text-right text-xs text-muted">{timeAgo(i.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function TopIps() {
  const q = useQuery({ queryKey: ['top-ips'], queryFn: () => api<SourceIpStats[]>('/dashboard/top-ips?hours=24&limit=8'), refetchInterval: REFRESH })
  const max = Math.max(1, ...(q.data ?? []).map((r) => r.failures))
  return (
    <Card title="Origens hostis · 24h">
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && <Empty>Sem tráfego de autenticação.</Empty>}
      {q.data && q.data.length > 0 && (
        <ul className="space-y-2">
          {q.data.map((r) => {
            const breached = r.successes > 0 && r.failures > 0
            return (
              <li key={r.ip} title={`${r.ip}: ${r.failures} falhas, ${r.successes} logins, ${r.usernames} usuários testados`}>
                <div className="flex items-center justify-between gap-2 text-xs">
                  <Link to={`/events?ip=${encodeURIComponent(r.ip)}`} className="font-mono hover:text-hud">{r.ip}</Link>
                  <span className="tnum font-mono text-ink2">
                    {r.failures} falhas · {r.usernames} usr
                    {breached && <span className="ml-1.5 font-bold text-critical">· {r.successes} LOGIN</span>}
                  </span>
                </div>
                <div className="mt-1 h-1.5 bg-raised">
                  <div className="h-full rounded-r-[4px]" style={{ width: `${(r.failures / max) * 100}%`, background: 'var(--s1)' }} />
                </div>
              </li>
            )
          })}
        </ul>
      )}
    </Card>
  )
}

function AssetHealth() {
  const q = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: REFRESH })
  return (
    <Card title={<><Server size={13} aria-hidden /> Ativos monitorados</>} action={<Link to="/hosts" className="hud-label text-[10px] text-hud hover:underline">Detalhes</Link>}>
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && <Empty>Nenhum agente reportou ainda.</Empty>}
      <ul className="space-y-4">
        {q.data?.map((h) => {
          const online = h.status === 'ONLINE'
          const m = h.metrics ?? {}
          return (
            <li key={h.id}>
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2 font-mono text-sm font-semibold">
                  <span className={`inline-block h-2 w-2 rounded-full ${online ? 'live-dot' : ''}`} style={{ background: online ? 'var(--good)' : 'var(--critical)' }} aria-hidden />
                  {h.id}
                </span>
                <span className={`hud-label text-[10px] ${online ? 'text-good' : 'font-bold text-critical'}`}>
                  {online ? 'Online' : `Offline · ${timeAgo(h.lastSeen)}`}
                </span>
              </div>
              {online && (
                <div className="mt-2 grid grid-cols-3 gap-3">
                  <Meter label="CPU" value={m.cpuPercent} />
                  <Meter label="RAM" value={m.memPercent} />
                  <Meter label="Disco" value={m.diskPercent} warnAt={85} />
                </div>
              )}
              <p className="mt-1.5 font-mono text-[11px] text-muted">
                {h.openPorts?.length ?? 0} portas · {h.os ?? '?'}
              </p>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}

function Meter({ label, value, warnAt = 90 }: { label: string; value?: number; warnAt?: number }) {
  const color = value === undefined ? 'var(--muted)' : value >= warnAt ? 'var(--critical)' : value >= warnAt - 20 ? 'var(--warning)' : 'var(--good)'
  return (
    <div title={`${label}: ${value?.toFixed(1) ?? '-'}%`}>
      <div className="flex justify-between font-mono text-[10px]">
        <span className="text-muted">{label}</span>
        <span className="tnum text-ink">{value !== undefined ? `${value.toFixed(0)}%` : '-'}</span>
      </div>
      <div className="mt-1 h-1.5 bg-raised">
        <div className="h-full" style={{ width: `${value ?? 0}%`, background: color }} />
      </div>
    </div>
  )
}

function LiveFeed({ className }: { className?: string }) {
  const q = useQuery({
    queryKey: ['events', 'live'],
    queryFn: () => api<Page<SecurityEvent>>('/events?size=18'),
    refetchInterval: 5_000,
  })
  return (
    <Card className={className} title={<><Terminal size={13} aria-hidden /> Feed ao vivo</>} action={<Link to="/events" className="hud-label text-[10px] text-hud hover:underline">Explorar</Link>}>
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.content.length === 0 && <Empty>Aguardando eventos do agente…</Empty>}
      <ol className="-mx-4 -my-2 font-mono text-xs">
        {q.data?.content.map((e) => (
          <FeedLine key={e.id} e={e} />
        ))}
      </ol>
    </Card>
  )
}

function FeedLine({ e }: { e: SecurityEvent }): ReactNode {
  const st = severityStyle[e.severity]
  const who = [e.username, e.sourceIp].filter(Boolean).join('@')
  const path = typeof e.metadata?.path === 'string' ? e.metadata.path : undefined
  return (
    <li className="flex items-center gap-2 border-t border-line px-4 py-1 first:border-t-0 hover:bg-raised">
      <span className="tnum shrink-0 text-muted">{new Date(e.occurredAt).toLocaleTimeString('pt-BR')}</span>
      <span className="flex w-16 shrink-0 items-center gap-1" title={st.label}>
        <st.Icon size={11} style={{ color: st.color }} aria-hidden />
        <span className="text-[10px] uppercase text-ink2">{st.label.slice(0, 4)}</span>
      </span>
      <span className="w-36 shrink-0 truncate text-ink">{eventTypeLabel[e.type] ?? e.type}</span>
      <span className="min-w-0 flex-1 truncate text-ink2">{path ?? (who || e.message)}</span>
      <span className="hidden shrink-0 text-muted lg:block">{e.hostId}</span>
    </li>
  )
}
