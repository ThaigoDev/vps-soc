import { useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Area, AreaChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowRight, Boxes, ChevronRight, Hourglass, Server, Siren } from 'lucide-react'
import { api, qs, type Host, type Incident, type Page, type SecurityEvent, type ServiceView, type SourceIpStats, type Summary, type TimelineBucket } from '../api'
import { ApprovalBanner, useKpis } from '../components/SocMetrics'
import { HealthBadge, healthOrder } from '../components/ServiceUi'
import { Card, Empty, ErrorNote, Hint, PageHeader, Segmented, SeverityBadge, chartTooltip, eventTypeLabel, severityStyle, threatLevel, timeAgo } from '../components/ui'

const REFRESH = 10_000

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
    <div className="space-y-5">
      <PageHeader title="Visão geral" description="O resumo do que está acontecendo nos seus servidores agora. Comece por aqui: se algo precisar de você, aparece em destaque." />
      {summary.error && <ErrorNote error={summary.error} />}
      <ApprovalBanner />
      {summary.data && <StatusHero s={summary.data} />}
      {summary.data && <KeyNumbers s={summary.data} />}

      <div className="grid gap-5 xl:grid-cols-3">
        <AttentionList incidents={active.data?.content} error={active.error} className="xl:col-span-2" />
        <ServersCard />
      </div>

      <Activity />

      <div className="grid gap-5 xl:grid-cols-3">
        <RecentEvents className="xl:col-span-2" />
        <TopIps />
      </div>
    </div>
  )
}

// ---- status --------------------------------------------------------------------------------

function StatusHero({ s }: { s: Summary }) {
  const t = threatLevel(s.openIncidents)
  const score = s.securityScore
  const scoreColor = score >= 80 ? 'var(--good)' : score >= 50 ? 'var(--warning)' : 'var(--critical)'
  const scoreLabel = score >= 80 ? 'Boa' : score >= 50 ? 'Em risco' : 'Crítica'
  const counts = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).filter((k) => (s.openIncidents[k] ?? 0) > 0)
  return (
    <section className={`grid gap-5 rounded-xl border p-5 md:grid-cols-[1fr_auto] ${t.level === 1 ? 'alarm-pulse' : ''}`}
      style={{ borderColor: `color-mix(in srgb, ${t.color} 55%, transparent)`, background: `color-mix(in srgb, ${t.color} 7%, var(--surface))` }}>
      <div className="flex items-start gap-4">
        <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full" style={{ background: `color-mix(in srgb, ${t.color} 18%, transparent)` }}>
          <t.Icon size={26} style={{ color: t.color }} aria-hidden />
        </span>
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider" style={{ color: t.color }}>Situação: {t.label}</p>
          <p className="mt-0.5 text-2xl font-semibold tracking-tight">{t.headline}</p>
          <p className="mt-1 text-sm text-ink2">
            {s.totalOpenIncidents === 0
              ? 'Nenhum incidente aberto. O SOC continua vigiando logins, arquivos, portas e processos.'
              : <>
                  {s.totalOpenIncidents} incidente{s.totalOpenIncidents === 1 ? '' : 's'} aberto{s.totalOpenIncidents === 1 ? '' : 's'}
                  {counts.length > 0 && <>: {counts.map((k) => `${s.openIncidents[k]} ${severityStyle[k].label.toLowerCase()}`).join(', ')}</>}.
                </>}
          </p>
          {s.totalOpenIncidents > 0 && (
            <Link to="/incidents" className="mt-3 inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold text-white hover:brightness-110"
              style={{ background: t.level <= 2 ? t.color : 'var(--primary)' }}>
              Ver incidentes <ArrowRight size={15} aria-hidden />
            </Link>
          )}
        </div>
      </div>
      <div className="flex items-center gap-4 border-t border-line pt-4 md:border-l md:border-t-0 md:pl-6 md:pt-0">
        <ScoreRing score={score} color={scoreColor} />
        <div>
          <p className="flex items-center gap-1.5 text-sm font-medium">
            Nota de segurança
            <Hint text="Começa em 100 e perde pontos para cada incidente aberto: 40 por crítico, 20 por alto, 5 por médio e 1 por baixo. Resolver incidentes faz a nota subir." />
          </p>
          <p className="text-sm font-semibold" style={{ color: scoreColor }}>{scoreLabel}</p>
          <p className="mt-0.5 text-xs text-muted">de 0 a 100</p>
        </div>
      </div>
    </section>
  )
}

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 30
  const len = 2 * Math.PI * r
  return (
    <svg viewBox="0 0 76 76" className="h-20 w-20 shrink-0" role="img" aria-label={`Nota de segurança ${score} de 100`}>
      <circle cx="38" cy="38" r={r} fill="none" stroke="var(--raised)" strokeWidth="8" />
      <circle cx="38" cy="38" r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
        strokeDasharray={`${(len * Math.max(score, 0)) / 100} ${len}`} transform="rotate(-90 38 38)" />
      <text x="38" y="44" textAnchor="middle" fill="var(--ink)" fontSize="20" fontWeight="700">{score}</text>
    </svg>
  )
}

function KeyNumbers({ s }: { s: Summary }) {
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services'), refetchInterval: REFRESH })
  const kpis = useKpis(30)
  const apps = services.data ?? []
  const appsBad = apps.filter((a) => a.health === 'DOWN' || a.health === 'DEGRADED').length
  const waiting = kpis.data?.actionsAwaitingApproval ?? 0
  const crit = (s.openIncidents.CRITICAL ?? 0) + (s.openIncidents.HIGH ?? 0)
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <NumberCard to="/incidents" Icon={Siren} label="Incidentes abertos" value={s.totalOpenIncidents}
        detail={crit > 0 ? `${crit} grave${crit === 1 ? '' : 's'} (alto ou crítico)` : 'nenhum grave'} tone={crit > 0 ? 'var(--critical)' : undefined} />
      <NumberCard to="/hosts" Icon={Server} label="Servidores online" value={`${s.hostsOnline} de ${s.hostsTotal}`}
        detail={s.hostsTotal === 0 ? 'nenhum agente instalado' : s.hostsOnline < s.hostsTotal ? 'algum servidor parou de responder' : 'todos respondendo'}
        tone={s.hostsOnline < s.hostsTotal ? 'var(--critical)' : undefined} />
      <NumberCard to="/services" Icon={Boxes} label="Aplicações com problema" value={appsBad}
        detail={apps.length === 0 ? 'nenhuma aplicação PM2' : `de ${apps.length} ${apps.length === 1 ? 'aplicação' : 'aplicações'}`}
        tone={appsBad > 0 ? 'var(--warning)' : undefined} />
      <NumberCard to="/response" Icon={Hourglass} label="Esperando sua aprovação" value={waiting}
        detail={waiting > 0 ? 'ações de defesa para aprovar' : 'nada pendente'} tone={waiting > 0 ? 'var(--warning)' : undefined} />
    </div>
  )
}

function NumberCard({ to, Icon, label, value, detail, tone }: { to: string; Icon: typeof Siren; label: string; value: number | string; detail: string; tone?: string }) {
  return (
    <Link to={to} className="group rounded-xl border border-line bg-surface p-4 hover:border-[var(--hud)]">
      <p className="flex items-center gap-2 text-sm text-ink2">
        <Icon size={16} className="text-muted" aria-hidden /> {label}
        <ChevronRight size={15} className="ml-auto text-muted opacity-0 transition-opacity group-hover:opacity-100" aria-hidden />
      </p>
      <p className="tnum mt-2 text-3xl font-semibold" style={tone ? { color: tone } : undefined}>
        {typeof value === 'number' ? value.toLocaleString('pt-BR') : value}
      </p>
      <p className="mt-0.5 text-xs text-muted">{detail}</p>
    </Link>
  )
}

// ---- what needs attention ------------------------------------------------------------------

function AttentionList({ incidents, error, className }: { incidents?: Incident[]; error: unknown; className?: string }) {
  const sorted = [...(incidents ?? [])].sort((a, b) =>
    (a.status === 'OPEN' ? 0 : 1) - (b.status === 'OPEN' ? 0 : 1) || b.riskScore - a.riskScore).slice(0, 6)
  return (
    <Card flush className={className} title="Precisa da sua atenção"
      description="Incidentes abertos, os mais perigosos primeiro. Clique para ver o que aconteceu e o que fazer."
      action={<Link to="/incidents" className="text-xs font-medium text-hud hover:underline">Ver todos</Link>}>
      {error ? <div className="px-4"><ErrorNote error={error} /></div> : null}
      {incidents && incidents.length === 0 && <Empty>Nada por aqui. Nenhum incidente aberto.</Empty>}
      <ul className="divide-y divide-line">
        {sorted.map((i) => (
          <li key={i.id}>
            <Link to={`/incidents/${i.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-raised">
              <SeverityBadge severity={i.severity} />
              <span className="min-w-0 flex-1">
                <span className="block truncate font-medium">{i.title}</span>
                <span className="block truncate text-xs text-muted">
                  {i.hostId}{i.sourceIp ? ` · de ${i.sourceIp}` : ''} · {timeAgo(i.lastSeen)}
                </span>
              </span>
              <span className={`hidden whitespace-nowrap rounded-full px-2 py-0.5 text-xs sm:inline ${i.status === 'OPEN' ? 'bg-raised font-semibold text-ink' : 'text-muted'}`}>
                {i.status === 'OPEN' ? 'Ninguém assumiu' : 'Em análise'}
              </span>
              <ChevronRight size={16} className="shrink-0 text-muted" aria-hidden />
            </Link>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function ServersCard() {
  const q = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: REFRESH })
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services'), refetchInterval: REFRESH })
  const apps = [...(services.data ?? [])].sort((a, b) => healthOrder[a.health] - healthOrder[b.health]).slice(0, 5)
  return (
    <Card title="Servidores e aplicações" description="Se cada máquina está respondendo e quanto recurso está usando."
      action={<Link to="/hosts" className="text-xs font-medium text-hud hover:underline">Detalhes</Link>}>
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && (
        <Empty>Nenhum servidor conectado ainda. Instale o agente na VPS (veja Ajuda).</Empty>
      )}
      <ul className="space-y-4">
        {q.data?.map((h) => {
          const online = h.status === 'ONLINE'
          const m = h.metrics ?? {}
          return (
            <li key={h.id}>
              <div className="flex items-center justify-between gap-2">
                <span className="flex min-w-0 items-center gap-2 font-medium">
                  <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${online ? 'live-dot' : ''}`} style={{ background: online ? 'var(--good)' : 'var(--critical)' }} aria-hidden />
                  <span className="truncate">{h.id}</span>
                </span>
                <span className={`text-xs ${online ? 'text-good' : 'font-semibold text-critical'}`}>
                  {online ? 'Online' : `Offline há ${timeAgo(h.lastSeen).replace(' atrás', '')}`}
                </span>
              </div>
              {online && (
                <div className="mt-2 grid grid-cols-3 gap-3">
                  <Meter label="CPU" value={m.cpuPercent} />
                  <Meter label="Memória" value={m.memPercent} />
                  <Meter label="Disco" value={m.diskPercent} warnAt={85} />
                </div>
              )}
            </li>
          )
        })}
      </ul>
      {apps.length > 0 && (
        <div className="mt-4 border-t border-line pt-3">
          <p className="mb-2 text-xs font-medium text-muted">Aplicações (PM2)</p>
          <ul className="space-y-1.5">
            {apps.map((a) => (
              <li key={`${a.hostId}-${a.pm2.pm2Home}-${a.pm2.pmId}`}>
                <Link to={`/services/${encodeURIComponent(a.hostId)}/${encodeURIComponent(a.pm2.name)}`} className="flex items-center gap-2 text-sm hover:text-hud">
                  <span className="min-w-0 flex-1 truncate">{a.pm2.name}</span>
                  <HealthBadge health={a.health} />
                </Link>
              </li>
            ))}
          </ul>
          {(services.data?.length ?? 0) > apps.length && (
            <Link to="/services" className="mt-2 block text-xs text-hud hover:underline">+ {(services.data?.length ?? 0) - apps.length} aplicação(ões)</Link>
          )}
        </div>
      )}
    </Card>
  )
}

function Meter({ label, value, warnAt = 90 }: { label: string; value?: number; warnAt?: number }) {
  const color = value === undefined ? 'var(--muted)' : value >= warnAt ? 'var(--critical)' : value >= warnAt - 20 ? 'var(--warning)' : 'var(--good)'
  return (
    <div title={`${label}: ${value?.toFixed(1) ?? '-'}%`}>
      <div className="flex justify-between text-xs">
        <span className="text-muted">{label}</span>
        <span className="tnum font-medium">{value !== undefined ? `${value.toFixed(0)}%` : '-'}</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-raised">
        <div className="h-full rounded-full" style={{ width: `${value ?? 0}%`, background: color }} />
      </div>
    </div>
  )
}

// ---- activity -------------------------------------------------------------------------------

/** Two series only: attacks on login vs. everything else. The full breakdown lives in Relatórios. */
function Activity() {
  const [hours, setHours] = useState(24)
  const q = useQuery({
    queryKey: ['timeline', hours],
    queryFn: () => api<TimelineBucket[]>(`/dashboard/timeline?hours=${hours}`),
    refetchInterval: REFRESH * 3,
  })
  const data = q.data?.map((b) => ({
    label: new Date(b.hour).toLocaleString('pt-BR', hours > 24 ? { day: '2-digit', month: '2-digit', hour: '2-digit' } : { hour: '2-digit', minute: '2-digit' }),
    ataques: b.authFailures,
    outros: b.authSuccesses + b.privilege + b.network + b.other + b.integrity,
  }))
  const total = data?.reduce((n, d) => n + d.ataques, 0) ?? 0
  return (
    <Card title="Atividade"
      description={`Tentativas de login que falharam (sinal de ataque) comparadas com o resto da atividade registrada. ${total.toLocaleString('pt-BR')} tentativas falhas no período.`}
      action={
        <div className="flex items-center gap-2">
          <Segmented label="Período" value={hours} onChange={setHours} options={[{ value: 24, label: '24 horas' }, { value: 168, label: '7 dias' }]} />
          <Link to="/reports" className="text-xs font-medium text-hud hover:underline">Mais gráficos</Link>
        </div>
      }>
      {q.error && <ErrorNote error={q.error} />}
      <div className="h-60">
        {data && (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 6, right: 6, left: -18, bottom: 0 }}>
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={32} />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip {...chartTooltip} />
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
              <Area type="monotone" dataKey="ataques" name="Logins que falharam" stroke="var(--s2)" fill="var(--s2)" fillOpacity={0.18} strokeWidth={2} isAnimationActive={false} />
              <Area type="monotone" dataKey="outros" name="Outros eventos" stroke="var(--s1)" fill="var(--s1)" fillOpacity={0.12} strokeWidth={2} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}

function RecentEvents({ className }: { className?: string }) {
  const q = useQuery({
    queryKey: ['events', 'live'],
    queryFn: () => api<Page<SecurityEvent>>('/events?size=8'),
    refetchInterval: 5_000,
  })
  return (
    <Card flush className={className} title="Últimos eventos" description="O que o agente registrou por último, em tempo real."
      action={<Link to="/events" className="text-xs font-medium text-hud hover:underline">Ver todos</Link>}>
      {q.error && <div className="px-4"><ErrorNote error={q.error} /></div>}
      {q.data && q.data.content.length === 0 && <Empty>Aguardando eventos do agente…</Empty>}
      <ul className="divide-y divide-line">
        {q.data?.content.map((e) => <EventLine key={e.id} e={e} />)}
      </ul>
    </Card>
  )
}

function EventLine({ e }: { e: SecurityEvent }): ReactNode {
  const st = severityStyle[e.severity]
  const who = [e.username && `usuário ${e.username}`, e.sourceIp && `IP ${e.sourceIp}`].filter(Boolean).join(' · ')
  const path = typeof e.metadata?.path === 'string' ? e.metadata.path : undefined
  return (
    <li className="flex items-center gap-3 px-4 py-2.5 text-sm">
      <st.Icon size={15} style={{ color: st.color }} aria-label={st.label} className="shrink-0" />
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium">{eventTypeLabel[e.type] ?? e.type}</span>
        <span className="block truncate text-xs text-muted">{path ?? (who || e.message || e.hostId)}</span>
      </span>
      <span className="tnum shrink-0 text-xs text-muted">{new Date(e.occurredAt).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}</span>
    </li>
  )
}

function TopIps() {
  const q = useQuery({ queryKey: ['top-ips'], queryFn: () => api<SourceIpStats[]>('/dashboard/top-ips?hours=24&limit=6'), refetchInterval: REFRESH })
  const max = Math.max(1, ...(q.data ?? []).map((r) => r.failures))
  return (
    <Card title="Quem mais tentou entrar · 24h" description="Endereços IP com mais tentativas de login que falharam.">
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && <Empty>Nenhuma tentativa de login nas últimas 24 horas.</Empty>}
      <ul className="space-y-3">
        {q.data?.map((r) => {
          const breached = r.successes > 0 && r.failures > 0
          return (
            <li key={r.ip} title={`${r.ip}: ${r.failures} falhas, ${r.successes} logins, ${r.usernames} usuários testados`}>
              <div className="flex items-center justify-between gap-2 text-sm">
                <Link to={`/events?ip=${encodeURIComponent(r.ip)}`} className="font-mono text-xs hover:text-hud">{r.ip}</Link>
                <span className="tnum text-xs text-ink2">
                  {r.failures.toLocaleString('pt-BR')} falhas
                  {breached && <span className="ml-1.5 font-semibold text-critical">· conseguiu entrar</span>}
                </span>
              </div>
              <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-raised">
                <div className="h-full rounded-full" style={{ width: `${(r.failures / max) * 100}%`, background: breached ? 'var(--critical)' : 'var(--s2)' }} />
              </div>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
