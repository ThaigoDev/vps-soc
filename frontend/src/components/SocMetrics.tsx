import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CheckCircle2, Gauge, Hourglass, ShieldAlert, Users, XCircle } from 'lucide-react'
import { api, type Host, type Kpis } from '../api'
import { Card, Empty, ErrorNote, chartTooltip } from './ui'
import { fmtDuration } from './ResponseUi'

export const ruleLabel: Record<string, string> = {
  SSH_BRUTE_FORCE: 'Brute force SSH',
  SSH_LOGIN_AFTER_BRUTE_FORCE: 'Login após brute force',
  SSH_ROOT_LOGIN: 'Login root',
  SSH_LOGIN_NEW_SOURCE: 'Login de IP novo',
  SUDO_FAILURE: 'Falha de sudo',
  NEW_LISTENING_PORT: 'Porta nova',
  FIM_AUTHORIZED_KEYS: 'authorized_keys',
  FIM_SSHD_CONFIG: 'sshd_config',
  FIM_SUDOERS: 'sudoers',
  FIM_CRON: 'cron',
  FIM_ACCOUNTS: 'contas (passwd)',
  SUSPICIOUS_PROCESS: 'Processo suspeito',
  WEB_SHELL: 'Web shell',
  AGENT_OFFLINE: 'Agente offline',
  DISK_USAGE_HIGH: 'Disco cheio',
  SERVICE_FAILED: 'Serviço em falha',
  SECURITY_UPDATES: 'Patches pendentes',
  REBOOT_REQUIRED: 'Reboot pendente',
  SSH_WEAK_CONFIG: 'SSH fraco',
  SERVICE_DOWN: 'App PM2 caiu',
  SERVICE_CRASH_LOOP: 'App PM2 em crash loop',
  SERVICE_HIGH_MEMORY: 'App PM2 com memória alta',
  SERVICE_VULNERABLE: 'Dependências vulneráveis',
  SERVICE_DEBUG_EXPOSED: 'Debugger do Node aberto',
  SERVICE_NOT_RESPONDING: 'App não responde',
  CERT_EXPIRING: 'Certificado TLS vencendo',
}

export function useKpis(days: number) {
  return useQuery({ queryKey: ['kpis', days], queryFn: () => api<Kpis>(`/dashboard/kpis?days=${days}`), refetchInterval: 30_000 })
}

/** Banner when containment actions are waiting for the operator. */
export function ApprovalBanner() {
  const q = useKpis(30)
  const n = q.data?.actionsAwaitingApproval ?? 0
  if (n === 0) return null
  return (
    <Link to="/response" className="panel flex items-center gap-3 border border-warning bg-surface px-4 py-3 hover:bg-raised">
      <Hourglass size={18} className="text-warning" aria-hidden />
      <span className="font-semibold">{n} ação{n === 1 ? '' : 'ões'} de resposta aguardando sua aprovação</span>
      <span className="hud-label ml-auto text-[10px] text-hud">Revisar →</span>
    </Link>
  )
}

/** SOC performance: mean times, automation, noise, exposure. */
export function SocKpis() {
  const [days, setDays] = useState(30)
  const q = useKpis(days)
  const k = q.data
  return (
    <Card title={<><Gauge size={13} aria-hidden /> Desempenho do SOC</>}
      action={
        <div className="flex gap-1 font-mono text-[11px]">
          {[7, 30, 90].map((d) => (
            <button key={d} onClick={() => setDays(d)} className={`rounded-sm border px-2 py-0.5 ${d === days ? 'border-hud text-ink' : 'border-transparent text-muted hover:text-ink2'}`}>{d}d</button>
          ))}
        </div>
      }>
      {q.error && <ErrorNote error={q.error} />}
      {k && (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Tile label="MTTD · detectar" value={fmtDuration(k.mttdSeconds)} hint="Da primeira evidência até virar incidente" />
            <Tile label="MTTA · reconhecer" value={fmtDuration(k.mttaSeconds)} hint="Do incidente até alguém assumir a análise" />
            <Tile label="MTTC · conter" value={fmtDuration(k.mttcSeconds)} hint="Do incidente até a ameaça ser contida (ex.: IP bloqueado)" />
            <Tile label="MTTR · resolver" value={fmtDuration(k.mttrSeconds)} hint="Do incidente até ser resolvido" />
          </div>
          <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
            <Small label="Incidentes" value={k.incidentsOpened} hint={`${k.incidentsResolved} resolvidos`} />
            <Small label="Backlog aberto" value={k.backlog} tone={k.backlog > 0 ? 'var(--serious)' : undefined} />
            <Small label="Contenção automática" value={pct(k.autoContainmentRate)} hint={`${k.containedAutomatically} de ${k.contained} contidos`} />
            <Small label="Falsos positivos" value={pct(k.falsePositiveRate)} hint={`${k.falsePositives} marcados`} />
            <Small label="IPs bloqueados" value={k.activeBlocks} />
            <Small label="Pacotes descartados" value={k.droppedPackets.toLocaleString('pt-BR')} hint="pelo firewall do agente" />
            <Small label="Eventos/min" value={k.eventsPerMinute.toFixed(1)} hint="média da última hora" />
            <Small label="Atraso dos dados" value={fmtDuration(k.maxDataLagSeconds)} hint="último contato do agente" tone={k.maxDataLagSeconds > 120 ? 'var(--critical)' : undefined} />
          </div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 border-t border-line pt-3 text-xs text-ink2">
            <span className="flex items-center gap-1"><CheckCircle2 size={12} className="text-good" aria-hidden /> {k.actionsAuto} ações automáticas</span>
            <span className="flex items-center gap-1"><Users size={12} className="text-hud" aria-hidden /> {k.actionsManual} manuais</span>
            <span className="flex items-center gap-1"><XCircle size={12} className="text-critical" aria-hidden /> {k.actionsFailed} falhas/recusas</span>
            <Link to="/response" className="flex items-center gap-1 hover:text-ink"><Hourglass size={12} className="text-warning" aria-hidden /> {k.actionsAwaitingApproval} aguardando aprovação</Link>
          </div>
        </>
      )}
    </Card>
  )
}

function Tile({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="border border-line bg-page p-3" title={hint}>
      <p className="hud-label text-[10px] text-muted">{label}</p>
      <p className="tnum mt-1 font-mono text-2xl font-bold">{value}</p>
      <p className="mt-0.5 text-[11px] leading-tight text-muted">{hint}</p>
    </div>
  )
}

function Small({ label, value, hint, tone }: { label: string; value: string | number; hint?: string; tone?: string }) {
  return (
    <div title={hint}>
      <p className="hud-label text-[10px] text-muted">{label}</p>
      <p className="tnum font-mono text-lg font-bold" style={tone ? { color: tone } : undefined}>{value}</p>
      {hint && <p className="text-[10px] leading-tight text-muted">{hint}</p>}
    </div>
  )
}

function pct(v: number) {
  return `${Math.round(v * 100)}%`
}

/** Opened vs closed per day: is the SOC keeping up? Two series, categorical slots 1 and 2. */
export function IncidentTrend({ className }: { className?: string }) {
  const q = useKpis(14)
  const data = q.data?.daily.map((d) => ({ ...d, label: d.day.slice(8, 10) + '/' + d.day.slice(5, 7) }))
  return (
    <Card fill className={className} title="Incidentes por dia · abertos × fechados">
      {q.error && <ErrorNote error={q.error} />}
      <div className="min-h-56 flex-1">
        {data && (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barGap={2} barCategoryGap="25%">
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip cursor={{ fill: 'var(--raised)' }} {...chartTooltip} />
              <Legend iconType="square" iconSize={10} wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
              <Bar dataKey="opened" name="Abertos" fill="var(--s1)" radius={[4, 4, 0, 0]} maxBarSize={18} />
              <Bar dataKey="closed" name="Fechados" fill="var(--s2)" radius={[4, 4, 0, 0]} maxBarSize={18} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}

/** Which detections fire most, and how noisy each one is. */
export function TopDetections() {
  const q = useKpis(30)
  const rules = q.data?.topRules ?? []
  const users = q.data?.topUsernames ?? []
  const max = Math.max(1, ...rules.map((r) => r.incidents))
  const umax = Math.max(1, ...users.map((u) => u.count))
  return (
    <Card title={<><ShieldAlert size={13} aria-hidden /> Detecções mais frequentes · 30d</>}>
      {q.data && rules.length === 0 && <Empty>Nenhum incidente no período.</Empty>}
      <ul className="space-y-2">
        {rules.map((r) => (
          <li key={r.ruleId} title={`${r.incidents} incidentes, ${r.falsePositives} falsos positivos`}>
            <div className="flex justify-between text-xs">
              <span>{ruleLabel[r.ruleId] ?? r.ruleId}</span>
              <span className="tnum font-mono text-ink2">{r.incidents}{r.falsePositives > 0 && <span className="text-muted"> · {r.falsePositives} FP</span>}</span>
            </div>
            <div className="mt-1 h-1.5 bg-raised">
              <div className="h-full rounded-r-[4px]" style={{ width: `${(r.incidents / max) * 100}%`, background: 'var(--s1)' }} />
            </div>
          </li>
        ))}
      </ul>
      {users.length > 0 && (
        <>
          <p className="hud-label mb-2 mt-4 border-t border-line pt-3 text-[10px] text-muted">Usuários mais atacados · 24h</p>
          <ul className="space-y-1.5">
            {users.map((u) => (
              <li key={u.name} className="flex items-center gap-2 text-xs">
                <span className="w-24 truncate font-mono">{u.name || '(vazio)'}</span>
                <div className="h-1.5 flex-1 bg-raised">
                  <div className="h-full rounded-r-[4px]" style={{ width: `${(u.count / umax) * 100}%`, background: 'var(--s2)' }} />
                </div>
                <span className="tnum w-10 text-right font-mono text-ink2">{u.count}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  )
}

type Check = { ok: boolean | null; label: string; detail: string }

/** Hardening checklist derived from the agent's posture report. */
export function postureChecks(h: Host): Check[] {
  const p = h.posture
  const ports = h.openPorts ?? []
  const exposed = ports.filter((x) => x.address === '0.0.0.0' || x.address === '::')
  const ssh = p?.ssh
  return [
    {
      ok: ssh ? ssh.passwordAuthentication === 'no' : null,
      label: 'SSH só com chave',
      detail: ssh ? `PasswordAuthentication ${ssh.passwordAuthentication ?? '?'}` : 'sem dados (sshd -T)',
    },
    {
      ok: ssh ? ssh.permitRootLogin !== 'yes' : null,
      label: 'Root sem senha',
      detail: ssh ? `PermitRootLogin ${ssh.permitRootLogin ?? '?'}` : 'sem dados',
    },
    {
      ok: p?.securityUpdates === undefined || p.securityUpdates < 0 ? null : p.securityUpdates === 0,
      label: 'Patches de segurança',
      detail: p?.securityUpdates === undefined || p.securityUpdates < 0 ? 'sem dados' : `${p.securityUpdates} pendentes (${p.pendingUpdates} no total)`,
    },
    { ok: p ? !p.rebootRequired : null, label: 'Sem reboot pendente', detail: p?.rebootRequired ? 'reinicialização necessária' : 'ok' },
    {
      ok: p?.failedUnits ? p.failedUnits.length === 0 : null,
      label: 'Serviços rodando',
      detail: p?.failedUnits?.length ? `em falha: ${p.failedUnits.join(', ')}` : 'nenhum em falha',
    },
    {
      ok: p?.firewall ? !!p.firewall.enabled : null,
      label: 'Firewall do agente',
      detail: p?.firewall?.enabled ? `${p.firewall.blockedIps ?? 0} IPs bloqueados` : 'nftables indisponível',
    },
    { ok: exposed.length <= 3, label: 'Superfície exposta', detail: `${exposed.length} porta(s) pública(s): ${exposed.map((x) => x.port).join(', ') || '—'}` },
  ]
}

export function CheckList({ checks }: { checks: Check[] }) {
  return (
    <ul className="space-y-1.5">
      {checks.map((c) => (
        <li key={c.label} className="flex items-start gap-2 text-sm">
          {c.ok === null ? <span className="mt-0.5 h-3.5 w-3.5 shrink-0 rounded-full border border-muted" aria-label="sem dados" />
            : c.ok ? <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-good" aria-label="ok" />
              : <XCircle size={15} className="mt-0.5 shrink-0 text-critical" aria-label="atenção" />}
          <span>
            <span className={c.ok === false ? 'font-semibold' : ''}>{c.label}</span>
            <span className="block text-xs text-muted">{c.detail}</span>
          </span>
        </li>
      ))}
    </ul>
  )
}
