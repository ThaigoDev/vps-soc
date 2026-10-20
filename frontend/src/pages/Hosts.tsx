import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type Host, type MetricPoint } from '../api'
import { Card, Empty, ErrorNote, chartTooltip, fmtBytes, fmtTime, timeAgo } from '../components/ui'
import { CheckList, postureChecks } from '../components/SocMetrics'

export default function Hosts() {
  const q = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: 10_000 })
  if (q.error) return <ErrorNote error={q.error} />
  if (q.data && q.data.length === 0) {
    return (
      <Card title="Hosts">
        <Empty>Nenhum agente reportou ainda. Instale o agente na VPS (veja o README).</Empty>
      </Card>
    )
  }
  return <div className="space-y-4">{q.data?.map((h) => <HostCard key={h.id} host={h} />)}</div>
}

function HostCard({ host: h }: { host: Host }) {
  const online = h.status === 'ONLINE'
  const m = h.metrics ?? {}
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: online ? 'var(--good)' : 'var(--critical)' }} aria-hidden />
          {h.id}
          <span className="text-xs font-normal text-muted">{online ? 'Online' : 'Offline'} · visto {timeAgo(h.lastSeen)}</span>
        </span>
      }
      action={<span className="text-xs text-muted">{h.os} · agente {h.agentVersion}</span>}
    >
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <Gauge label="CPU" value={m.cpuPercent} />
        <Gauge label="Memória" value={m.memPercent} hint={fmtBytes(m.memTotalBytes)} />
        <Gauge label="Disco /" value={m.diskPercent} hint={fmtBytes(m.diskTotalBytes)} warnAt={85} />
        <div>
          <p className="text-xs text-ink2">Load (1m)</p>
          <p className="tnum mt-1 text-2xl font-semibold">{m.load1?.toFixed(2) ?? '-'}</p>
        </div>
        <div>
          <p className="text-xs text-ink2">Uptime</p>
          <p className="tnum mt-1 text-2xl font-semibold">{m.uptimeSeconds ? `${Math.floor(m.uptimeSeconds / 86400)}d ${Math.floor((m.uptimeSeconds % 86400) / 3600)}h` : '-'}</p>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 border-t border-line pt-4 sm:grid-cols-3 lg:grid-cols-6">
        <Figure label="Swap" value={m.swapPercent !== undefined ? `${m.swapPercent.toFixed(1)}%` : '-'} hint="uso alto = falta de RAM" />
        <Figure label="Rede ↓ entrada" value={fmtRate(m.netRxBps)} />
        <Figure label="Rede ↑ saída" value={fmtRate(m.netTxBps)} hint="pico inesperado: exfiltração ou DDoS saindo" />
        <Figure label="Conexões TCP" value={m.tcpEstablished ?? '-'} hint="estabelecidas agora" />
        <Figure label="Processos" value={m.processes ?? '-'} />
        <Figure label="Sessões abertas" value={h.posture?.sessions?.length ?? '-'} hint="usuários logados (who)" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <MetricsChart hostId={h.id} />
        <NetworkChart hostId={h.id} />
      </div>

      <div className="mt-5 grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="hud-label mb-2 text-[11px] font-semibold text-hud">Postura de segurança</h3>
          <CheckList checks={postureChecks(h)} />
          {h.response && (
            <p className="mt-3 text-xs text-muted">
              Resposta ativa no agente: {h.response.enabled ? 'ligada' : 'desligada'} · guarda local de brute force: {h.response.autoBlock ? 'ligada' : 'desligada'}
            </p>
          )}
        </div>
        <div>
          <h3 className="hud-label mb-2 text-[11px] font-semibold text-hud">Sessões interativas ({h.posture?.sessions?.length ?? 0})</h3>
          {h.posture?.sessions && h.posture.sessions.length > 0 ? (
            <ul className="space-y-1 font-mono text-xs">
              {h.posture.sessions.map((s) => (
                <li key={s.tty + s.loginAt} className="flex flex-wrap gap-x-3 border-b border-line py-1">
                  <span className="font-semibold">{s.user}</span>
                  <span className="text-ink2">{s.tty}</span>
                  <span className="text-ink2">{s.host || 'local'}</span>
                  <span className="ml-auto text-muted">{fmtTime(s.loginAt)}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">Ninguém logado agora.</p>
          )}
        </div>
      </div>

      <h3 className="mb-2 mt-5 text-sm font-semibold">Portas em escuta ({h.openPorts?.length ?? 0})</h3>
      {h.openPorts && h.openPorts.length > 0 ? (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[560px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 pb-1 font-normal">Porta</th>
                <th className="pb-1 font-normal">Endereço</th>
                <th className="pb-1 font-normal">Processo</th>
                <th className="pb-1 font-normal">Executável</th>
                <th className="px-4 pb-1 font-normal">Usuário</th>
              </tr>
            </thead>
            <tbody className="font-mono text-xs">
              {h.openPorts.map((p) => {
                const exposed = p.address === '0.0.0.0' || p.address === '::'
                return (
                  <tr key={`${p.proto}-${p.address}-${p.port}`} className="border-t border-line">
                    <td className="tnum px-4 py-1.5 font-semibold">{p.port}/{p.proto}</td>
                    <td className="py-1.5">
                      {p.address} {exposed && <span className="ml-1 rounded bg-raised px-1 font-sans text-[10px] text-ink2">pública</span>}
                    </td>
                    <td className="py-1.5">{p.process ?? '-'} {p.pid ? <span className="text-muted">({p.pid})</span> : null}</td>
                    <td className="max-w-xs truncate py-1.5 text-ink2">{p.exe ?? '-'}</td>
                    <td className="px-4 py-1.5">{p.user ?? '-'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>Sem dados de portas.</Empty>
      )}
    </Card>
  )
}

function Gauge({ label, value, hint, warnAt = 90 }: { label: string; value?: number; hint?: string; warnAt?: number }) {
  const color = value === undefined ? 'var(--muted)' : value >= warnAt ? 'var(--critical)' : value >= warnAt - 20 ? 'var(--warning)' : 'var(--good)'
  return (
    <div>
      <p className="text-xs text-ink2">{label} {hint && <span className="text-muted">· {hint}</span>}</p>
      <p className="tnum mt-1 text-2xl font-semibold">{value !== undefined ? `${value.toFixed(1)}%` : '-'}</p>
      <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-raised">
        <div className="h-full rounded-full" style={{ width: `${value ?? 0}%`, background: color }} />
      </div>
    </div>
  )
}

// Three percentage series on one 0-100 axis; categorical slots 1-3.
const lines = [
  { key: 'cpu', label: 'CPU %', color: 'var(--s1)' },
  { key: 'mem', label: 'Memória %', color: 'var(--s2)' },
  { key: 'disk', label: 'Disco %', color: 'var(--s3)' },
] as const

function MetricsChart({ hostId }: { hostId: string }) {
  const q = useQuery({
    queryKey: ['metrics', hostId],
    queryFn: () => api<MetricPoint[]>(`/hosts/${encodeURIComponent(hostId)}/metrics?hours=24`),
    refetchInterval: 30_000,
  })
  const data = q.data?.map((p) => ({ ...p, label: new Date(p.t).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }) }))
  if (!data || data.length < 2) return null
  return (
    <div className="mt-5 h-48">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 4, right: 4, left: -16, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--line)" />
          <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={40} />
          <YAxis domain={[0, 100]} tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip
            contentStyle={{ background: 'var(--surface)', border: '1px solid var(--line)', borderRadius: 6, fontSize: 12 }}
            labelStyle={{ color: 'var(--ink)', fontWeight: 600 }}
            itemStyle={{ color: 'var(--ink-2)' }}
            cursor={{ stroke: 'var(--axis)' }}
          />
          <Legend iconType="plainline" wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
          {lines.map((l) => (
            <Line key={l.key} dataKey={l.key} name={l.label} stroke={l.color} strokeWidth={2} dot={false} isAnimationActive={false}
              activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

function Figure({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div title={hint}>
      <p className="text-xs text-ink2">{label}</p>
      <p className="tnum mt-1 font-mono text-xl font-semibold">{value}</p>
      {hint && <p className="text-[10px] leading-tight text-muted">{hint}</p>}
    </div>
  )
}

function fmtRate(bps?: number): string {
  if (bps === undefined) return '-'
  if (bps < 1024) return `${bps.toFixed(0)} B/s`
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`
  return `${(bps / 1024 / 1024).toFixed(2)} MB/s`
}

// Network throughput in its own chart (different unit from the % chart: never a dual axis).
const netLines = [
  { key: 'rxKB', label: 'Entrada KB/s', color: 'var(--s1)' },
  { key: 'txKB', label: 'Saída KB/s', color: 'var(--s2)' },
] as const

function NetworkChart({ hostId }: { hostId: string }) {
  const q = useQuery({
    queryKey: ['metrics', hostId],
    queryFn: () => api<MetricPoint[]>(`/hosts/${encodeURIComponent(hostId)}/metrics?hours=24`),
    refetchInterval: 30_000,
  })
  const data = q.data
    ?.filter((p) => p.netRx !== undefined && p.netRx !== null)
    .map((p) => ({
      label: new Date(p.t).toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
      rxKB: Math.round(((p.netRx ?? 0) / 1024) * 10) / 10,
      txKB: Math.round(((p.netTx ?? 0) / 1024) * 10) / 10,
    }))
  if (!data || data.length < 2) return null
  return (
    <div className="mt-5 h-48">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 4, right: 4, left: -8, bottom: 0 }}>
          <CartesianGrid vertical={false} stroke="var(--line)" />
          <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={40} />
          <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} />
          <Tooltip cursor={{ stroke: 'var(--axis)' }} {...chartTooltip} />
          <Legend iconType="plainline" wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
          {netLines.map((l) => (
            <Line key={l.key} dataKey={l.key} name={l.label} stroke={l.color} strokeWidth={2} dot={false} isAnimationActive={false}
              activeDot={{ r: 4, stroke: 'var(--surface)', strokeWidth: 2 }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
