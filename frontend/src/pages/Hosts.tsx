import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type AttackMap, type Host, type MapServer, type MetricPoint, type ServiceView } from '../api'
import { Globe2, MapPin, Server, Workflow } from 'lucide-react'
import { InfraFlow } from '../components/InfraFlow'
import { WorldMap, countryName } from '../components/WorldMap'
import { Card, Empty, ErrorNote, PageHeader, chartTooltip, fmtBytes, fmtTime, timeAgo } from '../components/ui'
import { CheckList, postureChecks } from '../components/SocMetrics'

export default function Hosts() {
  const q = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: 10_000 })
  const map = useAttackMap(24)
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services'), refetchInterval: 10_000 })
  const { hash } = useLocation()
  useEffect(() => {
    if (!hash || !q.data) return
    document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [hash, q.data])

  return (
    <div className="space-y-5">
      <PageHeader icon={Server} title="Servidores"
        description="Onde ficam seus servidores, de onde vêm os ataques e o caminho que um acesso faz da internet até as aplicações. Logo abaixo, a ficha completa de cada servidor." />
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && (
        <Card><Empty>Nenhum servidor conectado ainda. Instale o agente na VPS (veja Ajuda → Como conectar uma VPS).</Empty></Card>
      )}
      {map.data && q.data && q.data.length > 0 && <MapCard data={map.data} hosts={q.data} />}
      {q.data?.map((h) => (
        <div key={h.id} id={h.id} className="scroll-mt-20 space-y-5">
          <Card title={<><Workflow size={16} className="text-muted" aria-hidden /> Arquitetura em 3D · {h.id}</>}
            description="O caminho de um acesso, da internet até as aplicações. Gire e clique nas peças: verde funciona, amarelo pede atenção, vermelho é onde está o problema.">
            <InfraFlow host={h} services={(services.data ?? []).filter((x) => x.hostId === h.id)} attackers={attackSummary(map.data)} />
          </Card>
          <HostCard host={h} geo={map.data?.servers.find((x) => x.hostId === h.id)} />
        </div>
      ))}
    </div>
  )
}

export function useAttackMap(hours: number) {
  return useQuery({ queryKey: ['map', hours], queryFn: () => api<AttackMap>(`/dashboard/map?hours=${hours}`), refetchInterval: 30_000 })
}

function attackSummary(m?: AttackMap) {
  if (!m) return undefined
  return {
    total: m.attackers.filter((a) => a.failures > 0).length,
    breached: m.attackers.filter((a) => a.failures > 0 && a.successes > 0).length,
    blocked: m.attackers.filter((a) => a.blocked).length,
  }
}

function MapCard({ data, hosts }: { data: AttackMap; hosts: Host[] }) {
  const navigate = useNavigate()
  const unknown = data.servers.filter((s) => !s.geo)
  const totalFailures = data.attackers.reduce((n, a) => n + a.failures, 0)
  const located = data.attackers.filter((a) => a.geo).length
  return (
    <Card title={<><Globe2 size={16} className="text-muted" aria-hidden /> Mapa · seus servidores e a origem dos ataques (24h)</>}
      description={`${data.attackers.length} endereço(s) tentaram entrar nos seus servidores, somando ${totalFailures.toLocaleString('pt-BR')} tentativas. As linhas mostram de onde vieram.`}>
      <div id="mapa" className="grid scroll-mt-20 gap-6 xl:grid-cols-[minmax(0,1fr)_300px]">
        <div>
          <WorldMap data={data} onSelectServer={(id) => navigate(`/hosts#${encodeURIComponent(id)}`)} />
          {!data.geoEnabled && <p className="mt-3 text-xs text-warning">A localização por IP está desligada (SOC_GEOIP_ENABLED=false): o mapa mostra só o que já estava salvo.</p>}
          {data.geoEnabled && data.pendingLookups > 0 && <p className="mt-3 text-xs text-muted">Localizando {data.pendingLookups} endereço(s)… o mapa se completa sozinho em alguns segundos.</p>}
          {data.geoEnabled && located === 0 && data.attackers.length > 0 && data.pendingLookups === 0 && (
            <p className="mt-3 text-xs text-muted">Não foi possível localizar os atacantes. O servidor do SOC precisa de acesso à internet para consultar a localização dos IPs.</p>
          )}
        </div>
        <div className="space-y-5">
          <div>
            <h3 className="mb-2 text-sm font-semibold">De onde vêm os ataques</h3>
            {data.countries.length === 0 && <p className="text-sm text-muted">Nenhum ataque localizado nas últimas 24h.</p>}
            <ul className="space-y-2.5">
              {data.countries.slice(0, 8).map((c) => {
                const max = data.countries[0].failures || 1
                return (
                  <li key={c.code}>
                    <div className="flex items-center justify-between gap-2 text-sm">
                      <span className="flex items-center gap-2">
                        <span className="w-7 rounded bg-raised py-0.5 text-center font-mono text-[11px] font-semibold text-ink2">{c.code}</span>
                        {countryName(c.code, c.name)}
                      </span>
                      <span className="tnum text-xs text-ink2">{c.failures.toLocaleString('pt-BR')}</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-raised">
                      <div className="h-full rounded-full" style={{ width: `${(c.failures / max) * 100}%`, background: c.successes ? 'var(--critical)' : 'var(--s2)' }} />
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>
          {unknown.map((s) => <LocationForm key={s.hostId} server={s} host={hosts.find((h) => h.id === s.hostId)} />)}
        </div>
      </div>
    </Card>
  )
}

/** Shown when the SOC does not know where a server is (old agent, or connected only through Tailscale). */
function LocationForm({ server, host }: { server: MapServer; host?: Host }) {
  const qc = useQueryClient()
  const [ip, setIp] = useState(host?.manualIp ?? '')
  const save = useMutation({
    mutationFn: () => api<MapServer>(`/hosts/${encodeURIComponent(server.hostId)}/location`, { method: 'PUT', body: JSON.stringify({ ip }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['map'] })
      qc.invalidateQueries({ queryKey: ['hosts'] })
    },
  })
  const waiting = server.publicIp && !server.geo
  return (
    <div className="rounded-lg border border-warning p-3">
      <p className="text-sm font-semibold">Onde fica {server.hostId}?</p>
      <p className="mt-0.5 text-xs text-ink2">
        {waiting
          ? `Localizando ${server.ip}…`
          : <>O SOC não sabe o IP público deste servidor. O jeito mais fácil: coloque no <code className="font-mono">.env</code> do SOC a linha <code className="font-mono">SOC_SERVER_PUBLIC_IP=SEU_IP</code> e rode <code className="font-mono">docker compose up -d</code>. Ou digite aqui:</>}
      </p>
      {!waiting && (
        <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); save.mutate() }}>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="ex.: 82.25.79.73" aria-label={`IP público de ${server.hostId}`}
            className="min-w-0 flex-1 rounded-lg border border-line bg-page px-2.5 py-1.5 font-mono text-xs" />
          <button disabled={save.isPending || !ip.trim()} className="rounded-lg bg-[var(--primary)] px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50">Salvar</button>
        </form>
      )}
      {save.error && <ErrorNote error={save.error} />}
    </div>
  )
}

function HostCard({ host: h, geo }: { host: Host; geo?: MapServer }) {
  const online = h.status === 'ONLINE'
  const m = h.metrics ?? {}
  return (
    <Card
      title={
        <span className="flex items-center gap-2">
          <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: online ? 'var(--good)' : 'var(--critical)' }} aria-hidden />
          <span className="text-base">{h.id}</span>
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${online ? 'text-good' : 'text-critical'}`} style={{ background: `color-mix(in srgb, ${online ? 'var(--good)' : 'var(--critical)'} 14%, transparent)` }}>
            {online ? 'Online' : `Offline · visto ${timeAgo(h.lastSeen)}`}
          </span>
        </span>
      }
      description={<HostWhere geo={geo} />}
      action={<span className="text-xs text-muted">{h.os} · agente {h.agentVersion}</span>}
    >
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
        <Gauge label="CPU" value={m.cpuPercent} />
        <Gauge label="Memória" value={m.memPercent} hint={fmtBytes(m.memTotalBytes)} />
        <Gauge label="Disco" value={m.diskPercent} hint={fmtBytes(m.diskTotalBytes)} warnAt={85} />
        <div>
          <p className="text-xs text-ink2" title="Média de processos esperando CPU no último minuto. Acima do número de núcleos = máquina sobrecarregada.">Carga (1 min)</p>
          <p className="tnum mt-1 text-2xl font-semibold">{m.load1?.toFixed(2) ?? '-'}</p>
        </div>
        <div>
          <p className="text-xs text-ink2">Ligado há</p>
          <p className="tnum mt-1 text-2xl font-semibold">{m.uptimeSeconds ? `${Math.floor(m.uptimeSeconds / 86400)}d ${Math.floor((m.uptimeSeconds % 86400) / 3600)}h` : '-'}</p>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 border-t border-line pt-4 sm:grid-cols-3 lg:grid-cols-6">
        <Figure label="Swap" value={m.swapPercent !== undefined ? `${m.swapPercent.toFixed(1)}%` : '-'} hint="uso alto = falta de RAM" />
        <Figure label="Rede ↓ entrada" value={fmtRate(m.netRxBps)} />
        <Figure label="Rede ↑ saída" value={fmtRate(m.netTxBps)} hint="pico inesperado: exfiltração ou DDoS saindo" />
        <Figure label="Conexões TCP" value={m.tcpEstablished ?? '-'} hint="estabelecidas agora" />
        <Figure label="Processos" value={m.processes ?? '-'} />
        <Figure label="Pessoas logadas" value={h.posture?.sessions?.length ?? '-'} hint="usuários logados (who)" />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <MetricsChart hostId={h.id} />
        <NetworkChart hostId={h.id} />
      </div>

      <div className="mt-5 grid gap-6 lg:grid-cols-2">
        <div>
          <h3 className="mb-1 text-sm font-semibold">Checklist de segurança</h3>
          <p className="mb-3 text-xs text-muted">Boas práticas verificadas automaticamente. Itens com X precisam de correção.</p>
          <CheckList checks={postureChecks(h)} />
          {h.response && (
            <p className="mt-3 text-xs text-muted">
              Resposta ativa no agente: {h.response.enabled ? 'ligada' : 'desligada'} · guarda local de brute force: {h.response.autoBlock ? 'ligada' : 'desligada'}
            </p>
          )}
        </div>
        <div>
          <h3 className="mb-1 text-sm font-semibold">Quem está logado agora ({h.posture?.sessions?.length ?? 0})</h3>
          <p className="mb-3 text-xs text-muted">Sessões abertas no terminal da VPS (comando who).</p>
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

      <h3 className="mt-6 text-sm font-semibold">Portas abertas ({h.openPorts?.length ?? 0})</h3>
      <p className="mb-2 text-xs text-muted">Programas esperando conexões. “Pública” = acessível pela internet; feche o que não precisa estar exposto.</p>
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
                      {p.address} {exposed && <span className="ml-1 rounded bg-raised px-1 font-sans text-xs text-ink2">pública</span>}
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

function HostWhere({ geo }: { geo?: MapServer }) {
  if (!geo?.geo) return <>Localização desconhecida{geo?.ip ? ` · ${geo.ip}` : ''}</>
  const g = geo.geo
  return (
    <span className="inline-flex items-center gap-1">
      <MapPin size={12} aria-hidden /> {[g.city, countryName(g.countryCode, g.country)].filter(Boolean).join(', ')}
      {g.org ? ` · ${g.org}` : ''} · IP {geo.ip}{geo.ipSource === 'ENV' ? ' (definido no .env)' : geo.ipSource === 'MANUAL' ? ' (definido no painel)' : ''}
    </span>
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
          <Tooltip cursor={{ stroke: 'var(--axis)' }} {...chartTooltip} />
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
      <p className="tnum mt-1 text-xl font-semibold">{value}</p>
      {hint && <p className="text-xs leading-tight text-muted">{hint}</p>}
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
