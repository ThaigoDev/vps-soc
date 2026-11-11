import { useNavigate } from 'react-router-dom'
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import type { Host, ServiceView, Site } from '../api'

/*
 * Infrastructure flow for one server, left to right, the way a request travels:
 *   Internet → Firewall → Server → Entrances (domains and public ports) → Applications
 * Every box is colored by its own state, and the links leading to a broken box turn red,
 * so "where is the problem" is visible at a glance. Plain SVG, no layout library.
 */

type State = 'ok' | 'warn' | 'bad' | 'off'

interface FlowNode {
  id: string
  col: number
  title: string
  detail: string
  state: State
  problem?: string
  to?: string
}

const stateStyle: Record<State, { color: string; label: string }> = {
  ok: { color: 'var(--good)', label: 'ok' },
  warn: { color: 'var(--warning)', label: 'atenção' },
  bad: { color: 'var(--critical)', label: 'problema' },
  off: { color: 'var(--muted)', label: 'sem dados' },
}

const COLS = ['Internet', 'Firewall', 'Servidor', 'Entradas', 'Aplicações']
const NW = 212
const NH = 60
const GAP_X = 44
const GAP_Y = 16
const TOP = 34

const SUSPICIOUS_DIRS = ['/tmp/', '/var/tmp/', '/dev/shm/']

function trunc(s: string, n: number) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s
}

export interface FlowInput {
  host: Host
  services: ServiceView[]
  attackers?: { total: number; breached: number; blocked: number }
}

export function buildFlow({ host, services, attackers }: FlowInput) {
  const nodes: FlowNode[] = []
  const links: [string, string][] = []
  const online = host.status === 'ONLINE'
  const p = host.posture
  const fw = p?.firewall
  const m = host.metrics ?? {}

  const atk = attackers ?? { total: 0, breached: 0, blocked: 0 }
  nodes.push({
    id: 'internet', col: 0, title: 'Internet',
    detail: atk.total ? `${atk.total} IP(s) atacando · 24h` : 'sem ataques nas últimas 24h',
    state: atk.breached ? 'bad' : atk.total ? 'warn' : 'ok',
    problem: atk.breached ? `${atk.breached} atacante(s) conseguiram fazer login` : undefined,
    to: '/hosts#mapa',
  })

  nodes.push({
    id: 'firewall', col: 1, title: 'Firewall',
    detail: fw?.enabled ? `${fw.blockedIps ?? 0} IP(s) bloqueado(s)` : fw ? 'desligado' : 'sem dados',
    state: !fw ? 'off' : fw.enabled ? 'ok' : 'warn',
    problem: fw && !fw.enabled ? 'Firewall do agente desligado: atacantes não são bloqueados' : undefined,
    to: '/response',
  })
  links.push(['internet', 'firewall'])

  const diskHigh = (m.diskPercent ?? 0) >= 90
  const failed = p?.failedUnits?.length ?? 0
  const serverProblem = !online ? 'Servidor parou de responder (agente offline)'
    : diskHigh ? `Disco quase cheio (${m.diskPercent?.toFixed(0)}%)`
      : failed ? `Serviço do sistema em falha: ${p!.failedUnits!.join(', ')}` : undefined
  nodes.push({
    id: 'server', col: 2, title: host.id,
    detail: online ? `CPU ${m.cpuPercent?.toFixed(0) ?? '-'}% · RAM ${m.memPercent?.toFixed(0) ?? '-'}% · Disco ${m.diskPercent?.toFixed(0) ?? '-'}%` : 'offline',
    state: !online ? 'bad' : diskHigh || failed ? 'warn' : 'ok',
    problem: serverProblem,
    to: `/hosts#${encodeURIComponent(host.id)}`,
  })
  links.push(['firewall', 'server'])

  // Entrances: nginx sites (deduplicated across apps) and other public ports.
  const sites = new Map<string, Site>()
  for (const s of services) for (const site of s.pm2.sites ?? []) sites.set(site.configFile + site.domains.join(','), site)
  const siteNodes: { node: FlowNode; ports: number[] }[] = []
  for (const site of sites.values()) {
    const end = site.certificate?.notAfter ? new Date(site.certificate.notAfter) : null
    const days = end ? Math.floor((end.getTime() - Date.now()) / 86_400_000) : null
    const state: State = !site.tls ? 'warn' : days !== null && days <= 7 ? 'bad' : days !== null && days <= 21 ? 'warn' : 'ok'
    const node: FlowNode = {
      id: `site-${site.configFile}-${site.domains[0]}`, col: 3, title: site.domains[0] ?? '(sem domínio)',
      detail: site.tls ? (days !== null ? `HTTPS · ${days < 0 ? 'certificado vencido' : `cert. vale ${days} dias`}` : 'HTTPS') : 'só HTTP (sem cadeado)',
      state,
      problem: !site.tls ? `${site.domains[0]} não usa HTTPS` : days !== null && days <= 21 ? `Certificado de ${site.domains[0]} ${days < 0 ? 'venceu' : `vence em ${days} dias`}` : undefined,
    }
    siteNodes.push({ node, ports: site.proxyPorts ?? [] })
    nodes.push(node)
    links.push(['server', node.id])
  }

  const passwordSsh = p?.ssh?.passwordAuthentication === 'yes'
  const exposed = (host.openPorts ?? []).filter((x) => x.address === '0.0.0.0' || x.address === '::')
  const seen = new Set<number>()
  for (const port of exposed) {
    if (seen.has(port.port)) continue
    seen.add(port.port)
    if (sites.size > 0 && (port.port === 80 || port.port === 443)) continue // shown as the sites
    const suspicious = !!port.exe && SUSPICIOUS_DIRS.some((d) => port.exe!.startsWith(d))
    const isSsh = port.process === 'sshd' || port.port === 22
    const state: State = suspicious ? 'bad' : isSsh && passwordSsh ? 'warn' : 'ok'
    const node: FlowNode = {
      id: `port-${port.port}`, col: 3, title: isSsh ? `SSH · porta ${port.port}` : `Porta ${port.port}`,
      detail: `${port.process ?? 'processo desconhecido'}${suspicious ? ' · em pasta temporária' : isSsh && passwordSsh ? ' · aceita senha' : ''}`,
      state,
      problem: suspicious ? `Porta ${port.port} aberta por programa suspeito (${port.exe})` : isSsh && passwordSsh ? 'SSH aceita login por senha (alvo de força bruta)' : undefined,
      to: `/hosts#${encodeURIComponent(host.id)}`,
    }
    nodes.push(node)
    links.push(['server', node.id])
  }

  for (const s of services) {
    const a = s.pm2
    const state: State = s.health === 'HEALTHY' ? 'ok' : s.health === 'DEGRADED' ? 'warn' : s.health === 'DOWN' ? 'bad' : 'off'
    const node: FlowNode = {
      id: `app-${a.pm2Home}-${a.pmId}`, col: 4, title: a.name,
      detail: s.health === 'DOWN' ? 'fora do ar' : a.probe?.ok ? `responde em ${a.probe.latencyMs} ms` : a.status,
      state,
      problem: state === 'bad' || state === 'warn' ? `${a.name}: ${s.reasons[0] ?? 'com problema'}` : undefined,
      to: `/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(a.name)}`,
    }
    nodes.push(node)
    // Link from the entrance that reaches it: a domain proxying to its port, a public port,
    // or (when nothing outside reaches it) an "internal only" box, so lines never skip a column.
    const from = siteNodes.filter((x) => x.ports.some((pt) => a.ports?.includes(pt)))
    const publicPort = (a.ports ?? []).map((pt) => `port-${pt}`).find((id) => nodes.some((x) => x.id === id))
    if (from.length) from.forEach((x) => links.push([x.node.id, node.id]))
    else if (publicPort) links.push([publicPort, node.id])
    else {
      const internal: FlowNode = {
        id: `internal-${node.id}`, col: 3, title: a.ports?.length ? `Porta ${a.ports.join(', ')}` : 'Sem porta',
        detail: a.ports?.length ? 'só acesso interno' : 'processo em segundo plano', state: 'ok',
      }
      nodes.push(internal)
      links.push(['server', internal.id], [internal.id, node.id])
    }
  }

  return { nodes, links }
}

export function InfraFlow(props: FlowInput) {
  const navigate = useNavigate()
  const { nodes, links } = buildFlow(props)
  const cols = COLS.map((_, c) => nodes.filter((n) => n.col === c))
  const rows = Math.max(...cols.map((c) => c.length), 1)
  const height = TOP + rows * NH + (rows - 1) * GAP_Y + 8
  const width = COLS.length * NW + (COLS.length - 1) * GAP_X

  const pos = new Map<string, { x: number; y: number }>()
  cols.forEach((col, c) => {
    const block = col.length * NH + (col.length - 1) * GAP_Y
    const start = TOP + (rows * NH + (rows - 1) * GAP_Y - block) / 2
    col.forEach((n, i) => pos.set(n.id, { x: c * (NW + GAP_X), y: start + i * (NH + GAP_Y) }))
  })
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const problems = nodes.filter((n) => n.problem)

  return (
    <div>
      {problems.length === 0 ? (
        <p className="mb-3 flex items-center gap-2 text-sm text-good"><CheckCircle2 size={16} aria-hidden /> Nenhum problema no caminho da internet até as aplicações.</p>
      ) : (
        <ul className="mb-4 space-y-1.5">
          {problems.sort((a, b) => (a.state === 'bad' ? 0 : 1) - (b.state === 'bad' ? 0 : 1)).map((n) => (
            <li key={n.id} className="flex items-start gap-2 text-sm">
              {n.state === 'bad'
                ? <XCircle size={16} className="mt-0.5 shrink-0 text-critical" aria-label="problema" />
                : <AlertTriangle size={16} className="mt-0.5 shrink-0 text-warning" aria-label="atenção" />}
              <span><span className="font-medium">{COLS[n.col]}:</span> {n.problem}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full min-w-[820px]" role="img"
          aria-label={`Fluxo da infraestrutura de ${props.host.id}: ${problems.length} ponto(s) com problema`}>
          {COLS.map((c, i) => (
            <text key={c} x={i * (NW + GAP_X) + NW / 2} y={14} textAnchor="middle" fontSize={12} fontWeight={600} fill="var(--muted)"
              style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {c}
            </text>
          ))}
          {links.map(([a, b]) => {
            const pa = pos.get(a), pb = pos.get(b), nb = byId.get(b)
            if (!pa || !pb || !nb) return null
            const x1 = pa.x + NW, y1 = pa.y + NH / 2, x2 = pb.x, y2 = pb.y + NH / 2
            const mx = (x1 + x2) / 2
            const broken = nb.state === 'bad'
            return (
              <path key={`${a}->${b}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none"
                stroke={broken ? 'var(--critical)' : nb.state === 'warn' ? 'var(--warning)' : 'var(--axis)'}
                strokeWidth={broken ? 2.2 : 1.6} strokeDasharray={broken ? '6 5' : undefined} className={broken ? 'flow-dash' : ''} />
            )
          })}
          {nodes.map((n) => {
            const p = pos.get(n.id)!
            const st = stateStyle[n.state]
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`} onClick={() => n.to && navigate(n.to)}
                className={n.to ? 'cursor-pointer' : ''} role={n.to ? 'link' : undefined}>
                <title>{`${n.title}: ${n.detail}${n.problem ? ` — ${n.problem}` : ''}`}</title>
                <rect width={NW} height={NH} rx={10} fill="var(--surface)" stroke={n.state === 'ok' || n.state === 'off' ? 'var(--line)' : st.color}
                  strokeWidth={n.state === 'bad' ? 2 : 1.2} />
                <rect width={5} height={NH - 16} x={0} y={8} rx={2.5} fill={st.color} />
                <circle cx={NW - 14} cy={14} r={5} fill={st.color} />
                <text x={16} y={25} fontSize={13.5} fontWeight={600} fill="var(--ink)">{trunc(n.title, 24)}</text>
                <text x={16} y={44} fontSize={11.5} fill="var(--ink-2)">{trunc(n.detail, 33)}</text>
              </g>
            )
          })}
        </svg>
      </div>
      <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-ink2">
        {(['ok', 'warn', 'bad'] as State[]).map((s) => (
          <li key={s} className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: stateStyle[s].color }} /> {stateStyle[s].label === 'ok' ? 'Funcionando' : stateStyle[s].label === 'atenção' ? 'Atenção' : 'Problema'}
          </li>
        ))}
        <li className="text-muted">Clique em uma caixa para ver os detalhes.</li>
      </ul>
    </div>
  )
}
