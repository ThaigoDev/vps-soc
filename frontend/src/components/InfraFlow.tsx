import { Suspense, lazy, useState } from 'react'
import { webglAvailable } from './three/support'
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'
import type { Host, ServiceView, Site } from '../api'

/*
 * Infrastructure path for one server, left to right, the way a request travels:
 *   Internet → Firewall → Server → Entrances (domains and public ports) → Applications
 * buildFlow() works out each piece and its state; InfraFlow lists the problems in words and
 * shows the same path as an interactive 3D model (three/AppArchitecture3D, loaded on demand).
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

const SUSPICIOUS_DIRS = ['/tmp/', '/var/tmp/', '/dev/shm/']

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

const ArchitectureView = lazy(() => import('./three/AppArchitecture3D'))

/** Problems in plain language, then the interactive 3D model of the same path. */
export function InfraFlow(props: FlowInput) {
  const data = buildFlow(props)
  const problems = data.nodes.filter((n) => n.problem)
  const [gl] = useState(webglAvailable)
  return (
    <div>
      {problems.length === 0 ? (
        <p className="mb-3 flex items-center gap-2 text-sm text-good"><CheckCircle2 size={16} aria-hidden /> Nenhum problema no caminho da internet até as aplicações.</p>
      ) : (
        <ul className="mb-4 space-y-1.5">
          {[...problems].sort((a, b) => (a.state === 'bad' ? 0 : 1) - (b.state === 'bad' ? 0 : 1)).map((n) => (
            <li key={n.id} className="flex items-start gap-2 text-sm">
              {n.state === 'bad'
                ? <XCircle size={16} className="mt-0.5 shrink-0 text-critical" aria-label="problema" />
                : <AlertTriangle size={16} className="mt-0.5 shrink-0 text-warning" aria-label="atenção" />}
              <span><span className="font-medium">{COLS[n.col]}:</span> {n.problem}</span>
            </li>
          ))}
        </ul>
      )}
      {gl ? (
        <Suspense fallback={<div className="flex h-[460px] items-center justify-center rounded-xl border border-line text-sm text-muted">Carregando modelo 3D…</div>}>
          <ArchitectureView data={data} />
        </Suspense>
      ) : (
        <ol className="grid gap-2 sm:grid-cols-5">
          {COLS.map((c, i) => (
            <li key={c} className="rounded-lg border border-line p-2 text-xs">
              <p className="mb-1 font-semibold text-muted">{c}</p>
              {data.nodes.filter((n) => n.col === i).map((n) => <p key={n.id}>{n.title} · {stateStyle[n.state].label}</p>)}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
