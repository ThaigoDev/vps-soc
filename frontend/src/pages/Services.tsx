import { useNavigate } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Boxes, Workflow } from 'lucide-react'
import { InfraFlow } from '../components/InfraFlow'
import { useAttackMap } from './Hosts'
import { api, type Host, type ServiceView } from '../api'
import { Card, Empty, ErrorNote, PageHeader, SeverityBadge, timeAgo } from '../components/ui'
import { HealthBadge, ScoreBadge, VulnCounts, fmtMb, fmtUptime, healthOrder } from '../components/ServiceUi'

export function useServices() {
  return useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services'), refetchInterval: 10_000 })
}

export default function Services() {
  const q = useServices()
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts'), refetchInterval: 30_000 })
  const navigate = useNavigate()
  const list = [...(q.data ?? [])].sort((a, b) =>
    healthOrder[a.health] - healthOrder[b.health] || a.hostId.localeCompare(b.hostId) || a.pm2.pmId - b.pm2.pmId)
  const count = (h: ServiceView['health']) => list.filter((s) => s.health === h).length
  const multiHost = new Set(list.map((s) => s.hostId)).size > 1
  const map = useAttackMap(24)
  const attack = map.data ? {
    total: map.data.attackers.filter((a) => a.failures > 0).length,
    breached: map.data.attackers.filter((a) => a.failures > 0 && a.successes > 0).length,
    blocked: map.data.attackers.filter((a) => a.blocked).length,
  } : undefined
  const pm2Problems = (hosts.data ?? []).filter((h) => h.pm2?.error || (h.pm2 && (h.pm2.daemons?.length ?? 0) === 0))

  return (
    <div className="space-y-5">
      <PageHeader icon={Boxes} title="Aplicações"
        description="Os sites e APIs Node.js que rodam na VPS pelo PM2. Mostra se cada um está no ar, se responde rápido, se está reiniciando sem parar, e se tem dependências com falhas de segurança conhecidas." />
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Tile label="Aplicações" value={list.length} />
        <Tile label="Saudáveis" value={count('HEALTHY')} tone="var(--good)" />
        <Tile label="Instáveis" value={count('DEGRADED')} tone={count('DEGRADED') ? 'var(--warning)' : undefined} />
        <Tile label="Fora do ar" value={count('DOWN')} tone={count('DOWN') ? 'var(--critical)' : undefined} />
        <Tile label="Reinícios na última hora" value={list.reduce((n, s) => n + s.restartsLastHour, 0)} />
      </div>

      {(hosts.data ?? []).filter((h) => list.some((x) => x.hostId === h.id)).map((h) => (
        <Card key={h.id} title={<><Workflow size={16} className="text-muted" aria-hidden /> Onde está o problema · {h.id}</>}
          description="O caminho de um acesso: internet, firewall, servidor, domínios/portas e aplicações. A caixa vermelha é onde algo quebrou.">
          <InfraFlow host={h} services={list.filter((x) => x.hostId === h.id)} attackers={attack} />
        </Card>
      ))}

      {pm2Problems.map((h) => (
        <p key={h.id} className="rounded-xl border border-warning bg-surface px-4 py-3 text-sm">
          <span className="font-semibold">{h.id}:</span>{' '}
          {h.pm2?.error ? `não foi possível ler o PM2 (${h.pm2.error})` : 'nenhum daemon PM2 rodando'}
        </p>
      ))}

      <Card flush title="Lista de aplicações" description="Problemas primeiro. Clique em uma aplicação para ver detalhes, gráficos e vulnerabilidades.">
        {q.error && <div className="px-4"><ErrorNote error={q.error} /></div>}
        {q.data && list.length === 0 && (
          <Empty>Nenhuma aplicação PM2 encontrada. O agente precisa ser a versão 0.5.0 ou mais nova e o PM2 precisa estar rodando na VPS.</Empty>
        )}
        {list.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[960px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2.5 font-medium">Saúde</th>
                  <th className="py-2.5 font-medium">Aplicação</th>
                  {multiHost && <th className="py-2.5 font-medium">Servidor</th>}
                  <th className="py-2.5 font-medium" title="Nota de 0 a 100 dos itens de segurança da aplicação">Segurança</th>
                  <th className="py-2.5 font-medium" title="Dependências npm com falhas conhecidas">Vulnerabilidades</th>
                  <th className="py-2.5 text-right font-medium" title="Quanto tempo a aplicação levou para responder na última checagem">Responde em</th>
                  <th className="py-2.5 text-right font-medium">No ar há</th>
                  <th className="py-2.5 text-right font-medium" title="Total · na última hora">Reinícios</th>
                  <th className="py-2.5 text-right font-medium">Memória</th>
                  <th className="px-4 py-2.5 font-medium">Incidentes</th>
                </tr>
              </thead>
              <tbody>
                {list.map((s) => {
                  const a = s.pm2
                  const worst = s.activeIncidents[0]
                  return (
                    <tr key={`${s.hostId}-${a.pm2Home}-${a.pmId}`} onClick={() => navigate(`/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(a.name)}`)}
                      className="cursor-pointer border-t border-line first:border-t-0 hover:bg-raised" title={s.reasons.join(' · ')}>
                      <td className="px-4 py-3"><HealthBadge health={s.health} /></td>
                      <td className="max-w-xs py-3">
                        <Link to={`/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(a.name)}`} className="font-medium hover:text-hud" onClick={(e) => e.stopPropagation()}>
                          {a.name}
                        </Link>
                        <span className="block truncate text-xs text-muted">
                          {s.health !== 'HEALTHY' ? s.reasons[0] : <>PM2: {a.status}{a.ports?.length ? ` · porta ${a.ports.join(', ')}` : ''}</>}
                        </span>
                      </td>
                      {multiHost && <td className="py-3 text-xs text-ink2">{s.hostId}</td>}
                      <td className="py-3"><ScoreBadge score={s.securityScore} /></td>
                      <td className="py-3"><VulnCounts counts={s.vulnerabilities} /></td>
                      <td className="tnum py-3 text-right text-xs">
                        {a.probe ? (a.probe.ok ? `${a.probe.latencyMs} ms` : <span className="font-semibold text-critical">não respondeu</span>) : <span className="text-muted">—</span>}
                      </td>
                      <td className="tnum py-3 text-right text-xs">{fmtUptime(a.startedAt, a.status)}</td>
                      <td className="tnum py-3 text-right text-xs">
                        {a.restarts}
                        <span className={s.restartsLastHour > 0 ? 'font-semibold text-warning' : 'text-muted'}> · {s.restartsLastHour}</span>
                      </td>
                      <td className="tnum py-3 text-right text-xs">{fmtMb(a.memoryBytes)}</td>
                      <td className="px-4 py-3">
                        {worst ? (
                          <span className="flex items-center gap-1.5">
                            <SeverityBadge severity={worst.severity} />
                            <span className="text-xs text-ink2">{s.activeIncidents.length > 1 ? `+${s.activeIncidents.length - 1}` : ''}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-muted">{s.incidents30d ? `${s.incidents30d} em 30 dias` : 'nenhum'}</span>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {list.length > 0 && (
          <p className="border-t border-line px-4 py-3 text-xs text-muted">
            Atualizado pelo agente a cada 30 s (último: {timeAgo(list[0].reportedAt)}). A <b>saúde</b> olha se o app está no ar, responde, reinicia demais ou usa memória demais.
            A <b>segurança</b> olha dependências com falhas conhecidas, versão do Node, se roda como root, HTTPS e arquivo .env.
          </p>
        )}
      </Card>
    </div>
  )
}

function Tile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4">
      <p className="text-sm text-ink2">{label}</p>
      <p className="tnum mt-1 text-3xl font-semibold" style={tone ? { color: tone } : undefined}>{value}</p>
    </div>
  )
}
