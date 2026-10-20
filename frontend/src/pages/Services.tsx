import { useNavigate } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Boxes } from 'lucide-react'
import { api, type Host, type ServiceView } from '../api'
import { Card, Empty, ErrorNote, SeverityBadge, timeAgo } from '../components/ui'
import { HealthBadge, Pm2Status, fmtMb, fmtUptime, healthOrder } from '../components/ServiceUi'

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
  const pm2Problems = (hosts.data ?? []).filter((h) => h.pm2?.error || (h.pm2 && (h.pm2.daemons?.length ?? 0) === 0))

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <Tile label="Apps no PM2" value={list.length} />
        <Tile label="Saudáveis" value={count('HEALTHY')} tone="var(--good)" />
        <Tile label="Degradados" value={count('DEGRADED')} tone={count('DEGRADED') ? 'var(--warning)' : undefined} />
        <Tile label="Fora do ar" value={count('DOWN')} tone={count('DOWN') ? 'var(--critical)' : undefined} />
        <Tile label="Reinícios · 1h" value={list.reduce((n, s) => n + s.restartsLastHour, 0)} />
      </div>

      {pm2Problems.map((h) => (
        <p key={h.id} className="border border-warning bg-surface px-4 py-2 text-sm">
          <span className="font-semibold">{h.id}:</span>{' '}
          {h.pm2?.error ? `não foi possível ler o PM2 (${h.pm2.error})` : 'nenhum daemon PM2 rodando'}
        </p>
      ))}

      <Card title={<><Boxes size={13} aria-hidden /> Apps PM2 · pm2 list</>}>
        {q.error && <ErrorNote error={q.error} />}
        {q.data && list.length === 0 && (
          <Empty>Nenhum app PM2 reportado. O agente precisa ser a versão 0.5.0 ou mais nova, e o PM2 precisa estar rodando na VPS.</Empty>
        )}
        {list.length > 0 && (
          <div className="-mx-4 overflow-x-auto">
            <table className="w-full min-w-[980px] text-sm">
              <thead>
                <tr className="hud-label text-left text-[10px] text-muted">
                  <th className="px-4 pb-2 font-normal">Saúde</th>
                  <th className="pb-2 font-normal">id · nome</th>
                  {multiHost && <th className="pb-2 font-normal">Host</th>}
                  <th className="pb-2 font-normal">Status</th>
                  <th className="pb-2 text-right font-normal">Uptime</th>
                  <th className="pb-2 text-right font-normal">↺ total · 1h</th>
                  <th className="pb-2 text-right font-normal">CPU</th>
                  <th className="pb-2 text-right font-normal">Memória</th>
                  <th className="pb-2 pl-4 font-normal">Portas</th>
                  <th className="pb-2 font-normal">Usuário · modo</th>
                  <th className="px-4 pb-2 font-normal">Incidentes</th>
                </tr>
              </thead>
              <tbody>
                {list.map((s) => {
                  const a = s.pm2
                  const worst = s.activeIncidents[0]
                  return (
                    <tr key={`${s.hostId}-${a.pm2Home}-${a.pmId}`} onClick={() => navigate(`/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(a.name)}`)}
                      className="cursor-pointer border-t border-line hover:bg-raised" title={s.reasons.join(' · ')}>
                      <td className="px-4 py-2"><HealthBadge health={s.health} /></td>
                      <td className="py-2">
                        <Link to={`/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(a.name)}`} className="font-semibold hover:text-hud" onClick={(e) => e.stopPropagation()}>
                          <span className="font-mono text-xs text-muted">{a.pmId}</span> {a.name}
                        </Link>
                        {s.health !== 'HEALTHY' && <span className="block text-xs text-ink2">{s.reasons[0]}</span>}
                      </td>
                      {multiHost && <td className="py-2 font-mono text-xs text-ink2">{s.hostId}</td>}
                      <td className="py-2"><Pm2Status status={a.status} /></td>
                      <td className="tnum py-2 text-right font-mono text-xs">{fmtUptime(a.startedAt, a.status)}</td>
                      <td className="tnum py-2 text-right font-mono text-xs">
                        {a.restarts}
                        <span className={s.restartsLastHour > 0 ? 'font-bold text-warning' : 'text-muted'}> · {s.restartsLastHour}</span>
                      </td>
                      <td className="tnum py-2 text-right font-mono text-xs">{a.cpuPercent.toFixed(1)}%</td>
                      <td className="tnum py-2 text-right font-mono text-xs">
                        {fmtMb(a.memoryBytes)}
                        <span className="block text-[10px] text-muted">{s.memoryPercent.toFixed(1)}% RAM</span>
                      </td>
                      <td className="py-2 pl-4 font-mono text-xs">{a.ports?.length ? a.ports.join(', ') : '—'}</td>
                      <td className="py-2 text-xs text-ink2">{a.user ?? '?'} · {a.mode ?? 'fork'}</td>
                      <td className="px-4 py-2">
                        {worst ? (
                          <span className="flex items-center gap-1.5">
                            <SeverityBadge severity={worst.severity} />
                            <span className="text-xs text-ink2">{s.activeIncidents.length > 1 ? `+${s.activeIncidents.length - 1}` : ''}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-muted">{s.incidents30d ? `${s.incidents30d} em 30d` : 'nenhum'}</span>
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
          <p className="mt-3 text-xs text-muted">
            Atualizado pelo agente a cada 30 s · último relatório {timeAgo(list[0].reportedAt)}. A saúde considera o status, reinícios na última hora,
            crash loop, memória acima de 40% da RAM, CPU acima de 90% e incidentes de segurança ligados ao app.
          </p>
        )}
      </Card>
    </div>
  )
}

function Tile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="panel border border-line bg-surface p-3" style={tone ? { borderColor: tone } : undefined}>
      <p className="hud-label text-[10px] text-muted">{label}</p>
      <p className="tnum mt-1 font-mono text-3xl font-bold" style={tone ? { color: tone } : undefined}>{value}</p>
    </div>
  )
}

/** Compact strip for the overview: every app as a chip, problems first. */
export function ServicesPanel() {
  const q = useServices()
  const list = [...(q.data ?? [])].sort((a, b) => healthOrder[a.health] - healthOrder[b.health] || a.pm2.pmId - b.pm2.pmId)
  if (q.data && list.length === 0) return null
  const bad = list.filter((s) => s.health === 'DOWN' || s.health === 'DEGRADED').length
  return (
    <Card title={<><Boxes size={13} aria-hidden /> Serviços (PM2)</>}
      action={<Link to="/services" className="hud-label text-[10px] text-hud hover:underline">{bad ? `${bad} com problema · ` : ''}Detalhes</Link>}>
      {q.error && <ErrorNote error={q.error} />}
      <div className="flex flex-wrap gap-2">
        {list.map((s) => (
          <Link key={`${s.hostId}-${s.pm2.pm2Home}-${s.pm2.pmId}`} to={`/services/${encodeURIComponent(s.hostId)}/${encodeURIComponent(s.pm2.name)}`}
            title={s.reasons.join(' · ')}
            className="flex items-center gap-2 border border-line bg-page px-2.5 py-1.5 hover:border-hud">
            <HealthBadge health={s.health} />
            <span className="text-sm font-semibold">{s.pm2.name}</span>
            <span className="font-mono text-[11px] text-muted">{fmtUptime(s.pm2.startedAt, s.pm2.status)} · ↺{s.pm2.restarts} · {fmtMb(s.pm2.memoryBytes)}</span>
            {s.activeIncidents.length > 0 && <SeverityBadge severity={s.activeIncidents[0].severity} />}
          </Link>
        ))}
      </div>
    </Card>
  )
}
