import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { ChevronRight, Siren } from 'lucide-react'
import { api, qs, type Incident, type Page, type Severity } from '../api'
import { ruleLabel } from '../components/SocMetrics'
import { Card, Empty, ErrorNote, PageHeader, Pager, RiskBar, Segmented, SeverityBadge, StatusBadge, severityStyle, timeAgo } from '../components/ui'

const statusFilters = [
  { value: 'OPEN,ACKNOWLEDGED', label: 'Abertos' },
  { value: 'RESOLVED,FALSE_POSITIVE', label: 'Encerrados' },
  { value: 'ALL', label: 'Todos' },
]

const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function Incidents() {
  const [status, setStatus] = useState(statusFilters[0].value)
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [page, setPage] = useState(0)
  const navigate = useNavigate()

  const q = useQuery({
    queryKey: ['incidents', status, severity, page],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status: status === 'ALL' ? '' : status, severity, page, size: 25 })}`),
    refetchInterval: 10_000,
    placeholderData: keepPreviousData,
  })

  return (
    <div>
      <PageHeader icon={Siren} title="Incidentes"
        description="Um incidente é um problema que o SOC detectou e que precisa de uma pessoa: um ataque, um login estranho, um arquivo importante alterado. Abra um para ver o que aconteceu e os próximos passos." />
      <Card flush
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Segmented label="Situação" value={status} onChange={(v) => { setStatus(v); setPage(0) }} options={statusFilters} />
            <select value={severity} onChange={(e) => { setSeverity(e.target.value as Severity | ''); setPage(0) }}
              className="rounded-lg border border-line bg-page px-2 py-1.5 text-xs" aria-label="Severidade">
              <option value="">Qualquer severidade</option>
              {severities.map((s) => <option key={s} value={s}>{severityStyle[s].label}</option>)}
            </select>
          </div>
        }
        title={q.data ? `${q.data.totalElements.toLocaleString('pt-BR')} incidente${q.data.totalElements === 1 ? '' : 's'}` : 'Incidentes'}
        description="Os mais recentes primeiro. Clique em uma linha para abrir.">
        {q.error && <div className="px-4"><ErrorNote error={q.error} /></div>}
        {q.data && q.data.content.length === 0 && (
          <Empty>{status === 'OPEN,ACKNOWLEDGED' ? 'Nenhum incidente aberto. Tudo tranquilo.' : 'Nenhum incidente com esses filtros.'}</Empty>
        )}
        {q.data && q.data.content.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2.5 font-medium">Severidade</th>
                  <th className="py-2.5 font-medium">O que aconteceu</th>
                  <th className="py-2.5 font-medium">Origem</th>
                  <th className="py-2.5 font-medium">Risco</th>
                  <th className="py-2.5 font-medium">Situação</th>
                  <th className="py-2.5 text-right font-medium">Última vez</th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody>
                {q.data.content.map((i) => (
                  <tr key={i.id} onClick={() => navigate(`/incidents/${i.id}`)} className="cursor-pointer border-t border-line first:border-t-0 hover:bg-raised">
                    <td className="px-4 py-3"><SeverityBadge severity={i.severity} /></td>
                    <td className="max-w-md py-3">
                      <Link to={`/incidents/${i.id}`} onClick={(e) => e.stopPropagation()} className="block truncate font-medium hover:text-hud">{i.title}</Link>
                      <span className="text-xs text-muted">{ruleLabel[i.ruleId] ?? i.ruleId} · {i.hostId} · {i.eventCount} evento{i.eventCount === 1 ? '' : 's'}</span>
                    </td>
                    <td className="py-3 font-mono text-xs text-ink2">{i.sourceIp ?? i.username ?? '—'}</td>
                    <td className="py-3"><RiskBar value={i.riskScore} /></td>
                    <td className="py-3"><StatusBadge status={i.status} /></td>
                    <td className="whitespace-nowrap py-3 text-right text-xs text-muted">{timeAgo(i.lastSeen)}</td>
                    <td className="pr-3 text-muted"><ChevronRight size={16} aria-hidden /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {q.data && <Pager page={page} totalPages={q.data.totalPages} onPage={setPage} />}
      </Card>
    </div>
  )
}
