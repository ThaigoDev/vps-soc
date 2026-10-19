import { useState } from 'react'
import { Link } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api, qs, type Incident, type Page, type Severity } from '../api'
import { Card, Empty, ErrorNote, RiskBar, SeverityBadge, StatusBadge, timeAgo } from '../components/ui'

const statusFilters = [
  { value: 'OPEN,ACKNOWLEDGED', label: 'Ativos' },
  { value: 'RESOLVED,FALSE_POSITIVE', label: 'Fechados' },
  { value: '', label: 'Todos' },
]

export default function Incidents() {
  const [status, setStatus] = useState(statusFilters[0].value)
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [page, setPage] = useState(0)

  const q = useQuery({
    queryKey: ['incidents', status, severity, page],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status, severity, page, size: 25 })}`),
    refetchInterval: 10_000,
    placeholderData: keepPreviousData,
  })

  return (
    <Card
      title="Incidentes"
      action={
        <div className="flex flex-wrap gap-2 text-sm">
          <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(0) }} className="rounded border border-line bg-page px-2 py-1">
            {statusFilters.map((s) => <option key={s.label} value={s.value}>{s.label}</option>)}
          </select>
          <select value={severity} onChange={(e) => { setSeverity(e.target.value as Severity | ''); setPage(0) }} className="rounded border border-line bg-page px-2 py-1">
            <option value="">Todas severidades</option>
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      }
    >
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.content.length === 0 && <Empty>Nenhum incidente com esses filtros.</Empty>}
      {q.data && q.data.content.length > 0 && (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 pb-2 font-normal">#</th>
                <th className="pb-2 font-normal">Severidade</th>
                <th className="pb-2 font-normal">Incidente</th>
                <th className="pb-2 font-normal">Origem</th>
                <th className="pb-2 font-normal">Risco</th>
                <th className="pb-2 font-normal">Eventos</th>
                <th className="pb-2 font-normal">Status</th>
                <th className="px-4 pb-2 text-right font-normal">Último</th>
              </tr>
            </thead>
            <tbody>
              {q.data.content.map((i) => (
                <tr key={i.id} className="border-t border-line hover:bg-raised">
                  <td className="tnum px-4 py-2 text-muted">{i.id}</td>
                  <td className="py-2"><SeverityBadge severity={i.severity} /></td>
                  <td className="max-w-md py-2">
                    <Link to={`/incidents/${i.id}`} className="block truncate font-medium hover:text-accent">{i.title}</Link>
                    <span className="text-xs text-muted">{i.hostId} · {i.techniques.map((t) => t.id).join(', ') || i.ruleId}</span>
                  </td>
                  <td className="py-2 font-mono text-xs text-ink2">{i.sourceIp ?? i.username ?? '-'}</td>
                  <td className="py-2"><RiskBar value={i.riskScore} /></td>
                  <td className="tnum py-2">{i.eventCount}</td>
                  <td className="py-2"><StatusBadge status={i.status} /></td>
                  <td className="whitespace-nowrap px-4 py-2 text-right text-xs text-muted">{timeAgo(i.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.data && q.data.totalPages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-2 text-sm">
          <button disabled={page === 0} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Anterior</button>
          <span className="text-xs text-muted">{page + 1} / {q.data.totalPages}</span>
          <button disabled={page + 1 >= q.data.totalPages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Próxima</button>
        </div>
      )}
    </Card>
  )
}
