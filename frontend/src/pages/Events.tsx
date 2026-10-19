import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api, qs, type EventCategory, type Page, type SecurityEvent } from '../api'
import { Card, Empty, ErrorNote, SeverityBadge, eventTypeLabel, fmtTime } from '../components/ui'

const categories: { value: EventCategory | ''; label: string }[] = [
  { value: '', label: 'Todas categorias' },
  { value: 'AUTH_FAILURE', label: 'Falhas de autenticação' },
  { value: 'AUTH_SUCCESS', label: 'Logins' },
  { value: 'PRIVILEGE', label: 'Privilégio (sudo)' },
  { value: 'NETWORK', label: 'Rede' },
  { value: 'FILE', label: 'Arquivos' },
  { value: 'PROCESS', label: 'Processos' },
  { value: 'AGENT', label: 'Agente' },
]

export default function Events() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(0)
  const [expanded, setExpanded] = useState<number | null>(null)
  const ip = params.get('ip') ?? ''
  const username = params.get('username') ?? ''
  const category = params.get('category') ?? ''

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
    setPage(0)
  }

  const q = useQuery({
    queryKey: ['events', ip, username, category, page],
    queryFn: () => api<Page<SecurityEvent>>(`/events${qs({ ip, username, category, page, size: 50 })}`),
    refetchInterval: 10_000,
    placeholderData: keepPreviousData,
  })

  return (
    <Card
      title="Eventos"
      action={
        <div className="flex flex-wrap gap-2 text-sm">
          <select value={category} onChange={(e) => set('category', e.target.value)} className="rounded border border-line bg-page px-2 py-1">
            {categories.map((c) => <option key={c.label} value={c.value}>{c.label}</option>)}
          </select>
          <input defaultValue={ip} onBlur={(e) => set('ip', e.target.value.trim())} onKeyDown={(e) => e.key === 'Enter' && set('ip', e.currentTarget.value.trim())}
            placeholder="IP" className="w-36 rounded border border-line bg-page px-2 py-1 font-mono text-xs" key={`ip-${ip}`} />
          <input defaultValue={username} onBlur={(e) => set('username', e.target.value.trim())} onKeyDown={(e) => e.key === 'Enter' && set('username', e.currentTarget.value.trim())}
            placeholder="Usuário" className="w-32 rounded border border-line bg-page px-2 py-1 font-mono text-xs" key={`u-${username}`} />
        </div>
      }
    >
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.content.length === 0 && <Empty>Nenhum evento.</Empty>}
      {q.data && q.data.content.length > 0 && (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 pb-2 font-normal">Quando</th>
                <th className="pb-2 font-normal">Severidade</th>
                <th className="pb-2 font-normal">Tipo</th>
                <th className="pb-2 font-normal">Usuário</th>
                <th className="pb-2 font-normal">IP</th>
                <th className="px-4 pb-2 font-normal">Host</th>
              </tr>
            </thead>
            <tbody>
              {q.data.content.map((e) => (
                <EventRow key={e.id} e={e} open={expanded === e.id} toggle={() => setExpanded(expanded === e.id ? null : e.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {q.data && q.data.totalPages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-2 text-sm">
          <span className="mr-auto text-xs text-muted">{q.data.totalElements.toLocaleString('pt-BR')} eventos</span>
          <button disabled={page === 0} onClick={() => setPage(page - 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Anterior</button>
          <span className="text-xs text-muted">{page + 1} / {q.data.totalPages}</span>
          <button disabled={page + 1 >= q.data.totalPages} onClick={() => setPage(page + 1)} className="rounded border border-line px-2 py-1 disabled:opacity-40">Próxima</button>
        </div>
      )}
    </Card>
  )
}

function EventRow({ e, open, toggle }: { e: SecurityEvent; open: boolean; toggle: () => void }) {
  return (
    <>
      <tr onClick={toggle} className="cursor-pointer border-t border-line hover:bg-raised">
        <td className="tnum whitespace-nowrap px-4 py-1.5 text-xs text-ink2">{fmtTime(e.occurredAt)}</td>
        <td className="py-1.5"><SeverityBadge severity={e.severity} /></td>
        <td className="py-1.5">{eventTypeLabel[e.type] ?? e.type}</td>
        <td className="py-1.5 font-mono text-xs">{e.username ?? '-'}</td>
        <td className="py-1.5 font-mono text-xs">{e.sourceIp ?? '-'}</td>
        <td className="px-4 py-1.5 text-xs text-muted">{e.hostId}</td>
      </tr>
      {open && (
        <tr className="bg-raised">
          <td colSpan={6} className="px-4 py-2">
            {e.message && <p className="break-all font-mono text-xs">{e.message}</p>}
            {e.metadata && <pre className="mt-1 overflow-x-auto text-xs text-ink2">{JSON.stringify(e.metadata, null, 2)}</pre>}
          </td>
        </tr>
      )}
    </>
  )
}
