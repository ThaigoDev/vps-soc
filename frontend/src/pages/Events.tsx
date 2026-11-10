import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { api, qs, type EventCategory, type Page, type SecurityEvent } from '../api'
import { Activity } from 'lucide-react'
import { Card, Empty, ErrorNote, PageHeader, Pager, SeverityBadge, eventTypeLabel, fmtTime } from '../components/ui'

const categories: { value: EventCategory | ''; label: string }[] = [
  { value: '', label: 'Todos os tipos' },
  { value: 'AUTH_FAILURE', label: 'Falhas de autenticação' },
  { value: 'AUTH_SUCCESS', label: 'Logins' },
  { value: 'PRIVILEGE', label: 'Privilégio (sudo)' },
  { value: 'NETWORK', label: 'Rede' },
  { value: 'FILE', label: 'Arquivos' },
  { value: 'PROCESS', label: 'Processos' },
  { value: 'RESPONSE', label: 'Resposta automática' },
  { value: 'SERVICE', label: 'Apps PM2' },
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

  const input = 'rounded-lg border border-line bg-page px-2.5 py-1.5 text-xs'
  return (
    <div>
      <PageHeader icon={Activity} title="Eventos"
        description="Tudo o que o agente registrou na VPS, um por linha: tentativas de login, uso de sudo, portas, arquivos, processos. Os incidentes são montados a partir destes eventos. Use os filtros para investigar um IP ou usuário." />
      <Card flush
        title={q.data ? `${q.data.totalElements.toLocaleString('pt-BR')} evento${q.data.totalElements === 1 ? '' : 's'}` : 'Eventos'}
        description="Clique em uma linha para ver os detalhes técnicos."
        action={
          <div className="flex flex-wrap gap-2">
            <select value={category} onChange={(e) => set('category', e.target.value)} className={input} aria-label="Tipo de evento">
              {categories.map((c) => <option key={c.label} value={c.value}>{c.label}</option>)}
            </select>
            <input defaultValue={ip} onBlur={(e) => set('ip', e.target.value.trim())} onKeyDown={(e) => e.key === 'Enter' && set('ip', e.currentTarget.value.trim())}
              placeholder="Filtrar por IP" aria-label="Filtrar por IP" className={`w-36 font-mono ${input}`} key={`ip-${ip}`} />
            <input defaultValue={username} onBlur={(e) => set('username', e.target.value.trim())} onKeyDown={(e) => e.key === 'Enter' && set('username', e.currentTarget.value.trim())}
              placeholder="Filtrar por usuário" aria-label="Filtrar por usuário" className={`w-36 font-mono ${input}`} key={`u-${username}`} />
            {(ip || username || category) && (
              <button onClick={() => { setParams(new URLSearchParams(), { replace: true }); setPage(0) }} className="rounded-lg px-2 py-1.5 text-xs text-hud hover:underline">
                Limpar filtros
              </button>
            )}
          </div>
        }
      >
        {q.error && <div className="px-4"><ErrorNote error={q.error} /></div>}
        {q.data && q.data.content.length === 0 && <Empty>Nenhum evento com esses filtros.</Empty>}
        {q.data && q.data.content.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead>
                <tr className="border-b border-line text-left text-xs text-muted">
                  <th className="px-4 py-2.5 font-medium">Quando</th>
                  <th className="py-2.5 font-medium">Severidade</th>
                  <th className="py-2.5 font-medium">O que foi</th>
                  <th className="py-2.5 font-medium">Usuário</th>
                  <th className="py-2.5 font-medium">IP</th>
                  <th className="px-4 py-2.5 font-medium">Servidor</th>
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
        {q.data && <Pager page={page} totalPages={q.data.totalPages} onPage={setPage} />}
      </Card>
    </div>
  )
}

function EventRow({ e, open, toggle }: { e: SecurityEvent; open: boolean; toggle: () => void }) {
  return (
    <>
      <tr onClick={toggle} aria-expanded={open} className="cursor-pointer border-t border-line first:border-t-0 hover:bg-raised">
        <td className="tnum whitespace-nowrap px-4 py-2.5 text-xs text-ink2">{fmtTime(e.occurredAt)}</td>
        <td className="py-2.5"><SeverityBadge severity={e.severity} /></td>
        <td className="py-2.5">{eventTypeLabel[e.type] ?? e.type}</td>
        <td className="py-2.5 font-mono text-xs">{e.username ?? '-'}</td>
        <td className="py-2.5 font-mono text-xs">{e.sourceIp ?? '-'}</td>
        <td className="px-4 py-2.5 text-xs text-muted">{e.hostId}</td>
      </tr>
      {open && (
        <tr className="bg-raised">
          <td colSpan={6} className="px-4 py-2">
            {e.message && <p className="break-all font-mono text-xs">{e.message}</p>}
            {e.metadata && <pre className="mt-1 overflow-x-auto font-mono text-xs text-ink2">{JSON.stringify(e.metadata, null, 2)}</pre>}
          </td>
        </tr>
      )}
    </>
  )
}
