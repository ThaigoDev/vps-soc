import { useState } from 'react'
import { Link } from 'react-router-dom'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Bot, Hourglass, ShieldCheck, Unlock } from 'lucide-react'
import { api, qs, type ActionStatus, type IpBlock, type Page, type Policy, type ResponseAction, type ResponsePolicy } from '../api'
import { Card, Empty, ErrorNote, fmtTime, timeAgo } from '../components/ui'
import { ActionCard, policyLabel } from '../components/ResponseUi'

const history: { value: string; label: string }[] = [
  { value: '', label: 'Todas' },
  { value: 'SUCCEEDED', label: 'Executadas' },
  { value: 'FAILED,REJECTED', label: 'Falhas e recusas' },
  { value: 'DISMISSED,EXPIRED', label: 'Descartadas' },
]

export default function Response() {
  const pending = useQuery({
    queryKey: ['actions', 'open'],
    queryFn: () => api<Page<ResponseAction>>(`/response/actions${qs({ status: 'PROPOSED,PENDING,SENT', size: 50 })}`),
    refetchInterval: 5_000,
  })
  const waiting = pending.data?.content.filter((a) => a.status === 'PROPOSED') ?? []
  const running = pending.data?.content.filter((a) => a.status !== 'PROPOSED') ?? []

  return (
    <div className="space-y-4">
      <PolicyCard />
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title={<><Hourglass size={13} aria-hidden /> Aguardando sua aprovação ({waiting.length})</>}>
          {pending.error && <ErrorNote error={pending.error} />}
          {pending.data && waiting.length === 0 && <Empty>Nada esperando por você.</Empty>}
          <ul className="space-y-2">{waiting.map((a) => <ActionCard key={a.id} a={a} showIncident />)}</ul>
          {running.length > 0 && (
            <>
              <p className="hud-label mb-2 mt-4 text-[10px] text-muted">Em execução</p>
              <ul className="space-y-2">{running.map((a) => <ActionCard key={a.id} a={a} showIncident />)}</ul>
            </>
          )}
        </Card>
        <Blocks />
      </div>
      <History />
    </div>
  )
}

function PolicyCard() {
  const q = useQuery({ queryKey: ['policy'], queryFn: () => api<ResponsePolicy>('/response/policy') })
  if (!q.data) return q.error ? <ErrorNote error={q.error} /> : null
  const p = q.data
  const rows: { label: string; policy: Policy; detail: string }[] = [
    { label: 'Bloquear brute force SSH', policy: p.blockBruteForce, detail: `${p.bruteForceBlockHours} h · com aprovação se o IP já logou antes` },
    { label: 'Bloquear invasor (login após brute force)', policy: p.blockCompromise, detail: `${p.compromiseBlockHours / 24} dias · derruba as sessões` },
    { label: 'Encerrar processo malicioso', policy: p.killProcess, detail: 'guarda cópia do binário como evidência' },
    { label: 'Limpar disco cheio', policy: p.diskCleanup, detail: 'journald > 500 MB + cache do apt' },
    { label: 'Reiniciar serviço em falha', policy: p.restartService, detail: 'só se ainda estiver em falha' },
  ]
  const color = (v: Policy) => (v === 'AUTO' ? 'var(--good)' : v === 'APPROVAL' ? 'var(--warning)' : 'var(--muted)')
  return (
    <Card title={<><Bot size={13} aria-hidden /> Playbooks · o que o SOC faz sozinho</>}
      action={<span className={`hud-label text-[10px] font-bold ${p.enabled ? 'text-good' : 'text-critical'}`}>{p.enabled ? 'Resposta ativa ligada' : 'Resposta ativa desligada'}</span>}>
      <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        {rows.map((r) => (
          <div key={r.label} className="border border-line bg-page p-3">
            <p className="text-sm font-semibold">{r.label}</p>
            <p className="hud-label mt-1 text-[10px] font-bold" style={{ color: color(r.policy) }}>{policyLabel[r.policy]}</p>
            <p className="mt-1 text-xs text-muted">{r.detail}</p>
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs text-ink2">
        Nunca bloqueados: loopback, redes privadas, Tailscale (100.64.0.0/10) e link-local (terminal do hPanel)
        {p.allowlist.length > 0 && <>, além de {p.allowlist.join(', ')}</>}. O agente também tem uma guarda local que bloqueia brute force
        mesmo com este painel desligado. Mude as políticas no .env (SOC_RESPONSE_*).
      </p>
    </Card>
  )
}

function Blocks() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: ['blocks'], queryFn: () => api<IpBlock[]>('/response/blocks'), refetchInterval: 10_000 })
  const unblock = useMutation({
    mutationFn: (id: number) => api(`/response/blocks/${id}/unblock`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['blocks'] })
      qc.invalidateQueries({ queryKey: ['actions'] })
    },
  })
  return (
    <Card title={<><Ban size={13} aria-hidden /> IPs bloqueados agora ({q.data?.length ?? 0})</>}>
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.length === 0 && <Empty>Nenhum IP bloqueado.</Empty>}
      {q.data && q.data.length > 0 && (
        <div className="-mx-4 overflow-x-auto">
          <table className="w-full min-w-[520px] text-sm">
            <thead>
              <tr className="hud-label text-left text-[10px] text-muted">
                <th className="px-4 pb-2 font-normal">IP</th>
                <th className="pb-2 font-normal">Por</th>
                <th className="pb-2 font-normal">Expira</th>
                <th className="pb-2 font-normal">Motivo</th>
                <th className="px-4 pb-2" />
              </tr>
            </thead>
            <tbody>
              {q.data.map((b) => (
                <tr key={b.id} className="border-t border-line">
                  <td className="px-4 py-1.5 font-mono text-xs">
                    <Link to={`/events?ip=${encodeURIComponent(b.ip)}`} className="hover:text-hud">{b.ip}</Link>
                    <span className="block text-[10px] text-muted">{b.hostId}</span>
                  </td>
                  <td className="py-1.5 text-xs">{b.origin === 'AGENT' ? 'Agente' : 'SOC'}</td>
                  <td className="tnum py-1.5 text-xs" title={fmtTime(b.expiresAt)}>{fmtTime(b.expiresAt)}</td>
                  <td className="max-w-[220px] truncate py-1.5 text-xs text-ink2" title={b.reason}>
                    {b.incidentId ? <Link to={`/incidents/${b.incidentId}`} className="hover:text-hud">{b.reason}</Link> : b.reason}
                  </td>
                  <td className="px-4 py-1.5 text-right">
                    <button onClick={() => unblock.mutate(b.id)} disabled={unblock.isPending}
                      className="hud-label inline-flex items-center gap-1 rounded-sm border border-line px-2 py-0.5 text-[10px] text-ink2 hover:bg-raised disabled:opacity-50">
                      <Unlock size={11} aria-hidden /> Desbloquear
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {unblock.error && <ErrorNote error={unblock.error} />}
      <p className="mt-3 flex items-center gap-1.5 text-xs text-muted">
        <ShieldCheck size={12} aria-hidden /> Os bloqueios ficam no nftables da VPS com prazo próprio: expiram sozinhos mesmo se o agente parar.
      </p>
    </Card>
  )
}

function History() {
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(0)
  const q = useQuery({
    queryKey: ['actions', 'history', status, page],
    queryFn: () => api<Page<ResponseAction>>(`/response/actions${qs({ status: status || 'SUCCEEDED,FAILED,REJECTED,DISMISSED,EXPIRED', page, size: 20 })}`),
    refetchInterval: 10_000,
    placeholderData: keepPreviousData,
  })
  return (
    <Card title="Histórico de ações"
      action={
        <select value={status} onChange={(e) => { setStatus(e.target.value as ActionStatus | ''); setPage(0) }} className="rounded-sm border border-line bg-page px-2 py-1 text-xs">
          {history.map((h) => <option key={h.label} value={h.value}>{h.label}</option>)}
        </select>
      }>
      {q.error && <ErrorNote error={q.error} />}
      {q.data && q.data.content.length === 0 && <Empty>Nenhuma ação ainda.</Empty>}
      <ul className="space-y-2">{q.data?.content.map((a) => <ActionCard key={a.id} a={a} showIncident />)}</ul>
      {q.data && q.data.totalPages > 1 && (
        <div className="mt-3 flex items-center justify-end gap-2 text-sm">
          <span className="mr-auto text-xs text-muted">{q.data.totalElements} ações · última {q.data.content[0] ? timeAgo(q.data.content[0].createdAt) : '—'}</span>
          <button disabled={page === 0} onClick={() => setPage(page - 1)} className="rounded-sm border border-line px-2 py-1 disabled:opacity-40">Anterior</button>
          <span className="text-xs text-muted">{page + 1} / {q.data.totalPages}</span>
          <button disabled={page + 1 >= q.data.totalPages} onClick={() => setPage(page + 1)} className="rounded-sm border border-line px-2 py-1 disabled:opacity-40">Próxima</button>
        </div>
      )}
    </Card>
  )
}
