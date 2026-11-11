import { useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, FileText, Printer, ShieldCheck, XCircle } from 'lucide-react'
import { api, type AttackMap, type Host, type ServiceView, type Summary } from '../api'
import { postureChecks, ruleLabel, useKpis } from '../components/SocMetrics'
import { fmtDuration } from '../components/ResponseUi'
import { healthStyle } from '../components/ServiceUi'
import { WorldMap, countryName } from '../components/WorldMap'
import { ErrorNote, PageHeader, Segmented, threatLevel } from '../components/ui'

/*
 * One-page security report in plain language, for a client or a manager who never opens the
 * dashboard: what happened in the period, what the SOC did on its own, where attacks came from
 * and what still needs to be fixed. "Imprimir" prints it (or saves it as PDF) without the app chrome.
 */
export default function ClientReport() {
  const [days, setDays] = useState(30)
  const kpis = useKpis(days)
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api<Summary>('/dashboard/summary') })
  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api<Host[]>('/hosts') })
  const services = useQuery({ queryKey: ['services'], queryFn: () => api<ServiceView[]>('/services') })
  const map = useQuery({ queryKey: ['map', days * 24, 'report'], queryFn: () => api<AttackMap>(`/dashboard/map?hours=${days * 24}&limit=200`) })

  const k = kpis.data
  const s = summary.data
  const error = kpis.error ?? summary.error ?? hosts.error ?? services.error ?? map.error
  const ready = k && s && hosts.data && services.data && map.data

  return (
    <div>
      <div className="no-print">
        <PageHeader icon={FileText} title="Relatório para o cliente"
          description="Um resumo de uma página, em linguagem simples, para mandar a um cliente ou gestor que não usa o painel. Escolha o período e clique em Imprimir para gerar o PDF."
          actions={
            <>
              <Segmented label="Período" value={days} onChange={setDays} options={[{ value: 7, label: 'Últimos 7 dias' }, { value: 30, label: 'Últimos 30 dias' }]} />
              <button onClick={() => window.print()} disabled={!ready}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--primary)] px-3 py-1.5 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-50">
                <Printer size={15} aria-hidden /> Imprimir / salvar PDF
              </button>
            </>
          } />
      </div>
      {error ? <ErrorNote error={error} /> : null}
      {ready && <Report days={days} k={k} s={s} hosts={hosts.data} services={services.data} map={map.data} />}
    </div>
  )
}

function Report({ days, k, s, hosts, services, map }: {
  days: number
  k: NonNullable<ReturnType<typeof useKpis>['data']>
  s: Summary
  hosts: Host[]
  services: ServiceView[]
  map: AttackMap
}) {
  const t = threatLevel(s.openIncidents)
  const now = new Date()
  const from = new Date(now.getTime() - days * 86_400_000)
  const fmt = (d: Date) => d.toLocaleDateString('pt-BR', { day: '2-digit', month: 'long', year: 'numeric' })
  const attempts = map.attackers.reduce((n, a) => n + a.failures, 0)
  const breached = map.attackers.filter((a) => a.failures > 0 && a.successes > 0)
  const countries = map.countries
  const appsBad = services.filter((x) => x.health === 'DOWN' || x.health === 'DEGRADED')
  const offline = hosts.filter((h) => h.status !== 'ONLINE')

  const todo: { text: string; why: string }[] = []
  for (const h of hosts) {
    for (const c of postureChecks(h)) {
      if (c.ok === false) todo.push({ text: `${h.id}: ${fixText(c.label)}`, why: c.detail })
    }
  }
  for (const a of services) {
    for (const c of a.checks.filter((x) => x.status === 'FAIL')) todo.push({ text: `${a.pm2.name}: ${c.label}`, why: c.detail })
  }
  if (s.totalOpenIncidents > 0) todo.unshift({ text: `Analisar ${s.totalOpenIncidents} incidente(s) ainda aberto(s)`, why: 'Cada um tem o passo a passo no painel, em Incidentes.' })

  const headline = s.totalOpenIncidents === 0 && breached.length === 0 && offline.length === 0
    ? 'Os servidores estão protegidos e não há nenhum problema de segurança aberto.'
    : t.level <= 2
      ? 'Há problemas graves que precisam de ação imediata (detalhes abaixo).'
      : 'Os servidores estão funcionando, com alguns pontos de atenção (detalhes abaixo).'

  return (
    <article className="mx-auto max-w-4xl rounded-2xl border border-line bg-surface p-8 print:max-w-none print:rounded-none print:border-0 print:p-0">
      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-line pb-5">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-hud"><ShieldCheck size={18} aria-hidden /> VPS-SOC · Relatório de segurança</p>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight">Resumo de {fmt(from)} a {fmt(now)}</h1>
          <p className="mt-1 text-sm text-ink2">Servidor{hosts.length === 1 ? '' : 'es'} monitorado{hosts.length === 1 ? '' : 's'}: {hosts.map((h) => h.id).join(', ') || 'nenhum'}</p>
        </div>
        <div className="rounded-xl border px-4 py-3 text-center" style={{ borderColor: t.color }}>
          <p className="text-xs text-muted">Situação agora</p>
          <p className="text-lg font-semibold" style={{ color: t.color }}>{t.label}</p>
          <p className="text-xs text-muted">nota {s.securityScore}/100</p>
        </div>
      </header>

      <Section title="Em resumo">
        <p className="text-base leading-relaxed">
          {headline} No período, <b>{attempts.toLocaleString('pt-BR')}</b> tentativa(s) de invasão vieram de <b>{map.attackers.length}</b> endereço(s)
          {countries.length > 0 && <> em <b>{countries.length}</b> país(es)</>}. O monitoramento abriu <b>{k.incidentsOpened}</b> alerta(s) de segurança
          e <b>{k.containedAutomatically}</b> ameaça(s) foram contidas automaticamente, sem esperar ninguém.
          {breached.length > 0 && <> <b className="text-critical">Atenção: {breached.length} atacante(s) conseguiram fazer login</b> e isso foi tratado como incidente crítico.</>}
        </p>
      </Section>

      <Section title="Números do período">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Num label="Tentativas de invasão" value={attempts.toLocaleString('pt-BR')} hint="logins que falharam" />
          <Num label="Alertas de segurança" value={String(k.incidentsOpened)} hint={`${k.incidentsResolved} resolvido(s)`} />
          <Num label="Contidos sozinhos" value={String(k.containedAutomatically)} hint="bloqueio automático" />
          <Num label="IPs bloqueados agora" value={String(k.activeBlocks)} hint="no firewall do servidor" />
          <Num label="Tempo para detectar" value={fmtDuration(k.mttdSeconds)} hint="média" />
          <Num label="Tempo para conter" value={fmtDuration(k.mttcSeconds)} hint="média" />
          <Num label="Tempo para resolver" value={fmtDuration(k.mttrSeconds)} hint="média" />
          <Num label="Alarmes falsos" value={`${Math.round(k.falsePositiveRate * 100)}%`} hint="dos alertas" />
        </div>
      </Section>

      <Section title="De onde vieram os ataques">
        {countries.length === 0 ? (
          <p className="text-sm text-ink2">Nenhum ataque com origem localizada no período.</p>
        ) : (
          <div className="grid items-start gap-6 md:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <WorldMap data={map} compact />
            <table className="w-full text-sm">
              <thead><tr className="border-b border-line text-left text-xs text-muted"><th className="py-1.5 font-medium">País</th><th className="py-1.5 text-right font-medium">IPs</th><th className="py-1.5 text-right font-medium">Tentativas</th></tr></thead>
              <tbody>
                {countries.slice(0, 8).map((c) => (
                  <tr key={c.code} className="border-b border-line last:border-0">
                    <td className="py-1.5">{countryName(c.code, c.name)}</td>
                    <td className="tnum py-1.5 text-right">{c.ips}</td>
                    <td className="tnum py-1.5 text-right">{c.failures.toLocaleString('pt-BR')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>

      <Section title="Principais tipos de ameaça">
        {k.topRules.length === 0 ? <p className="text-sm text-ink2">Nenhum alerta no período.</p> : (
          <ul className="grid gap-x-8 gap-y-1.5 sm:grid-cols-2">
            {k.topRules.slice(0, 6).map((r) => (
              <li key={r.ruleId} className="flex justify-between gap-3 border-b border-line py-1 text-sm">
                <span>{ruleLabel[r.ruleId] ?? r.ruleId}</span>
                <span className="tnum text-ink2">{r.incidents}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Saúde dos servidores e aplicações">
        <ul className="space-y-1.5 text-sm">
          {hosts.map((h) => (
            <Line key={h.id} ok={h.status === 'ONLINE'}>
              <b>{h.id}</b>: {h.status === 'ONLINE' ? `online · CPU ${h.metrics?.cpuPercent?.toFixed(0) ?? '-'}%, memória ${h.metrics?.memPercent?.toFixed(0) ?? '-'}%, disco ${h.metrics?.diskPercent?.toFixed(0) ?? '-'}%` : 'offline'}
            </Line>
          ))}
          {services.map((a) => (
            <Line key={`${a.hostId}-${a.pm2.pmId}`} ok={a.health === 'HEALTHY'} warn={a.health === 'DEGRADED'}>
              Aplicação <b>{a.pm2.name}</b>: {healthStyle[a.health].label.toLowerCase()}
              {a.availability.uptimePct != null && ` · no ar ${a.availability.uptimePct.toFixed(1)}% do tempo (24h)`}
              {a.health !== 'HEALTHY' && a.reasons[0] ? ` · ${a.reasons[0]}` : ''}
            </Line>
          ))}
        </ul>
        {appsBad.length === 0 && offline.length === 0 && <p className="mt-2 text-sm text-good">Tudo no ar.</p>}
      </Section>

      <Section title="O que recomendamos fazer">
        {todo.length === 0 ? <p className="text-sm text-good">Nada pendente. A configuração de segurança está em dia.</p> : (
          <ol className="list-decimal space-y-2 pl-5 text-sm">
            {todo.slice(0, 10).map((x) => (
              <li key={x.text}>
                <span className="font-medium">{x.text}</span>
                <span className="block text-xs text-muted">{x.why}</span>
              </li>
            ))}
          </ol>
        )}
      </Section>

      <footer className="mt-8 border-t border-line pt-3 text-xs text-muted">
        Gerado pelo VPS-SOC em {now.toLocaleString('pt-BR')}. Os servidores são monitorados 24 horas por um agente que registra logins,
        alterações de arquivos importantes, portas e processos; ataques conhecidos são bloqueados automaticamente.
      </footer>
    </article>
  )
}

/** Turns a checklist label ("SSH só com chave") into an action. */
function fixText(label: string): string {
  const map: Record<string, string> = {
    'SSH só com chave': 'desativar login SSH por senha (usar só chave)',
    'Root sem senha': 'impedir login direto como root',
    'Patches de segurança': 'instalar as atualizações de segurança pendentes',
    'Sem reboot pendente': 'reiniciar o servidor para concluir atualizações',
    'Serviços rodando': 'corrigir o serviço do sistema que está em falha',
    'Firewall do agente': 'ativar o firewall do agente',
    'Superfície exposta': 'fechar portas abertas para a internet que não são necessárias',
  }
  return map[label] ?? label
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-7">
      <h2 className="mb-3 text-base font-semibold">{title}</h2>
      {children}
    </section>
  )
}

function Num({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="rounded-lg border border-line p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="tnum mt-0.5 text-xl font-semibold">{value}</p>
      <p className="text-xs text-muted">{hint}</p>
    </div>
  )
}

function Line({ ok, warn, children }: { ok: boolean; warn?: boolean; children: ReactNode }) {
  return (
    <li className="flex items-start gap-2">
      {ok ? <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-good" aria-label="ok" />
        : warn ? <AlertTriangle size={16} className="mt-0.5 shrink-0 text-warning" aria-label="atenção" />
          : <XCircle size={16} className="mt-0.5 shrink-0 text-critical" aria-label="problema" />}
      <span>{children}</span>
    </li>
  )
}
