import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BarChart3 } from 'lucide-react'
import { api, qs, type Incident, type Page, type TimelineBucket } from '../api'
import { MitreMatrix } from '../components/MitreMatrix'
import { IncidentTrend, SocKpis, TopDetections } from '../components/SocMetrics'
import { Card, Empty, ErrorNote, PageHeader, Segmented, chartTooltip } from '../components/ui'

// Categorical slots 1..6 in a fixed order; color follows the category, never its rank.
const series = [
  { key: 'authFailures', label: 'Logins que falharam', color: 'var(--s1)' },
  { key: 'authSuccesses', label: 'Logins', color: 'var(--s2)' },
  { key: 'privilege', label: 'Uso de sudo', color: 'var(--s3)' },
  { key: 'network', label: 'Portas abertas/fechadas', color: 'var(--s4)' },
  { key: 'other', label: 'Agente', color: 'var(--s5)' },
  { key: 'integrity', label: 'Arquivos e processos', color: 'var(--s6)' },
] as const

export default function Reports() {
  const active = useQuery({
    queryKey: ['incidents', 'alert-watch'],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status: 'OPEN,ACKNOWLEDGED', size: 100 })}`),
    refetchInterval: 5_000,
  })
  return (
    <div className="space-y-5">
      <PageHeader icon={BarChart3} title="Relatórios"
        description="Números para acompanhar o trabalho do SOC ao longo do tempo: quanto tempo leva para responder, o que mais dispara e como os ataques se distribuem. Bom para apresentar resultados." />
      <SocKpis />
      <Timeline />
      <div className="grid gap-5 xl:grid-cols-3">
        <IncidentTrend className="xl:col-span-2" />
        <TopDetections />
      </div>
      <Card title="Mapa MITRE ATT&CK"
        description="O MITRE ATT&CK é um catálogo público das técnicas que atacantes usam. Cada coluna é uma etapa de um ataque; as caixas acesas são técnicas vistas nos incidentes abertos agora.">
        {active.error && <ErrorNote error={active.error} />}
        {active.data && <MitreMatrix incidents={active.data.content} />}
      </Card>
    </div>
  )
}

function Timeline() {
  const [hours, setHours] = useState(24)
  const [asTable, setAsTable] = useState(false)
  const q = useQuery({
    queryKey: ['timeline', hours],
    queryFn: () => api<TimelineBucket[]>(`/dashboard/timeline?hours=${hours}`),
    refetchInterval: 30_000,
  })
  const data = q.data?.map((b) => ({ ...b, label: new Date(b.hour).toLocaleString('pt-BR', hours > 24 ? { day: '2-digit', hour: '2-digit' } : { hour: '2-digit', minute: '2-digit' }) }))
  return (
    <Card title="Eventos por hora, por tipo"
      description="Cada barra é uma hora; as cores mostram que tipo de coisa aconteceu. Use “Tabela” para ver os números exatos."
      action={
        <div className="flex flex-wrap items-center gap-2">
          <Segmented label="Formato" value={asTable ? 'table' : 'chart'} onChange={(v) => setAsTable(v === 'table')}
            options={[{ value: 'chart', label: 'Gráfico' }, { value: 'table', label: 'Tabela' }]} />
          <Segmented label="Período" value={hours} onChange={setHours}
            options={[{ value: 24, label: '24h' }, { value: 72, label: '3 dias' }, { value: 168, label: '7 dias' }]} />
        </div>
      }
    >
      {q.error && <ErrorNote error={q.error} />}
      {asTable && data && <TimelineTable rows={data} />}
      <div className={asTable ? 'hidden' : 'h-72'}>
        {data && (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -16, bottom: 0 }} barCategoryGap={2}>
              <CartesianGrid vertical={false} stroke="var(--line)" />
              <XAxis dataKey="label" tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={{ stroke: 'var(--axis)' }} minTickGap={24} />
              <YAxis tick={{ fill: 'var(--muted)', fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip cursor={{ fill: 'var(--raised)' }} {...chartTooltip} />
              <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 12, color: 'var(--ink-2)' }} />
              {series.map((s, i) => (
                <Bar key={s.key} dataKey={s.key} name={s.label} stackId="a" fill={s.color} stroke="var(--surface)" strokeWidth={1}
                  radius={i === series.length - 1 ? [4, 4, 0, 0] : 0} maxBarSize={28} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}

/** Same data as the chart, for exact numbers and for colors that are hard to tell apart. */
function TimelineTable({ rows }: { rows: (TimelineBucket & { label: string })[] }) {
  const busy = rows.filter((r) => series.some((s) => r[s.key] > 0)).reverse()
  if (busy.length === 0) return <Empty>Sem eventos no período.</Empty>
  return (
    <div className="-mx-4 h-72 overflow-auto">
      <table className="w-full min-w-[640px] text-xs">
        <thead className="sticky top-0 bg-surface">
          <tr className="text-left text-muted">
            <th className="px-4 pb-2 font-medium">Hora</th>
            {series.map((s) => (
              <th key={s.key} className="pb-2 pr-3 text-right font-medium">
                <span className="mr-1 inline-block h-2 w-2 rounded-full" style={{ background: s.color }} aria-hidden />{s.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="tnum">
          {busy.map((r) => (
            <tr key={r.hour} className="border-t border-line">
              <td className="px-4 py-1.5 text-ink2">{r.label}</td>
              {series.map((s) => (
                <td key={s.key} className={`py-1.5 pr-3 text-right ${r[s.key] ? 'text-ink' : 'text-muted'}`}>{r[s.key]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
