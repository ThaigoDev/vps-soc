import type { Incident, Severity } from '../api'
import { severityRank, severityStyle } from './ui'

/*
 * ATT&CK tactics in kill-chain order, with every technique the backend rules can emit
 * (detection/Mitre.java). A technique lights up with the worst severity among the active
 * incidents that carry it; the rest stay dim, showing what the SOC can see.
 */
const tactics: { name: string; techniques: { id: string; name: string }[] }[] = [
  { name: 'Acesso inicial', techniques: [
    { id: 'T1078', name: 'Contas válidas' },
    { id: 'T1078.003', name: 'Contas locais' },
  ] },
  { name: 'Execução', techniques: [
    { id: 'T1059', name: 'Interpretador de comandos' },
    { id: 'T1059.004', name: 'Shell Unix' },
  ] },
  { name: 'Persistência', techniques: [
    { id: 'T1098', name: 'Manipulação de conta' },
    { id: 'T1098.004', name: 'Chaves SSH autorizadas' },
    { id: 'T1136.001', name: 'Criar conta local' },
    { id: 'T1053.003', name: 'Cron' },
    { id: 'T1505.003', name: 'Web shell' },
  ] },
  { name: 'Escalada de privilégio', techniques: [
    { id: 'T1548.003', name: 'Abuso de sudo' },
  ] },
  { name: 'Evasão de defesa', techniques: [
    { id: 'T1562.001', name: 'Desativar ferramentas' },
    { id: 'T1070.004', name: 'Apagar arquivos' },
  ] },
  { name: 'Acesso a credenciais', techniques: [
    { id: 'T1110', name: 'Força bruta' },
    { id: 'T1110.001', name: 'Adivinhação de senha' },
    { id: 'T1110.003', name: 'Password spraying' },
  ] },
  { name: 'Comando e controle', techniques: [
    { id: 'T1571', name: 'Porta não padrão' },
  ] },
]

interface Hit {
  count: number
  worst: Severity
}

export function MitreMatrix({ incidents }: { incidents: Incident[] }) {
  const hits = new Map<string, Hit>()
  for (const inc of incidents) {
    for (const t of inc.techniques) {
      const h = hits.get(t.id)
      if (!h) hits.set(t.id, { count: 1, worst: inc.severity })
      else {
        h.count++
        if (severityRank[inc.severity] > severityRank[h.worst]) h.worst = inc.severity
      }
    }
  }
  const active = tactics.filter((t) => t.techniques.some((x) => hits.has(x.id))).length

  return (
    <div>
      <p className="mb-3 text-xs text-ink2">
        {active === 0
          ? 'Nenhuma tática do ATT&CK em incidentes ativos.'
          : `${active} de ${tactics.length} táticas com atividade em incidentes ativos. Passe o mouse para ver detalhes.`}
      </p>
      <div className="-mx-4 overflow-x-auto px-4">
        <div className="grid min-w-[860px] grid-cols-7 gap-1.5">
          {tactics.map((tac) => {
            const lit = tac.techniques.some((x) => hits.has(x.id))
            return (
              <div key={tac.name} className="flex flex-col gap-1.5">
                <div className={`hud-label border-b-2 pb-1 text-[10px] font-semibold ${lit ? 'border-critical text-ink' : 'border-line text-muted'}`}>
                  {tac.name}
                </div>
                {tac.techniques.map((t) => {
                  const h = hits.get(t.id)
                  const s = h ? severityStyle[h.worst] : null
                  return (
                    <a
                      key={t.id}
                      href={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}/`}
                      target="_blank"
                      rel="noreferrer"
                      title={h ? `${t.id} ${t.name}: ${h.count} incidente(s) ativo(s), pior severidade ${s!.label}` : `${t.id} ${t.name}: sem atividade`}
                      className={`block border px-2 py-1.5 text-xs transition-colors hover:border-hud ${h ? 'text-ink' : 'border-line text-muted'}`}
                      style={h ? { borderColor: s!.color, background: `color-mix(in srgb, ${s!.color} 16%, transparent)` } : undefined}
                    >
                      <span className="flex items-center justify-between gap-1 font-mono text-[10px]">
                        {t.id}
                        {h && s && (
                          <span className="flex items-center gap-0.5 font-semibold">
                            <s.Icon size={11} style={{ color: s.color }} aria-hidden />
                            {h.count}
                          </span>
                        )}
                      </span>
                      <span className="mt-0.5 block leading-tight">{t.name}</span>
                    </a>
                  )
                })}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
