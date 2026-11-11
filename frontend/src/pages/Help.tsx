import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Activity, BarChart3, Boxes, FileText, HelpCircle, LayoutDashboard, Server, ShieldCheck, Siren } from 'lucide-react'
import { Card, PageHeader, SeverityBadge } from '../components/ui'
import { CommandBlock } from '../components/ResponseUi'

const pages: { to: string; Icon: typeof Siren; title: string; text: string }[] = [
  { to: '/', Icon: LayoutDashboard, title: 'Visão geral', text: 'Resumo de tudo. Diz se está tudo bem e, se não estiver, o que precisa de você.' },
  { to: '/incidents', Icon: Siren, title: 'Incidentes', text: 'Problemas detectados que precisam de análise. Cada um explica o que aconteceu e o que fazer.' },
  { to: '/events', Icon: Activity, title: 'Eventos', text: 'O registro bruto de tudo que o agente viu. Útil para investigar um IP ou usuário.' },
  { to: '/hosts', Icon: Server, title: 'Servidores', text: 'Mapa-múndi com servidores e origem dos ataques, o caminho da internet até as aplicações e a ficha de cada VPS.' },
  { to: '/services', Icon: Boxes, title: 'Aplicações', text: 'Apps Node.js rodando no PM2: se estão no ar e se têm dependências vulneráveis.' },
  { to: '/response', Icon: ShieldCheck, title: 'Resposta automática', text: 'Ações de defesa (bloquear IP, matar processo). Aqui você aprova as que esperam por você.' },
  { to: '/reports', Icon: BarChart3, title: 'Relatórios', text: 'Métricas do SOC ao longo do tempo e o mapa MITRE ATT&CK.' },
  { to: '/client-report', Icon: FileText, title: 'Relatório do cliente', text: 'Resumo de uma página em linguagem simples, para imprimir ou salvar em PDF e mandar a quem não usa o painel.' },
]

const glossary: { term: string; text: ReactNode }[] = [
  { term: 'SOC', text: 'Security Operations Center, ou Centro de Operações de Segurança. A equipe (e as ferramentas) que vigia os sistemas e responde a ataques. Este painel é um mini SOC.' },
  { term: 'Agente', text: 'Programa pequeno instalado na VPS que lê os logs, portas, arquivos e processos e manda tudo para o SOC a cada poucos segundos.' },
  { term: 'Evento', text: 'Um fato registrado pelo agente: “login falhou”, “porta 4444 abriu”, “arquivo sudoers mudou”. Sozinho, um evento normalmente não é um problema.' },
  { term: 'Incidente', text: 'Quando um ou mais eventos formam um padrão perigoso (ex.: 50 logins falhos do mesmo IP em 1 minuto), o SOC abre um incidente. É isso que uma pessoa precisa olhar.' },
  { term: 'Severidade', text: <>O quão grave é: <SeverityBadge severity="CRITICAL" /> invasão provável, aja agora · <SeverityBadge severity="HIGH" /> ataque confirmado · <SeverityBadge severity="MEDIUM" /> suspeito, investigar · <SeverityBadge severity="LOW" /> aviso, baixo risco.</> },
  { term: 'Risco (0 a 100)', text: 'Nota de perigo de cada incidente. Sobe quando há sinais que pioram a situação, por exemplo um atacante que conseguiu logar depois de tentar várias senhas.' },
  { term: 'Nota de segurança', text: 'Começa em 100 e perde pontos para cada incidente aberto (40 crítico, 20 alto, 5 médio, 1 baixo). Resolver incidentes faz a nota voltar a subir.' },
  { term: 'Brute force', text: 'Ataque de “força bruta”: um robô tenta milhares de senhas até acertar. É o ataque mais comum contra SSH.' },
  { term: 'Falso positivo', text: 'Alarme que disparou mas não era ataque (ex.: você mesmo errou a senha várias vezes). Marque como falso positivo para o SOC aprender e não reabrir.' },
  { term: 'Bloquear IP', text: 'Colocar o endereço do atacante no firewall da VPS (nftables) para ele não conseguir mais se conectar. O bloqueio tem prazo e expira sozinho.' },
  { term: 'MITRE ATT&CK', text: 'Catálogo público, usado no mundo todo, das técnicas que atacantes usam (ex.: T1110 = força bruta). Cada incidente mostra as técnicas envolvidas.' },
  { term: 'MTTD, MTTA, MTTC, MTTR', text: 'Tempos médios para Detectar, Assumir (Acknowledge), Conter e Resolver um incidente. São as métricas clássicas para medir um SOC: quanto menor, melhor.' },
  { term: 'PM2', text: 'Gerenciador que mantém aplicações Node.js rodando na VPS e as reinicia se caírem.' },
  { term: 'Porta pública', text: 'Porta aberta em 0.0.0.0, ou seja, acessível por qualquer um na internet. Banco de dados e painéis administrativos não deveriam estar assim.' },
  { term: 'Geolocalização de IP', text: 'Descobrir o país e a cidade aproximados de um endereço IP. É assim que o mapa sabe onde fica o servidor e de onde vêm os ataques.' },
  { term: 'Tailscale', text: 'VPN que liga a VPS ao computador onde o SOC roda, sem expor o painel na internet. Os IPs dela começam com 100.' },
]

export default function Help() {
  return (
    <div className="space-y-5">
      <PageHeader icon={HelpCircle} title="Ajuda e glossário"
        description="Como usar o painel no dia a dia e o que significa cada termo. Para instalar e configurar, veja o guia em docs/GUIA.md no repositório." />

      <Card title="Rotina em 3 passos" description="O que fazer cada vez que abrir o painel.">
        <ol className="grid gap-4 md:grid-cols-3">
          <Step n={1} title="Olhe a Visão geral">
            O quadro do topo diz a situação. Verde = tudo bem. Amarelo, laranja ou vermelho = tem incidente aberto.
          </Step>
          <Step n={2} title="Abra o incidente mais grave">
            Clique em “Assumir análise” para avisar que você está cuidando. Leia “O que aconteceu” e siga os “Próximos passos”.
          </Step>
          <Step n={3} title="Feche o incidente">
            Depois de verificar, clique em “Resolver” (era real e foi tratado) ou “Falso positivo” (não era ataque). Escreva uma nota curta.
          </Step>
        </ol>
      </Card>

      <Card title="O que tem em cada página">
        <ul className="grid gap-3 sm:grid-cols-2">
          {pages.map((p) => (
            <li key={p.to}>
              <Link to={p.to} className="flex h-full gap-3 rounded-lg border border-line p-3 hover:border-[var(--hud)]">
                <p.Icon size={18} className="mt-0.5 shrink-0 text-hud" aria-hidden />
                <span>
                  <span className="block font-semibold">{p.title}</span>
                  <span className="block text-sm text-ink2">{p.text}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Glossário" description="Os termos que aparecem no painel, em linguagem simples.">
        <dl className="divide-y divide-line">
          {glossary.map((g) => (
            <div key={g.term} className="grid gap-1 py-3 sm:grid-cols-[200px_1fr] sm:gap-4">
              <dt className="font-semibold">{g.term}</dt>
              <dd className="text-sm leading-relaxed text-ink2">{g.text}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <Card title="Problemas comuns">
        <div className="space-y-5 text-sm">
          <Faq q="O painel abre, mas está tudo zerado e “Servidores online: 0 de 0”">
            Nenhum agente está mandando dados para este SOC. Na VPS, veja o log do agente e confira se o endereço do SOC está certo:
            <CommandBlock command="journalctl -u vps-soc-agent -n 30 --no-pager" />
            <CommandBlock command="grep SOC_SERVER_URL /etc/vps-soc-agent/agent.env" />
            O endereço precisa ser o IP e a porta onde este painel está rodando. Depois de corrigir, rode <code className="font-mono">systemctl restart vps-soc-agent</code>.
          </Faq>
          <Faq q="Um servidor aparece como Offline">
            O agente parou de mandar sinal de vida (a cada 30 s). Pode ser a VPS desligada, o agente parado ou a rede (Tailscale) fora do ar. Na VPS:
            <CommandBlock command="systemctl status vps-soc-agent" />
          </Faq>
          <Faq q="Não ouço o alarme">
            Navegadores só liberam som depois de um clique na página. Clique em “Ativar som” no topo, ou em Alertas → Testar alarme.
          </Faq>
        </div>
      </Card>
    </div>
  )
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <li className="flex gap-3">
      <span className="tnum flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-raised text-sm font-semibold text-hud">{n}</span>
      <span>
        <span className="block font-semibold">{title}</span>
        <span className="mt-0.5 block text-sm text-ink2">{children}</span>
      </span>
    </li>
  )
}

function Faq({ q, children }: { q: string; children: ReactNode }) {
  return (
    <div>
      <p className="font-semibold">{q}</p>
      <div className="mt-1 text-ink2">{children}</div>
    </div>
  )
}
