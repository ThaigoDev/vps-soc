import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'
import { Link } from 'react-router-dom'
import { ArrowDown, ArrowRight, Bell, BookOpen, Cpu, Github, Lock, Radar, Shield, ShieldCheck } from 'lucide-react'
import shotOverview from '../assets/presentation/overview.jpg'
import shotIncident from '../assets/presentation/incident.jpg'
import shotMap from '../assets/presentation/map.jpg'
import shotArchitecture from '../assets/presentation/architecture.jpg'
import shotReport from '../assets/presentation/report.jpg'
import shotResponse from '../assets/presentation/response.jpg'
import shotServices from '../assets/presentation/services.jpg'

/*
 * Scroll-telling presentation built only from real screenshots of the dashboard, in the
 * style of product pages: the hero screenshot rises and flattens as you scroll, a statement
 * lights up word by word, a pinned browser window swaps screenshots and zooms into the part
 * the text is talking about, a pinned track scrolls sideways through how it works, numbers
 * count up and a gallery drifts with parallax. No 3D; everything is CSS driven by scroll.
 * Public route (/apresentacao) and an offline single-file build (npm run build:presentation).
 */

const ACCENT = 'linear-gradient(90deg, #7cb2ff, #b69cff)'
const BUTTON = 'linear-gradient(90deg, #3b82f6, #7c3aed)'

// ---- scroll helpers ---------------------------------------------------------------------------

function reducedMotion(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
}

const clamp = (v: number, a = 0, b = 1) => Math.min(b, Math.max(a, v))

/** 0 when the section's top reaches the top of the screen, 1 when its bottom reaches the bottom. */
function useSectionProgress<T extends HTMLElement>(): [RefObject<T>, number] {
  const ref = useRef<T>(null)
  const [p, setP] = useState(0)
  useEffect(() => {
    let raf = 0
    const update = () => {
      raf = 0
      const el = ref.current
      if (!el) return
      const r = el.getBoundingClientRect()
      const total = r.height - window.innerHeight
      setP(total > 0 ? clamp(-r.top / total) : r.top < window.innerHeight ? 1 : 0)
    }
    const on = () => { if (!raf) raf = requestAnimationFrame(update) }
    update()
    window.addEventListener('scroll', on, { passive: true })
    window.addEventListener('resize', on)
    return () => {
      window.removeEventListener('scroll', on)
      window.removeEventListener('resize', on)
      if (raf) cancelAnimationFrame(raf)
    }
  }, [])
  return [ref, reducedMotion() ? 1 : p]
}

/** True once the element has entered the screen (for one-shot reveals). */
function useInView<T extends HTMLElement>(margin = '-15% 0px'): [RefObject<T>, boolean] {
  const ref = useRef<T>(null)
  const [seen, setSeen] = useState(reducedMotion())
  useEffect(() => {
    const el = ref.current
    if (!el || seen) return
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setSeen(true); io.disconnect() } }, { rootMargin: margin })
    io.observe(el)
    return () => io.disconnect()
  }, [margin, seen])
  return [ref, seen]
}

function Reveal({ children, delay = 0, className = '' }: { children: ReactNode; delay?: number; className?: string }) {
  const [ref, seen] = useInView<HTMLDivElement>()
  return (
    <div ref={ref} className={className}
      style={{ opacity: seen ? 1 : 0, transform: seen ? 'none' : 'translateY(32px)', transition: `opacity .9s ${delay}ms cubic-bezier(.2,.7,.2,1), transform .9s ${delay}ms cubic-bezier(.2,.7,.2,1)` }}>
      {children}
    </div>
  )
}

function GradientText({ children }: { children: ReactNode }) {
  return <span style={{ background: ACCENT, WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' }}>{children}</span>
}

/** A browser window around a screenshot. */
function BrowserFrame({ children, url = 'vps-soc · painel', className = '' }: { children: ReactNode; url?: string; className?: string }) {
  return (
    <div className={`overflow-hidden rounded-2xl border border-white/10 bg-[#0d1117] shadow-[0_40px_120px_-20px_rgba(59,130,246,0.35)] ${className}`}>
      <div className="flex items-center gap-2 border-b border-white/10 bg-white/[0.03] px-4 py-2.5">
        <span className="h-3 w-3 rounded-full bg-[#ff5f57]" />
        <span className="h-3 w-3 rounded-full bg-[#febc2e]" />
        <span className="h-3 w-3 rounded-full bg-[#28c840]" />
        <span className="mx-auto truncate rounded-md bg-white/5 px-3 py-0.5 text-[11px] text-white/50">{url}</span>
        <span className="w-12" />
      </div>
      {children}
    </div>
  )
}

// ---- page ---------------------------------------------------------------------------------------

/** {@code standalone}: the offline single-file build, without links into the dashboard. */
export default function Presentation({ standalone = false }: { standalone?: boolean }) {
  useDarkTheme()
  const [pageRef, page] = useSectionProgress<HTMLDivElement>()
  return (
    <div ref={pageRef} className="relative min-h-screen overflow-x-clip text-white" style={{ background: '#07090d' }}>
      <div className="fixed inset-x-0 top-0 z-50 h-[3px]">
        <div className="h-full" style={{ width: `${page * 100}%`, background: ACCENT }} />
      </div>
      <header className="fixed inset-x-0 top-0 z-40 flex items-center gap-3 bg-[#07090d]/95 px-5 py-4 md:bg-transparent md:px-10" style={{ backgroundImage: 'linear-gradient(180deg, rgba(7,9,13,0.9), rgba(7,9,13,0))' }}>
        <span className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg" style={{ background: BUTTON }}>
            <Shield size={17} aria-hidden />
          </span>
          VPS-SOC
        </span>
        {!standalone && (
          <Link to="/" className="ml-auto rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-sm hover:bg-white/10">Abrir o painel</Link>
        )}
      </header>

      <Hero />
      <Statement />
      <Showcase />
      <HowItWorks />
      <Numbers />
      <Gallery />
      <Closing standalone={standalone} />
    </div>
  )
}

/** The presentation is designed dark; switch the page to dark while it is open. */
function useDarkTheme() {
  useEffect(() => {
    const root = document.documentElement
    const before = root.dataset.theme
    delete root.dataset.theme
    return () => {
      if (before) root.dataset.theme = before
    }
  }, [])
}

// ---- 1. hero: the screenshot rises and flattens ---------------------------------------------

function Hero() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const t = clamp(p / 0.7)
  const ease = 1 - Math.pow(1 - t, 3)
  return (
    <section ref={ref} className="relative h-[230vh]">
      <div className="sticky top-0 flex h-screen flex-col items-center overflow-hidden px-5 pt-28 md:pt-32">
        <div className="pointer-events-none absolute left-1/2 top-[30%] h-[60vh] w-[80vw] -translate-x-1/2 rounded-full opacity-60 blur-[120px]"
          style={{ background: 'radial-gradient(closest-side, rgba(59,130,246,0.45), rgba(124,58,237,0.25), transparent)' }} />
        <div className="relative z-10 max-w-4xl text-center" style={{ opacity: 1 - clamp(p * 2.2), transform: `translateY(${-p * 120}px) scale(${1 - p * 0.08})` }}>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/60">Centro de operações de segurança para VPS</p>
          <h1 className="mt-5 text-[2.6rem] font-semibold leading-[1.05] tracking-tight md:text-7xl">
            Segurança de servidor que <GradientText>qualquer pessoa entende</GradientText>
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-base text-white/65 md:text-lg">
            O VPS-SOC vigia sua VPS 24 horas, entende os ataques, reage sozinho e explica tudo em português.
          </p>
          <p className="mt-8 inline-flex items-center gap-2 text-sm text-white/50">
            Role para conhecer <ArrowDown size={15} className="motion-safe:animate-bounce" aria-hidden />
          </p>
        </div>
        <div className="absolute inset-x-0 bottom-0 flex justify-center px-4" style={{ perspective: '1400px' }}>
          <div className="w-full max-w-6xl" style={{
            transform: `translateY(${(1 - ease) * 46}vh) rotateX(${(1 - ease) * 28}deg) scale(${0.82 + ease * 0.18})`,
            transformOrigin: '50% 100%',
            marginBottom: `${ease * 7}vh`,
          }}>
            <BrowserFrame>
              <img src={shotOverview} alt="Visão geral do painel do VPS-SOC" className="block w-full" />
            </BrowserFrame>
          </div>
        </div>
      </div>
    </section>
  )
}

// ---- 2. statement: words light up -------------------------------------------------------------

const STATEMENT = 'Toda VPS ligada na internet é atacada minutos depois. Robôs tentam milhares de senhas por dia, e quem cuida do servidor só descobre a invasão quando o estrago já aconteceu.'
const HOT = ['minutos', 'milhares', 'invasão']

function Statement() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const words = STATEMENT.split(' ')
  const lit = p * 1.25 * words.length
  return (
    <section ref={ref} className="relative h-[220vh]">
      <div className="sticky top-0 flex h-screen items-center justify-center px-6">
        <div className="max-w-5xl">
          <p className="mb-6 text-xs font-semibold uppercase tracking-[0.25em] text-white/50">O problema</p>
          <p className="text-[1.9rem] font-semibold leading-[1.25] tracking-tight md:text-6xl md:leading-[1.15]">
            {words.map((w, i) => {
              const on = clamp(lit - i)
              const hot = HOT.some((h) => w.startsWith(h))
              return (
                <span key={i} style={{ opacity: 0.14 + on * 0.86, color: hot && on > 0.9 ? '#ff7a7a' : undefined, transition: 'color .3s' }}>{w} </span>
              )
            })}
          </p>
        </div>
      </div>
    </section>
  )
}

// ---- 3. showcase: pinned window, zooms into what the text talks about -----------------------

interface Step {
  kicker: string
  title: string
  text: string
  img: string
  url: string
  /** Zoom: scale and the point of the screenshot it zooms into (percent). */
  zoom: [number, number, number]
}

const STEPS: Step[] = [
  { kicker: 'Visão geral', title: 'A situação inteira em uma frase', text: 'Verde é tudo tranquilo. Vermelho é ataque em andamento. Ao lado, uma nota de 0 a 100 que sobe quando os problemas são resolvidos.', img: shotOverview, url: 'vps-soc · visão geral', zoom: [1.75, 60, 38] },
  { kicker: 'Prioridades', title: 'O que precisa de você, mais grave primeiro', text: 'Quatro números levam direto para a página certa, e a lista mostra os incidentes abertos em ordem de perigo.', img: shotOverview, url: 'vps-soc · visão geral', zoom: [1.55, 45, 88] },
  { kicker: 'Incidentes', title: 'Cada ataque explicado em português', text: 'Quem, de onde, quantas vezes e o que fez depois de entrar. Escrito com os dados reais, não com códigos de log.', img: shotIncident, url: 'vps-soc · incidente #10', zoom: [1.6, 52, 24] },
  { kicker: 'Contexto', title: 'Risco, origem e técnicas do MITRE ATT&CK', text: 'Cada incidente mostra o nível de risco, o IP e as técnicas de ataque envolvidas, com um botão para assumir a análise.', img: shotIncident, url: 'vps-soc · incidente #10', zoom: [1.6, 55, 50] },
  { kicker: 'Mapa', title: 'Onde está o servidor e de onde vêm os ataques', text: 'Cada IP que tentou entrar vira um ponto no mapa, com uma linha até o servidor. Ao lado, os países que mais atacaram.', img: shotMap, url: 'vps-soc · servidores', zoom: [1.35, 50, 42] },
  { kicker: 'Aplicações', title: 'O caminho até cada aplicação', text: 'Internet, firewall, servidor, domínios e aplicações. A peça vermelha é onde está o problema, e a lista acima diz o que fazer.', img: shotServices, url: 'vps-soc · aplicações', zoom: [1.3, 55, 62] },
  { kicker: 'Resposta automática', title: 'O SOC se defende sozinho', text: 'Bloqueia o IP atacante no firewall em segundos. Ações delicadas, como encerrar um processo, esperam o seu clique.', img: shotResponse, url: 'vps-soc · resposta automática', zoom: [1.45, 62, 30] },
  { kicker: 'Relatório', title: 'Um resumo pronto para o cliente', text: 'O período em uma página, em linguagem simples: ataques, bloqueios, países de origem e o que recomendamos fazer. Sai em PDF.', img: shotReport, url: 'vps-soc · relatório do cliente', zoom: [1.3, 60, 42] },
]

function Showcase() {
  const [active, setActive] = useState(0)
  const refs = useRef<(HTMLDivElement | null)[]>([])
  useEffect(() => {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i))
    }, { rootMargin: '-48% 0px -48% 0px' })
    refs.current.forEach((el) => el && io.observe(el))
    return () => io.disconnect()
  }, [])
  const s = STEPS[active]
  const still = reducedMotion()

  return (
    <section className="relative">
      <div className="mx-auto max-w-7xl px-5 pt-10 text-center md:px-10">
        <Reveal>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/50">O painel</p>
          <h2 className="mt-4 text-4xl font-semibold tracking-tight md:text-6xl">Feito para <GradientText>entender</GradientText>, não para decorar</h2>
        </Reveal>
      </div>
      <div className="mx-auto grid max-w-7xl gap-8 px-5 md:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)] md:px-10">
        {/* Pinned window (first in DOM so it sits on top on phones) */}
        <div className="sticky top-16 z-10 order-first -mx-5 bg-[#07090d] px-5 pb-4 md:order-last md:top-0 md:mx-0 md:flex md:h-screen md:items-center md:bg-transparent md:px-0 md:pb-0">
          <div className="relative w-full pt-2 md:pt-0">
            <BrowserFrame url={s.url} className="w-full">
              <div className="relative aspect-[16/10] overflow-hidden">
                {STEPS.map((st, i) => (
                  <img key={i} src={st.img} alt={i === active ? `${st.kicker}: ${st.title}` : ''} aria-hidden={i !== active}
                    className="absolute inset-0 h-full w-full object-cover"
                    style={{
                      opacity: i === active ? 1 : 0,
                      transformOrigin: `${st.zoom[1]}% ${st.zoom[2]}%`,
                      transform: `scale(${i === active ? st.zoom[0] : 1})`,
                      transition: still ? 'none' : 'opacity .6s ease, transform 1.1s cubic-bezier(.2,.7,.2,1)',
                    }} />
                ))}
              </div>
            </BrowserFrame>
            <div className="mt-4 hidden gap-1.5 md:flex" aria-hidden>
              {STEPS.map((_, i) => (
                <span key={i} className="h-1 flex-1 rounded-full" style={{ background: i <= active ? ACCENT : 'rgba(255,255,255,0.12)', transition: 'background .4s' }} />
              ))}
            </div>
          </div>
        </div>
        {/* Texts */}
        <div className="md:py-[30vh]">
          {STEPS.map((st, i) => (
            <div key={i} ref={(el) => { refs.current[i] = el }} data-i={i} className="flex min-h-[70vh] items-center md:min-h-[80vh]">
              <div style={{ opacity: i === active ? 1 : 0.25, transform: i === active ? 'none' : 'translateY(12px)', transition: 'opacity .5s, transform .5s' }}>
                <p className="text-xs font-semibold uppercase tracking-[0.2em]"><GradientText>{String(i + 1).padStart(2, '0')} · {st.kicker}</GradientText></p>
                <h3 className="mt-3 text-3xl font-semibold leading-tight tracking-tight md:text-4xl">{st.title}</h3>
                <p className="mt-4 max-w-md text-base leading-relaxed text-white/65 md:text-lg">{st.text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ---- 4. how it works: pinned, scrolls sideways ----------------------------------------------

const FLOW = [
  { Icon: Cpu, title: 'O agente vigia a VPS', text: 'Um programa em Go de poucos megabytes lê logins, sudo, portas, processos, arquivos críticos e as aplicações do PM2.', chips: ['SSH e sudo', 'Portas', 'Arquivos', 'PM2'] },
  { Icon: Lock, title: 'Envia por um túnel seguro', text: 'Os eventos vão pelo Tailscale para o SOC, que roda fora da VPS. Um invasor não consegue apagar o histórico.', chips: ['Criptografado', 'Fora da VPS'] },
  { Icon: Radar, title: 'O SOC detecta e explica', text: 'Regras transformam eventos em incidentes com risco, MITRE ATT&CK e um texto dizendo o que aconteceu e o que fazer.', chips: ['Força bruta', 'Web shell', 'Chave SSH plantada'] },
  { Icon: ShieldCheck, title: 'Reage em segundos', text: 'O agente bloqueia o atacante no firewall da VPS. Ações delicadas esperam a aprovação de uma pessoa.', chips: ['Bloqueio de IP', 'Com aprovação'] },
  { Icon: Bell, title: 'E avisa quem precisa saber', text: 'Sirene no painel, notificação no navegador e mensagem no Telegram, mesmo com o painel fechado.', chips: ['Telegram', 'Navegador'] },
]

function HowItWorks() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const track = useRef<HTMLDivElement>(null)
  const [shift, setShift] = useState(0)
  useEffect(() => {
    const measure = () => {
      const el = track.current
      if (el) setShift(Math.max(0, el.scrollWidth - window.innerWidth))
    }
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [])
  return (
    <section ref={ref} className="relative mt-24 h-[360vh]">
      <div className="sticky top-0 flex h-screen flex-col justify-center overflow-hidden">
        <div className="px-5 md:px-16">
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/50">Como funciona</p>
          <h2 className="mt-4 max-w-3xl text-4xl font-semibold tracking-tight md:text-6xl">Do ataque ao alerta, <GradientText>em segundos</GradientText></h2>
        </div>
        <div className="relative mt-12">
          <div className="absolute left-0 right-0 top-[38px] h-px bg-white/10" />
          <div className="absolute left-0 top-[38px] h-px" style={{ width: `${p * 100}%`, background: ACCENT }} />
          <div ref={track} className="flex gap-6 px-5 md:gap-8 md:px-16" style={{ transform: `translateX(${-p * shift}px)`, width: 'max-content' }}>
            {FLOW.map((f, i) => {
              const on = p * (FLOW.length - 0.3) >= i
              return (
                <article key={f.title} className="w-[78vw] max-w-[420px] shrink-0 md:w-[400px]">
                  <span className="relative z-10 flex h-[76px] w-[76px] items-center justify-center rounded-2xl border transition-all duration-500"
                    style={{ borderColor: on ? 'rgba(124,178,255,0.6)' : 'rgba(255,255,255,0.12)', background: on ? 'linear-gradient(135deg, rgba(59,130,246,0.35), rgba(124,58,237,0.35))' : '#0d1117' }}>
                    <f.Icon size={30} className={on ? 'text-white' : 'text-white/40'} aria-hidden />
                  </span>
                  <div className="mt-6 rounded-2xl border border-white/10 bg-white/[0.03] p-6 transition-opacity duration-500" style={{ opacity: on ? 1 : 0.35 }}>
                    <p className="text-xs font-semibold text-white/40">PASSO {i + 1}</p>
                    <h3 className="mt-2 text-2xl font-semibold tracking-tight">{f.title}</h3>
                    <p className="mt-3 leading-relaxed text-white/65">{f.text}</p>
                    <ul className="mt-4 flex flex-wrap gap-2">
                      {f.chips.map((c) => <li key={c} className="rounded-full border border-white/10 px-3 py-1 text-xs text-white/70">{c}</li>)}
                    </ul>
                  </div>
                </article>
              )
            })}
          </div>
        </div>
      </div>
    </section>
  )
}

// ---- 5. numbers count up ------------------------------------------------------------------------

function Counter({ to, suffix = '' }: { to: number; suffix?: string }) {
  const [ref, seen] = useInView<HTMLSpanElement>()
  const [n, setN] = useState(reducedMotion() ? to : 0)
  useEffect(() => {
    if (!seen || reducedMotion()) return
    let raf = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = clamp((now - start) / 1400)
      setN(Math.round(to * (1 - Math.pow(1 - t, 3))))
      if (t < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [seen, to])
  return <span ref={ref} className="tnum">{n}{suffix}</span>
}

function Numbers() {
  const items = [
    { n: 26, s: '', label: 'tipos de detecção', hint: 'de força bruta a aplicação fora do ar' },
    { n: 6, s: '', label: 'ações de defesa', hint: 'bloquear IP, encerrar processo, reiniciar…' },
    { n: 30, s: 's', label: 'entre cada sinal de vida', hint: 'o silêncio do agente vira alerta' },
    { n: 0, s: '', label: 'comandos de shell enviados', hint: 'o agente só executa ações validadas' },
  ]
  return (
    <section className="mx-auto max-w-7xl px-5 py-32 md:px-10">
      <Reveal>
        <h2 className="max-w-3xl text-4xl font-semibold tracking-tight md:text-5xl">Pequeno no servidor, <GradientText>completo no painel</GradientText></h2>
      </Reveal>
      <div className="mt-14 grid gap-px overflow-hidden rounded-3xl border border-white/10 bg-white/10 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((it, i) => (
          <Reveal key={it.label} delay={i * 120} className="bg-[#07090d] p-8">
            <p className="text-6xl font-semibold tracking-tight"><GradientText><Counter to={it.n} suffix={it.s} /></GradientText></p>
            <p className="mt-3 font-medium">{it.label}</p>
            <p className="mt-1 text-sm text-white/50">{it.hint}</p>
          </Reveal>
        ))}
      </div>
    </section>
  )
}

// ---- 6. gallery with parallax -------------------------------------------------------------------

function Gallery() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const cols: { img: string; alt: string }[][] = [
    [{ img: shotMap, alt: 'Mapa de ataques' }, { img: shotResponse, alt: 'Resposta automática' }],
    [{ img: shotIncident, alt: 'Incidente explicado' }, { img: shotArchitecture, alt: 'Arquitetura das aplicações' }],
    [{ img: shotReport, alt: 'Relatório do cliente' }, { img: shotServices, alt: 'Aplicações' }],
  ]
  const speeds = [-90, 80, -40]
  return (
    <section ref={ref} className="relative overflow-hidden py-24">
      <div className="mx-auto max-w-7xl px-5 md:px-10">
        <Reveal>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/50">Telas reais</p>
          <h2 className="mt-4 text-4xl font-semibold tracking-tight md:text-5xl">Tudo o que você viu está no painel</h2>
        </Reveal>
      </div>
      <div className="mx-auto mt-14 grid max-w-[1500px] grid-cols-1 gap-6 px-5 md:grid-cols-3 md:px-10">
        {cols.map((col, c) => (
          <div key={c} className="space-y-6" style={{ transform: `translateY(${(p - 0.5) * speeds[c]}px)` }}>
            {col.map((x) => (
              <BrowserFrame key={x.alt} url={x.alt}>
                <img src={x.img} alt={x.alt} loading="lazy" className="block w-full" />
              </BrowserFrame>
            ))}
          </div>
        ))}
      </div>
      <div className="pointer-events-none absolute inset-x-0 bottom-0 h-40" style={{ background: 'linear-gradient(0deg, #07090d, transparent)' }} />
    </section>
  )
}

// ---- 7. closing ---------------------------------------------------------------------------------

function Closing({ standalone }: { standalone: boolean }) {
  const stack = ['Go', 'Java 21 · Spring Boot', 'PostgreSQL', 'React · TypeScript', 'Docker', 'Tailscale']
  return (
    <section className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 py-24 text-center">
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-[70vh] w-[70vw] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-50 blur-[120px]"
        style={{ background: 'radial-gradient(closest-side, rgba(124,58,237,0.5), rgba(59,130,246,0.25), transparent)' }} />
      <div className="relative max-w-3xl">
        <Reveal>
          <h2 className="text-5xl font-semibold leading-[1.05] tracking-tight md:text-7xl">Seu servidor, <GradientText>vigiado de verdade</GradientText>.</h2>
        </Reveal>
        <Reveal delay={150}>
          <p className="mx-auto mt-6 max-w-xl text-lg text-white/65">Tudo sobe com um único <code className="rounded bg-white/10 px-1.5 py-0.5 font-mono text-base text-white">docker compose up</code>.</p>
        </Reveal>
        <Reveal delay={300}>
          <ul className="mt-10 flex flex-wrap justify-center gap-2">
            {stack.map((s) => <li key={s} className="rounded-full border border-white/10 bg-white/[0.04] px-4 py-1.5 text-sm text-white/75">{s}</li>)}
          </ul>
        </Reveal>
        <Reveal delay={450}>
          <div className="mt-12 flex flex-wrap justify-center gap-3">
            {!standalone && (
              <Link to="/" className="inline-flex items-center gap-2 rounded-full px-6 py-3 font-semibold hover:brightness-110" style={{ background: BUTTON }}>
                Abrir o painel <ArrowRight size={17} aria-hidden />
              </Link>
            )}
            <a href="https://github.com/ThaigoDev/vps-soc" target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-6 py-3 hover:bg-white/10">
              <Github size={17} aria-hidden /> Código no GitHub
            </a>
            <a href="https://github.com/ThaigoDev/vps-soc/blob/main/docs/GUIA.md" target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-6 py-3 hover:bg-white/10">
              <BookOpen size={17} aria-hidden /> Guia do projeto
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  )
}
