import { useEffect, useRef, useState, type CSSProperties, type ReactNode, type RefObject } from 'react'
import Lenis from 'lenis'
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
 * count up and a bento gallery reveals the screens. Smooth scrolling comes from Lenis; the
 * effects are plain CSS driven by scroll position. No 3D.
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

const EASE = 'cubic-bezier(.16,1,.3,1)'

/** Heading whose words slide up from behind a mask, one after another. */
function SplitReveal({ text, className = '', accent = [] as string[] }: { text: string; className?: string; accent?: string[] }) {
  const [ref, seen] = useInView<HTMLHeadingElement>('-10% 0px')
  return (
    <h2 ref={ref} className={className} aria-label={text}>
      {text.split(' ').map((w, i) => (
        <span key={i} aria-hidden className="inline-block overflow-hidden pb-[0.08em] align-top">
          <span className="inline-block" style={{
            transform: seen ? 'none' : 'translateY(105%)',
            transition: `transform 1s ${i * 55}ms ${EASE}`,
            ...(accent.includes(w.replace(/[.,]/g, '')) ? { background: ACCENT, WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' } : {}),
          }}>{w}&nbsp;</span>
        </span>
      ))}
    </h2>
  )
}

/** Opens from the middle (clip-path) while settling from a slight zoom: for screenshots. */
function ClipReveal({ children, delay = 0, className = '', style }: { children: ReactNode; delay?: number; className?: string; style?: CSSProperties }) {
  const [ref, seen] = useInView<HTMLDivElement>('-8% 0px')
  return (
    <div ref={ref} className={className} style={{
      clipPath: seen ? 'inset(-30% -30% -30% -30% round 18px)' : 'inset(14% 10% 14% 10% round 18px)',
      transform: seen ? 'none' : 'scale(1.06) translateY(40px)',
      opacity: seen ? 1 : 0,
      filter: seen ? 'none' : 'blur(6px)',
      transition: `clip-path 1.3s ${delay}ms ${EASE}, transform 1.3s ${delay}ms ${EASE}, opacity .9s ${delay}ms ease, filter 1s ${delay}ms ease`,
      ...style,
    }}>
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
  useSmoothScroll()
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
      <Marquee />
      <HowItWorks />
      <Numbers />
      <Gallery />
      <Closing standalone={standalone} />
    </div>
  )
}

let lenis: Lenis | null = null

/** Inertial, eased wheel scrolling (the native scroll position still drives everything). */
function useSmoothScroll() {
  useEffect(() => {
    if (reducedMotion()) return
    lenis = new Lenis({ lerp: 0.085, wheelMultiplier: 0.9, smoothWheel: true })
    let raf = requestAnimationFrame(function loop(t) {
      lenis?.raf(t)
      raf = requestAnimationFrame(loop)
    })
    return () => {
      cancelAnimationFrame(raf)
      lenis?.destroy()
      lenis = null
    }
  }, [])
}

function scrollToEl(el: Element | null) {
  if (!el) return
  if (lenis) lenis.scrollTo(el as HTMLElement, { offset: -40, duration: 1.4 })
  else el.scrollIntoView({ behavior: 'auto' })
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

// ---- 1. hero: title words rise, then the screenshot rises and flattens ------------------------

function Hero() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const [loaded, setLoaded] = useState(reducedMotion())
  useEffect(() => { const t = window.setTimeout(() => setLoaded(true), 80); return () => window.clearTimeout(t) }, [])
  const t = clamp(p / 0.65)
  const ease = 1 - Math.pow(1 - t, 3)
  const title = 'Segurança de servidor que qualquer pessoa entende'
  return (
    <section ref={ref} className="relative h-[240vh]">
      <div className="sticky top-0 flex h-screen flex-col items-center overflow-hidden px-5 pt-28 md:pt-32">
        <div className="pointer-events-none absolute left-1/2 top-[28%] h-[60vh] w-[80vw] -translate-x-1/2 rounded-full blur-[120px]"
          style={{ opacity: 0.55 + ease * 0.25, background: 'radial-gradient(closest-side, rgba(59,130,246,0.45), rgba(124,58,237,0.28), transparent)' }} />
        <div className="relative z-10 max-w-4xl text-center" style={{ opacity: 1 - clamp(p * 2.4), transform: `translateY(${-p * 140}px) scale(${1 - p * 0.1})`, filter: `blur(${clamp(p * 2.4) * 6}px)` }}>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/60"
            style={{ opacity: loaded ? 1 : 0, transition: 'opacity 1s .1s ease' }}>Centro de operações de segurança para VPS</p>
          <h1 className="mt-5 text-[2.6rem] font-semibold leading-[1.05] tracking-tight md:text-7xl" aria-label={title}>
            {title.split(' ').map((w, i) => (
              <span key={i} aria-hidden className="inline-block overflow-hidden pb-[0.08em] align-top">
                <span className="inline-block" style={{
                  transform: loaded ? 'none' : 'translateY(105%)', transition: `transform 1.1s ${150 + i * 70}ms ${EASE}`,
                  ...(i >= 4 ? { background: ACCENT, WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' } : {}),
                }}>{w}&nbsp;</span>
              </span>
            ))}
          </h1>
          <p className="mx-auto mt-6 max-w-2xl text-base text-white/65 md:text-lg"
            style={{ opacity: loaded ? 1 : 0, transform: loaded ? 'none' : 'translateY(16px)', transition: `opacity 1s .7s ease, transform 1s .7s ${EASE}` }}>
            O VPS-SOC vigia sua VPS 24 horas, entende os ataques, reage sozinho e explica tudo em português.
          </p>
          <button onClick={() => scrollToEl(document.getElementById('problema'))}
            className="mt-8 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-5 py-2.5 text-sm text-white/80 hover:bg-white/10"
            style={{ opacity: loaded ? 1 : 0, transition: 'opacity 1s 1s ease' }}>
            Role para conhecer <ArrowDown size={15} className="motion-safe:animate-bounce" aria-hidden />
          </button>
        </div>
        <div className="absolute inset-x-0 bottom-0 flex justify-center px-4" style={{ perspective: '1600px' }}>
          <div style={{
            width: 'min(72rem, calc((100vh - 150px) * 1.55), 100%)',
            transform: `translateY(${(1 - ease) * 48}vh) rotateX(${(1 - ease) * 26}deg) scale(${0.84 + ease * 0.16})`,
            transformOrigin: '50% 100%',
            marginBottom: `${2 + ease * 5}vh`,
            opacity: loaded ? 1 : 0,
            transition: 'opacity 1.2s .5s ease',
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
    <section ref={ref} id="problema" className="relative h-[220vh]">
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

// ---- 3. showcase: pinned window, full screenshot, a spotlight on what the text talks about ----

interface Step {
  kicker: string
  title: string
  text: string
  img: string
  url: string
  /** Spotlight over the screenshot: left, top, width, height in percent. */
  spot: [number, number, number, number]
}

const STEPS: Step[] = [
  { kicker: 'Visão geral', title: 'A situação inteira em uma frase', text: 'Verde é tudo tranquilo. Vermelho é ataque em andamento. Ao lado, uma nota de 0 a 100 que sobe quando os problemas são resolvidos.', img: shotOverview, url: 'vps-soc · visão geral', spot: [18.5, 33, 79.5, 20] },
  { kicker: 'Prioridades', title: 'O que precisa de você, mais grave primeiro', text: 'Quatro números levam direto para a página certa, e a lista mostra os incidentes abertos em ordem de perigo.', img: shotOverview, url: 'vps-soc · visão geral', spot: [18.5, 54.5, 79.5, 44.5] },
  { kicker: 'Incidentes', title: 'Cada ataque explicado em português', text: 'Quem, de onde, quantas vezes e o que fez depois de entrar. Escrito com os dados reais, não com códigos de log.', img: shotIncident, url: 'vps-soc · incidente #10', spot: [18.5, 19, 80, 22] },
  { kicker: 'Contexto', title: 'Risco, origem e técnicas do MITRE ATT&CK', text: 'Cada incidente mostra o nível de risco, o IP e as técnicas de ataque envolvidas, com um botão para assumir a análise.', img: shotIncident, url: 'vps-soc · incidente #10', spot: [18.5, 41, 80, 30] },
  { kicker: 'Mapa', title: 'Onde está o servidor e de onde vêm os ataques', text: 'Cada IP que tentou entrar vira um ponto no mapa, com uma linha até o servidor. Ao lado, os países que mais atacaram.', img: shotMap, url: 'vps-soc · servidores', spot: [18.5, 24, 80, 59] },
  { kicker: 'Aplicações', title: 'O caminho até cada aplicação', text: 'Internet, firewall, servidor, domínios e aplicações. A peça vermelha é onde está o problema, e a lista acima diz o que fazer.', img: shotServices, url: 'vps-soc · aplicações', spot: [18.5, 38, 80, 61] },
  { kicker: 'Resposta automática', title: 'O SOC se defende sozinho', text: 'Bloqueia o IP atacante no firewall em segundos. Ações delicadas, como encerrar um processo, esperam o seu clique.', img: shotResponse, url: 'vps-soc · resposta automática', spot: [18.5, 25, 80, 37] },
  { kicker: 'Relatório', title: 'Um resumo pronto para o cliente', text: 'O período em uma página, em linguagem simples: ataques, bloqueios, países de origem e o que recomendamos fazer. Sai em PDF.', img: shotReport, url: 'vps-soc · relatório do cliente', spot: [26, 30, 63, 69] },
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
  const [x, y, w, h] = s.spot
  const move = still ? 'none' : `all 1s ${EASE}`

  return (
    <section className="relative">
      <div className="mx-auto max-w-7xl px-5 pt-16 text-center md:px-10">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/50">O painel</p>
        <SplitReveal text="Feito para entender, não para decorar" accent={['entender']} className="mt-4 text-4xl font-semibold tracking-tight md:text-6xl" />
      </div>
      <div className="mx-auto grid max-w-[88rem] gap-8 px-5 md:grid-cols-[minmax(0,0.62fr)_minmax(0,1.38fr)] md:gap-14 md:px-10">
        {/* Pinned window (first in DOM so it sits on top on phones) */}
        <div className="sticky top-16 z-10 order-first -mx-5 bg-[#07090d] px-5 pb-4 md:order-last md:top-0 md:mx-0 md:flex md:h-screen md:items-center md:bg-transparent md:px-0 md:pb-0">
          <div className="relative w-full pt-2 md:pt-0">
            <BrowserFrame url={s.url} className="w-full">
              <div className="relative aspect-[16/10] overflow-hidden">
                {STEPS.map((st, i) => (
                  st.img === (STEPS[i - 1]?.img) ? null : (
                    <img key={i} src={st.img} alt={st.img === s.img ? `${s.kicker}: ${s.title}` : ''} aria-hidden={st.img !== s.img}
                      className="absolute inset-0 h-full w-full object-cover"
                      style={{
                        opacity: st.img === s.img ? 1 : 0,
                        transform: st.img === s.img ? 'scale(1)' : 'scale(1.03)',
                        filter: st.img === s.img ? 'none' : 'blur(4px)',
                        transition: still ? 'none' : `opacity .7s ease, transform 1s ${EASE}, filter .7s ease`,
                      }} />
                  )
                ))}
                {/* Spotlight: everything outside the box dims */}
                <div className="pointer-events-none absolute rounded-xl" style={{
                  left: `${x}%`, top: `${y}%`, width: `${w}%`, height: `${h}%`,
                  boxShadow: '0 0 0 2px rgba(124,178,255,0.95), 0 0 40px 4px rgba(91,157,255,0.45), 0 0 0 200vmax rgba(5,7,10,0.58)',
                  transition: move,
                }}>
                  <span className="absolute -top-3 left-3 rounded-full px-2.5 py-0.5 text-[11px] font-semibold text-white shadow-lg" style={{ background: BUTTON }}>
                    {s.kicker}
                  </span>
                </div>
              </div>
            </BrowserFrame>
            <div className="mt-5 hidden gap-1.5 md:flex">
              {STEPS.map((st, i) => (
                <button key={i} onClick={() => scrollToEl(refs.current[i])} aria-label={`Ir para: ${st.kicker}`}
                  className="group flex-1 py-1.5">
                  <span className="block h-1 rounded-full transition-all duration-500 group-hover:opacity-100"
                    style={{ background: i <= active ? ACCENT : 'rgba(255,255,255,0.14)', opacity: i === active ? 1 : 0.85 }} />
                </button>
              ))}
            </div>
          </div>
        </div>
        {/* Texts */}
        <div className="md:py-[30vh]">
          {STEPS.map((st, i) => (
            <div key={i} ref={(el) => { refs.current[i] = el }} data-i={i} className="flex min-h-[70vh] items-center md:min-h-[85vh]">
              <div style={{ opacity: i === active ? 1 : 0.2, transform: i === active ? 'none' : 'translateY(18px)', filter: i === active ? 'none' : 'blur(2px)', transition: `opacity .6s ease, transform .8s ${EASE}, filter .6s ease` }}>
                <p className="text-xs font-semibold uppercase tracking-[0.2em]"><GradientText>{String(i + 1).padStart(2, '0')} · {st.kicker}</GradientText></p>
                <h3 className="mt-3 text-3xl font-semibold leading-tight tracking-tight md:text-[2.5rem]">{st.title}</h3>
                <p className="mt-4 max-w-md text-base leading-relaxed text-white/65 md:text-lg">{st.text}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ---- marquee of what it detects -------------------------------------------------------------

const DETECTS = ['Força bruta no SSH', 'Login depois de força bruta', 'Chave SSH plantada', 'Web shell', 'Porta suspeita aberta', 'Processo em /tmp', 'sudoers alterado', 'Cron malicioso', 'Disco cheio', 'Aplicação fora do ar', 'Crash loop no PM2', 'Certificado vencendo', 'Dependência vulnerável', 'Servidor offline']

function Marquee() {
  const row = [...DETECTS, ...DETECTS]
  return (
    <div className="relative mt-10 overflow-hidden py-6" aria-label={`O que o SOC detecta: ${DETECTS.join(', ')}`}>
      <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-32" style={{ background: 'linear-gradient(90deg, #07090d, transparent)' }} />
      <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-32" style={{ background: 'linear-gradient(270deg, #07090d, transparent)' }} />
      <div className="flex w-max gap-3 motion-safe:animate-[marquee_45s_linear_infinite]" aria-hidden>
        {row.map((d, i) => (
          <span key={i} className="whitespace-nowrap rounded-full border border-white/10 bg-white/[0.03] px-5 py-2 text-sm text-white/70">{d}</span>
        ))}
      </div>
    </div>
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
          <SplitReveal text="Do ataque ao alerta, em segundos" accent={['em', 'segundos']} className="mt-4 max-w-3xl text-4xl font-semibold tracking-tight md:text-6xl" />
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
      <SplitReveal text="Pequeno no servidor, completo no painel" accent={['completo', 'no', 'painel']} className="max-w-3xl text-4xl font-semibold tracking-tight md:text-6xl" />
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

// ---- 6. gallery: bento of real screens --------------------------------------------------------

function Gallery() {
  const [ref, p] = useSectionProgress<HTMLElement>()
  const rows: { img: string; title: string; text: string; wide: boolean }[][] = [
    [
      { img: shotMap, title: 'Mapa de ataques', text: 'Servidor e origem de cada ataque, por país.', wide: true },
      { img: shotReport, title: 'Relatório do cliente', text: 'Uma página, pronta para PDF.', wide: false },
    ],
    [
      { img: shotIncident, title: 'Incidente explicado', text: 'O que aconteceu, por que importa e o que fazer.', wide: false },
      { img: shotResponse, title: 'Resposta automática', text: 'Regras de defesa e ações esperando aprovação.', wide: true },
    ],
    [
      { img: shotArchitecture, title: 'Arquitetura das aplicações', text: 'O caminho de um acesso até cada aplicação.', wide: true },
      { img: shotServices, title: 'Aplicações', text: 'Saúde, tempo de resposta e segurança de cada app.', wide: false },
    ],
  ]
  return (
    <section ref={ref} className="relative py-28">
      <div className="mx-auto max-w-7xl px-5 md:px-10">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-white/50">Telas reais</p>
        <SplitReveal text="Tudo o que você viu está no painel" accent={['painel']} className="mt-4 max-w-3xl text-4xl font-semibold tracking-tight md:text-6xl" />
      </div>
      <div className="mx-auto mt-16 max-w-7xl space-y-6 px-5 md:space-y-8 md:px-10">
        {rows.map((row, r) => (
          <div key={r} className="grid gap-6 md:grid-cols-5 md:gap-8">
            {row.map((c, i) => (
              <ClipReveal key={c.title} delay={i * 140} className={c.wide ? 'md:col-span-3' : 'md:col-span-2 md:self-end'}
                style={{ translate: `0 ${(p - 0.5) * (i === 0 ? -24 : 24)}px` }}>
                <figure className="group">
                  <BrowserFrame url={c.title} className="transition-transform duration-500 group-hover:-translate-y-1">
                    <img src={c.img} alt={c.title} loading="lazy" className="block w-full" />
                  </BrowserFrame>
                  <figcaption className="mt-4 px-1">
                    <p className="font-semibold">{c.title}</p>
                    <p className="text-sm text-white/55">{c.text}</p>
                  </figcaption>
                </figure>
              </ClipReveal>
            ))}
          </div>
        ))}
      </div>
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
        <SplitReveal text="Seu servidor, vigiado de verdade." accent={['vigiado', 'de', 'verdade']} className="text-5xl font-semibold leading-[1.05] tracking-tight md:text-7xl" />
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
