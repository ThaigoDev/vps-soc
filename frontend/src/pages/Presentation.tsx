import { Suspense, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { ContactShadows, Environment, Float, Lightformer, RoundedBox, Sparkles, Stars } from '@react-three/drei'
import * as THREE from 'three'
import { ArrowDown, ArrowRight, BookOpen, Github, Shield } from 'lucide-react'
import type { Host, ServiceView } from '../api'
import { buildFlow } from '../components/InfraFlow'
import { ArchScene } from '../components/three/AppArchitecture3D'
import { Laptop } from '../components/three/Laptop'
import { Label3D, Link3D, Particles, StateRing, makeCurve, reducedMotion, usePalette, webglAvailable } from '../components/three/kit'
import shotOverview from '../assets/presentation/overview.jpg'
import shotIncident from '../assets/presentation/incident.jpg'
import shotMap from '../assets/presentation/map.jpg'
import shotArchitecture from '../assets/presentation/architecture.jpg'
import shotReport from '../assets/presentation/report.jpg'

/*
 * Scroll-telling presentation of the project. A fixed 3D stage sits behind the text:
 *   - a laptop showing real screenshots of the dashboard (it opens on the cover and the
 *     screen cross-fades between pages as you scroll);
 *   - a model of the whole system (attackers, firewall, VPS + agent, Tailscale tunnel,
 *     backend, database, dashboard, phone) whose traffic turns on chapter by chapter;
 *   - the application architecture view used in the dashboard.
 * Each chapter flies the camera to its subject. Public route (/apresentacao) and an offline
 * single-file build (npm run build:presentation); demo data only.
 */

const SCREENS = [shotOverview, shotIncident, shotMap, shotArchitecture, shotReport]
type Screen = 'overview' | 'incident' | 'map' | 'architecture' | 'report'
const SCREEN_INDEX: Record<Screen, number> = { overview: 0, incident: 1, map: 2, architecture: 3, report: 4 }

type Phase = 'cover' | 'problem' | 'agent' | 'tunnel' | 'detect' | 'respond' | 'alerts' | 'all'
const order: Phase[] = ['cover', 'problem', 'agent', 'tunnel', 'detect', 'respond', 'alerts', 'all']

interface Chapter {
  kicker: string
  title: string
  body: ReactNode
  cam: [number, number, number]
  look: [number, number, number]
  phase: Phase
  /** Shows the laptop with this page of the dashboard. */
  screen?: Screen
  /** Laptop turn (radians) while this chapter is on. */
  turn?: number
  tags?: string[]
}

const APP_Z = -30
const LAPTOP: [number, number, number] = [0, -0.4, 26]
const atLaptop = (dx: number, dy: number, dz: number): [number, number, number] => [LAPTOP[0] + dx, LAPTOP[1] + dy, LAPTOP[2] + dz]

const chapters: Chapter[] = [
  {
    kicker: 'VPS-SOC',
    title: 'Segurança de servidor que qualquer pessoa entende',
    body: <>Um centro de operações de segurança para a sua VPS: vigia 24 horas, entende os ataques, reage sozinho e explica tudo em português.</>,
    cam: atLaptop(0, 2.0, 5.6), look: atLaptop(0, 1.0, 0), phase: 'cover', screen: 'overview', turn: -0.35,
    tags: ['Agente em Go', 'Detecção + MITRE ATT&CK', 'Resposta automática', 'Painel em português'],
  },
  {
    kicker: 'O problema',
    title: 'Toda VPS é atacada minutos depois de ligada',
    body: <>Robôs no mundo inteiro tentam adivinhar a senha do SSH o dia todo. Quem cuida do servidor raramente olha os logs, e só percebe a invasão quando o estrago já aconteceu.</>,
    cam: [-9.5, 4, 8.5], look: [-7, 0, 0], phase: 'problem',
  },
  {
    kicker: 'O agente',
    title: 'Um programa pequeno de vigia dentro da VPS',
    body: (
      <ul className="space-y-2">
        <li>Lê os logins (SSH e sudo) em tempo real</li>
        <li>Percebe portas novas e processos suspeitos</li>
        <li>Vigia arquivos críticos: chaves SSH, sudoers, cron</li>
        <li>Mede CPU, memória, disco e as aplicações do PM2</li>
      </ul>
    ),
    cam: [-2.4, 3.2, 6.5], look: [-3, 0.2, 0], phase: 'agent',
  },
  {
    kicker: 'Caminho seguro',
    title: 'Os eventos saem por um túnel criptografado',
    body: <>O agente envia tudo pelo Tailscale para o SOC, que roda <b className="text-ink">fora</b> da VPS. Se um invasor tomar o servidor, não consegue apagar o histórico, e o silêncio do agente vira um alerta.</>,
    cam: [0, 5, 10], look: [0, 0, 0], phase: 'tunnel',
  },
  {
    kicker: 'Detecção',
    title: 'Regras transformam eventos em incidentes',
    body: <>Força bruta, login depois de força bruta, chave SSH plantada, web shell… Cada incidente ganha nível de risco e as técnicas do MITRE ATT&amp;CK envolvidas.</>,
    cam: [4.8, 4.6, 7.5], look: [3, 0, -1.2], phase: 'detect',
  },
  {
    kicker: 'Resposta automática',
    title: 'O atacante é bloqueado em segundos',
    body: <>O SOC manda o agente colocar o IP no firewall da VPS e os ataques param de chegar. Ações delicadas, como encerrar um processo, esperam a aprovação de uma pessoa.</>,
    cam: [-6, 5.2, 9.5], look: [-5.6, 0, 0], phase: 'respond',
  },
  {
    kicker: 'Alertas',
    title: 'O aviso chega no celular, mesmo com o painel fechado',
    body: <>Incidentes graves vão para o Telegram na hora. No navegador, uma sirene e uma notificação avisam quem estiver de plantão.</>,
    cam: [8.8, 4.4, 8.4], look: [5.6, 0.2, 0], phase: 'alerts',
  },
  {
    kicker: 'O painel',
    title: 'A situação inteira em uma tela',
    body: <>Uma frase diz se está tudo bem. Logo abaixo, o que precisa de atenção, os servidores, as aplicações e a atividade das últimas horas.</>,
    cam: atLaptop(-0.4, 2.0, 5.4), look: atLaptop(0, 1.0, 0), phase: 'all', screen: 'overview', turn: 0.3,
  },
  {
    kicker: 'Incidentes explicados',
    title: 'O que aconteceu, por que importa e o que fazer',
    body: <>Cada incidente é escrito com os dados reais: quem, de onde, quantas vezes e o que fez depois. Os próximos passos vêm com o comando pronto para copiar.</>,
    cam: atLaptop(0.2, 1.9, 5.7), look: atLaptop(0, 1.0, 0), phase: 'all', screen: 'incident', turn: -0.25,
  },
  {
    kicker: 'Mapa de ataques',
    title: 'Onde está o servidor e de onde vêm os ataques',
    body: <>O mapa-múndi mostra o servidor e cada IP que tentou entrar, com linhas até o alvo. Ao lado, os países que mais atacaram.</>,
    cam: atLaptop(-0.6, 1.9, 5.3), look: atLaptop(0, 1.0, 0), phase: 'all', screen: 'map', turn: 0.22,
  },
  {
    kicker: 'Arquitetura em 3D',
    title: 'Veja onde está o problema, peça por peça',
    body: <>Internet, firewall, servidor, domínios e portas, aplicações. Cada peça tem a cor do seu estado e o tráfego para onde algo quebrou. No painel, dá para girar e clicar em cada uma.</>,
    cam: [1.5, 12, APP_Z + 15], look: [1.2, 0, APP_Z], phase: 'all',
  },
  {
    kicker: 'Relatório do cliente',
    title: 'Um resumo de uma página, pronto para enviar',
    body: <>Tentativas de invasão, alertas, o que foi bloqueado sozinho, países de origem e o que recomendamos fazer, em linguagem simples. Sai em PDF com um clique.</>,
    cam: atLaptop(0.4, 1.9, 5.3), look: atLaptop(0, 1.0, 0), phase: 'all', screen: 'report', turn: -0.3,
  },
  {
    kicker: 'Feito com',
    title: 'Go, Java/Spring Boot, React e PostgreSQL',
    body: <>Agente em Go de poucos megabytes, backend em Spring Boot com PostgreSQL, painel em React com three.js. Tudo sobe com um único <code className="font-mono text-ink">docker compose up</code>.</>,
    cam: atLaptop(3.2, 3.4, 8.5), look: atLaptop(-0.6, 0.8, -3), phase: 'all', screen: 'overview', turn: -0.5,
  },
]

/** {@code standalone}: the offline single-file build, without links into the dashboard. */
export default function Presentation({ standalone = false }: { standalone?: boolean }) {
  const [step, setStep] = useState(0)
  const refs = useRef<(HTMLElement | null)[]>([])
  const [progress, setProgress] = useState(0)
  const gl = useMemo(webglAvailable, [])
  useDarkTheme()

  useEffect(() => {
    const io = new IntersectionObserver((entries) => {
      for (const e of entries) if (e.isIntersecting) setStep(Number((e.target as HTMLElement).dataset.step))
    }, { rootMargin: '-45% 0px -45% 0px' })
    refs.current.forEach((el) => el && io.observe(el))
    const onScroll = () => {
      const max = document.documentElement.scrollHeight - window.innerHeight
      setProgress(max > 0 ? window.scrollY / max : 0)
    }
    window.addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    return () => {
      io.disconnect()
      window.removeEventListener('scroll', onScroll)
    }
  }, [])

  const go = (i: number) => refs.current[i]?.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'center' })
  const chapter = chapters[step]
  // The laptop keeps showing the last page it showed while the camera is elsewhere.
  const lastScreen = useRef<Screen>('overview')
  if (chapter.screen) lastScreen.current = chapter.screen

  return (
    <div className="relative bg-page text-ink">
      <div className="fixed inset-0" aria-hidden>
        <div className="absolute inset-0" style={{ background: 'radial-gradient(ellipse 80% 60% at 65% 35%, rgba(91,157,255,0.16), transparent 60%), radial-gradient(ellipse 60% 50% at 85% 85%, rgba(167,139,250,0.12), transparent 60%), var(--page)' }} />
        {gl && (
          <Canvas camera={{ position: chapters[0].cam, fov: 40 }} dpr={[1, 2]} gl={{ antialias: true, alpha: true }}>
            <Stage step={step} screen={lastScreen.current} />
          </Canvas>
        )}
        <div className="pointer-events-none absolute inset-0 hidden md:block" style={{ background: 'linear-gradient(90deg, rgba(11,15,20,0.88) 0%, rgba(11,15,20,0.45) 32%, transparent 52%)' }} />
        <div className="pointer-events-none absolute inset-x-0 bottom-0 h-1/2 md:hidden" style={{ background: 'linear-gradient(0deg, rgba(11,15,20,0.92), transparent)' }} />
      </div>

      {/* Top bar */}
      <header className="fixed inset-x-0 top-0 z-20 flex items-center gap-3 px-5 py-4 md:px-8">
        <span className="flex items-center gap-2 font-semibold tracking-tight">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg" style={{ background: 'linear-gradient(135deg, #5b9dff, #8b5cf6)' }}>
            <Shield size={17} className="text-white" aria-hidden />
          </span>
          VPS-SOC
        </span>
        <span className="tnum ml-3 hidden text-xs text-muted sm:inline">{String(step + 1).padStart(2, '0')} / {String(chapters.length).padStart(2, '0')}</span>
        {!standalone && (
          <div className="ml-auto flex items-center gap-2">
            <Link to="/" className="rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-sm backdrop-blur hover:bg-white/10">Abrir o painel</Link>
          </div>
        )}
      </header>
      <div className="fixed inset-x-0 top-0 z-30 h-[3px]">
        <div className="h-full" style={{ width: `${progress * 100}%`, background: 'linear-gradient(90deg, #5b9dff, #a78bfa)' }} />
      </div>

      {/* Chapter dots */}
      <nav className="fixed right-5 top-1/2 z-20 hidden -translate-y-1/2 flex-col gap-3 md:flex" aria-label="Capítulos">
        {chapters.map((c, i) => (
          <button key={c.title} onClick={() => go(i)} aria-label={`Ir para: ${c.kicker}`} aria-current={i === step}
            className="group relative flex items-center justify-end">
            <span className="pointer-events-none absolute right-5 whitespace-nowrap rounded-md bg-surface/90 px-2 py-0.5 text-xs text-ink2 opacity-0 transition-opacity group-hover:opacity-100">{c.kicker}</span>
            <span className={`block rounded-full transition-all ${i === step ? 'h-6 w-1.5 bg-[#5b9dff]' : 'h-1.5 w-1.5 bg-white/35 group-hover:bg-white/70'}`} />
          </button>
        ))}
      </nav>

      {/* Chapters */}
      <main className="relative z-10">
        {chapters.map((c, i) => (
          <section key={c.title} ref={(el) => { refs.current[i] = el }} data-step={i}
            className="flex min-h-screen items-end px-4 pb-10 pt-24 md:items-center md:px-12 md:py-24 lg:px-20">
            <Card chapter={c} index={i} active={i === step} first={i === 0} last={i === chapters.length - 1} standalone={standalone} onNext={() => go(1)} />
          </section>
        ))}
      </main>
    </div>
  )
}

function Card({ chapter: c, index, active, first, last, standalone, onNext }: {
  chapter: Chapter
  index: number
  active: boolean
  first: boolean
  last: boolean
  standalone: boolean
  onNext: () => void
}) {
  return (
    <div className={`relative w-full max-w-[30rem] overflow-hidden rounded-3xl border p-7 shadow-2xl transition-all duration-700 md:p-8 ${active ? 'translate-y-0 opacity-100' : 'translate-y-8 opacity-30'}`}
      style={{ borderColor: 'rgba(255,255,255,0.10)', background: 'linear-gradient(160deg, rgba(23,30,42,0.78), rgba(12,16,23,0.62))', backdropFilter: 'blur(18px)', WebkitBackdropFilter: 'blur(18px)' }}>
      <span className="pointer-events-none absolute -right-2 -top-6 select-none text-[7rem] font-bold leading-none text-white/[0.04]">{String(index + 1).padStart(2, '0')}</span>
      <p className="text-xs font-semibold uppercase tracking-[0.18em]" style={{ background: 'linear-gradient(90deg, #7cb2ff, #b69cff)', WebkitBackgroundClip: 'text', backgroundClip: 'text', color: 'transparent' }}>
        {c.kicker}
      </p>
      <h2 className={`mt-3 font-semibold leading-[1.1] tracking-tight text-white ${first ? 'text-4xl md:text-5xl' : 'text-[1.75rem] md:text-3xl'}`}>{c.title}</h2>
      <div className="mt-4 text-[15.5px] leading-relaxed text-ink2 [&_li]:relative [&_li]:pl-5 [&_li]:before:absolute [&_li]:before:left-0 [&_li]:before:top-[0.6em] [&_li]:before:h-1.5 [&_li]:before:w-1.5 [&_li]:before:rounded-full [&_li]:before:bg-[#5b9dff]">
        {c.body}
      </div>
      {c.tags && (
        <ul className="mt-5 flex flex-wrap gap-2">
          {c.tags.map((t) => <li key={t} className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-ink2">{t}</li>)}
        </ul>
      )}
      {first && (
        <button onClick={onNext} className="mt-7 inline-flex items-center gap-2 rounded-full px-5 py-2.5 text-sm font-semibold text-white shadow-lg hover:brightness-110"
          style={{ background: 'linear-gradient(90deg, #3b82f6, #7c3aed)' }}>
          Começar <ArrowDown size={15} className="motion-safe:animate-bounce" aria-hidden />
        </button>
      )}
      {last && (
        <div className="mt-7 flex flex-wrap gap-2">
          {!standalone && (
            <Link to="/" className="inline-flex items-center gap-1.5 rounded-full px-5 py-2.5 text-sm font-semibold text-white hover:brightness-110"
              style={{ background: 'linear-gradient(90deg, #3b82f6, #7c3aed)' }}>
              Abrir o painel <ArrowRight size={15} aria-hidden />
            </Link>
          )}
          <a href="https://github.com/ThaigoDev/vps-soc" target="_blank" rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-white/5 px-4 py-2.5 text-sm hover:bg-white/10">
            <Github size={15} aria-hidden /> Código no GitHub
          </a>
          <a href="https://github.com/ThaigoDev/vps-soc/blob/main/docs/GUIA.md" target="_blank" rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-white/5 px-4 py-2.5 text-sm hover:bg-white/10">
            <BookOpen size={15} aria-hidden /> Guia
          </a>
        </div>
      )}
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

function Stage({ step, screen }: { step: number; screen: Screen }) {
  const p = usePalette()
  const c = chapters[step]
  return (
    <>
      <fog attach="fog" args={[p.page, 26, 80]} />
      <ambientLight intensity={0.55} />
      <directionalLight position={[6, 10, 8]} intensity={1.1} />
      <directionalLight position={[-8, 5, -6]} intensity={0.35} color="#a78bfa" />
      <Environment resolution={256} frames={1}>
        <Lightformer form="rect" intensity={2.2} position={[0, 5, 8]} scale={[10, 4, 1]} color="#ffffff" />
        <Lightformer form="rect" intensity={1.4} position={[-6, 2, 2]} rotation-y={Math.PI / 2} scale={[8, 2, 1]} color="#7cb2ff" />
        <Lightformer form="rect" intensity={1.2} position={[6, 2, 2]} rotation-y={-Math.PI / 2} scale={[8, 2, 1]} color="#b69cff" />
      </Environment>
      <Stars radius={90} depth={50} count={1800} factor={3} saturation={0} fade speed={0.4} />
      <CameraRig step={step} />
      <SystemScene phase={c.phase} labels={!c.screen && c.phase !== 'all'} />
      <group position={[0, 0, APP_Z]}>
        <DemoApps visible={chapters[step].kicker === 'Arquitetura em 3D'} />
      </group>
      <LaptopStage step={step} screen={screen} />
    </>
  )
}

/** The laptop: opens on load, turns a little per chapter, floats gently. */
function LaptopStage({ step, screen }: { step: number; screen: Screen }) {
  const turn = useRef<THREE.Group>(null)
  const [open, setOpen] = useState(0)
  const still = reducedMotion()
  useEffect(() => {
    const t = window.setTimeout(() => setOpen(1), still ? 0 : 500)
    return () => window.clearTimeout(t)
  }, [still])
  useFrame((_, dt) => {
    if (!turn.current) return
    const target = chapters[step].turn ?? 0
    turn.current.rotation.y += (target - turn.current.rotation.y) * (still ? 1 : 1 - Math.exp(-dt * 2))
  })
  const p = usePalette()
  return (
    <group position={LAPTOP}>
      <Float speed={still ? 0 : 1.2} rotationIntensity={0.08} floatIntensity={0.25} floatingRange={[0, 0.12]}>
        <group ref={turn} rotation={[0, chapters[0].turn ?? 0, 0]}>
          <Suspense fallback={null}>
            <Laptop screens={SCREENS} current={SCREEN_INDEX[screen]} open={open} />
          </Suspense>
          {/* Soft screen glow on the floor */}
          <pointLight position={[0, 1.2, 1.4]} intensity={6} distance={6} color="#7cb2ff" />
        </group>
      </Float>
      <ContactShadows position={[0, -0.02, 0]} opacity={0.55} scale={12} blur={2.6} far={4} color="#000000" />
      <Sparkles count={still ? 0 : 50} scale={[10, 4, 8]} position={[0, 1.6, 0]} size={2.2} speed={0.25} opacity={0.6} color={p.hud} />
    </group>
  )
}

/**
 * Glides the camera to the pose of the current chapter. The projection is shifted so the
 * subject sits beside the text card: to the right on wide screens, above it on phones
 * (where the camera also backs off, because the view is narrow).
 */
function CameraRig({ step }: { step: number }) {
  const { camera, size } = useThree()
  const look = useRef(new THREE.Vector3(...chapters[0].look))
  const still = reducedMotion()
  const narrow = size.width < 768
  useEffect(() => {
    const cam = camera as THREE.PerspectiveCamera
    if (narrow) cam.setViewOffset(size.width, size.height, 0, size.height * 0.2, size.width, size.height)
    else cam.setViewOffset(size.width, size.height, -size.width * 0.18, 0, size.width, size.height)
    cam.updateProjectionMatrix()
  }, [camera, size.width, size.height, narrow])
  useFrame((_, dt) => {
    const c = chapters[step]
    const target = new THREE.Vector3(...c.look)
    const pos = new THREE.Vector3(...c.cam).sub(target).multiplyScalar(narrow ? 1.9 : 1).add(target)
    const k = still ? 1 : 1 - Math.exp(-dt * 2.2)
    camera.position.lerp(pos, k)
    look.current.lerp(target, k)
    camera.lookAt(look.current)
  })
  return null
}

const P = {
  globe: new THREE.Vector3(-9, 0, 0),
  firewall: new THREE.Vector3(-6, 0, 0),
  vps: new THREE.Vector3(-3, 0, 0),
  backend: new THREE.Vector3(3, 0, 0),
  db: new THREE.Vector3(3, 0, -2.6),
  screen: new THREE.Vector3(6.4, 0.35, 1.3),
  phone: new THREE.Vector3(6.4, 0, -1.4),
}

/** The whole system: attackers, firewall, VPS + agent, tunnel, SOC backend, database, dashboard, phone. */
function SystemScene({ phase, labels }: { phase: Phase; labels: boolean }) {
  const p = usePalette()
  const attack = useMemo(() => makeCurve(P.globe, P.vps, 1.2), [])
  const tunnel = useMemo(() => new THREE.LineCurve3(new THREE.Vector3(-2.2, 0, 0), new THREE.Vector3(2.2, 0, 0)), [])
  const toDb = useMemo(() => makeCurve(P.backend, P.db, 0.3), [])
  const toScreen = useMemo(() => makeCurve(P.backend, P.screen, 0.6), [])
  const toPhone = useMemo(() => makeCurve(P.backend, P.phone, 0.6), [])
  const after = (ph: Phase) => order.indexOf(phase) >= order.indexOf(ph)
  const blocked = after('respond')
  const focus = (...ph: Phase[]) => phase === 'all' || ph.includes(phase)

  return (
    <group>
      <gridHelper args={[60, 60, p.line, p.line]} position={[0, -0.56, -10]} />

      {/* Internet / attackers */}
      <Globe position={P.globe} color={p.critical} />
      {labels && <Label3D position={[P.globe.x, 1.2, 0]} title="Internet" detail="robôs tentando senhas" color={p.critical} dim={!focus('problem', 'respond')} />}
      <Link3D curve={attack} color={p.critical} opacity={0.35} dashed />
      <Particles curve={attack} color={p.critical} count={10} speed={0.3} stopAt={blocked ? 0.38 : 1} visible />

      {/* Firewall */}
      <mesh position={P.firewall}>
        <boxGeometry args={[0.18, 1.5, 2.2]} />
        <meshStandardMaterial color={blocked ? p.critical : p.good} transparent opacity={blocked ? 0.75 : 0.35}
          emissive={blocked ? p.critical : p.good} emissiveIntensity={blocked ? 0.6 : 0.2} />
      </mesh>
      <StateRing color={blocked ? p.critical : p.good} radius={0.9} pulse={phase === 'respond'} />
      {labels && <Label3D position={[P.firewall.x, 1.25, 0]} title="Firewall" detail={blocked ? 'atacante bloqueado' : 'nftables na VPS'} color={blocked ? p.critical : p.good} dim={!focus('respond')} />}

      {/* VPS + agent */}
      <group position={P.vps}>
        <RoundedBox args={[1.4, 0.95, 1.4]} radius={0.12} smoothness={4}>
          <meshStandardMaterial color={p.raised} emissive={p.hud} emissiveIntensity={phase === 'agent' ? 0.25 : 0.05} />
        </RoundedBox>
        {[-0.2, 0.05, 0.3].map((y) => (
          <mesh key={y} position={[0, y - 0.05, 0.71]}>
            <boxGeometry args={[1, 0.05, 0.02]} />
            <meshBasicMaterial color={p.good} toneMapped={false} />
          </mesh>
        ))}
        <AgentChip color={p.hud} active={phase === 'agent'} />
        <StateRing color={p.hud} radius={1.15} />
      </group>
      {labels && <Label3D position={[P.vps.x, 1.55, 0]} title="Sua VPS + agente" detail="Go · 6 MB" color={p.hud} dim={!focus('problem', 'agent', 'tunnel')} />}

      {/* Tunnel */}
      <mesh position={[0, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <cylinderGeometry args={[0.32, 0.32, 4.4, 32, 1, true]} />
        <meshStandardMaterial color={p.hud} transparent opacity={after('tunnel') ? 0.18 : 0.06} side={THREE.DoubleSide} emissive={p.hud} emissiveIntensity={0.2} />
      </mesh>
      <Particles curve={tunnel} color={p.hud} count={8} speed={0.35} visible={after('tunnel')} />
      <Particles curve={tunnel} color={p.warning} count={3} speed={0.45} reverse visible={phase === 'respond'} size={0.08} />
      {labels && <Label3D position={[0, 0.85, 0]} title="Túnel Tailscale" detail="criptografado" color={p.hud} dim={!focus('tunnel')} />}

      {/* SOC backend */}
      <group position={P.backend}>
        <RoundedBox args={[1.5, 1.1, 1.5]} radius={0.14} smoothness={4}>
          <meshStandardMaterial color={p.raised} emissive={p.hud} emissiveIntensity={phase === 'detect' ? 0.3 : 0.06} />
        </RoundedBox>
        <RulesRings active={phase === 'detect'} color={p.hud} />
        <StateRing color={p.hud} radius={1.2} />
      </group>
      {labels && <Label3D position={[P.backend.x, 1.65, 0]} title="SOC (backend)" detail="regras · incidentes · resposta" color={p.hud} dim={!focus('tunnel', 'detect', 'respond', 'alerts')} />}

      {/* Database */}
      <mesh position={P.db}>
        <cylinderGeometry args={[0.55, 0.55, 0.9, 40]} />
        <meshStandardMaterial color={p.raised} emissive={p.s1} emissiveIntensity={phase === 'detect' ? 0.3 : 0.06} />
      </mesh>
      <Link3D curve={toDb} color={p.line} />
      <Particles curve={toDb} color={p.s1} count={3} speed={0.3} visible={after('detect')} />
      {labels && <Label3D position={[P.db.x, 1.0, P.db.z]} title="PostgreSQL" detail="histórico" dim={!focus('detect')} />}

      {/* Dashboard screen */}
      <group position={P.screen} rotation={[0, -0.35, 0]}>
        <RoundedBox args={[1.9, 1.15, 0.08]} radius={0.04} smoothness={4}>
          <meshStandardMaterial color={p.surface} emissive={p.hud} emissiveIntensity={phase === 'alerts' ? 0.25 : 0.05} />
        </RoundedBox>
        {[0.32, 0.1, -0.12, -0.34].map((y, i) => (
          <mesh key={y} position={[-0.25 + (i % 2) * 0.1, y, 0.05]}>
            <boxGeometry args={[1.1 - i * 0.15, 0.08, 0.01]} />
            <meshBasicMaterial color={i === 0 ? p.critical : p.line} toneMapped={false} />
          </mesh>
        ))}
      </group>
      <Link3D curve={toScreen} color={p.line} />
      <Particles curve={toScreen} color={p.hud} count={3} speed={0.3} visible={after('alerts')} />
      {labels && <Label3D position={[P.screen.x, 1.3, P.screen.z]} title="Painel" detail="React" dim={!focus('alerts')} />}

      {/* Phone */}
      <group position={P.phone}>
        <RoundedBox args={[0.5, 0.95, 0.08]} radius={0.06} smoothness={4}>
          <meshStandardMaterial color={p.surface} emissive={p.warning} emissiveIntensity={phase === 'alerts' ? 0.35 : 0.05} />
        </RoundedBox>
      </group>
      <Link3D curve={toPhone} color={p.line} />
      <Particles curve={toPhone} color={p.warning} count={2} speed={0.3} visible={after('alerts')} />
      {labels && <Label3D position={[P.phone.x, 0.95, P.phone.z]} title="Telegram" detail="alerta no celular" dim={!focus('alerts')} />}
    </group>
  )
}

function Globe({ position, color }: { position: THREE.Vector3; color: string }) {
  const ref = useRef<THREE.Mesh>(null)
  const still = reducedMotion()
  useFrame((_, dt) => {
    if (ref.current && !still) ref.current.rotation.y += dt * 0.25
  })
  return (
    <group position={position}>
      <mesh ref={ref}>
        <icosahedronGeometry args={[0.85, 2]} />
        <meshStandardMaterial color={color} wireframe emissive={color} emissiveIntensity={0.25} />
      </mesh>
      <StateRing color={color} radius={1.1} pulse />
    </group>
  )
}

function AgentChip({ color, active }: { color: string; active: boolean }) {
  const ref = useRef<THREE.Mesh>(null)
  const still = reducedMotion()
  useFrame(({ clock }) => {
    if (!ref.current) return
    ref.current.position.y = 0.72 + (still ? 0 : Math.sin(clock.getElapsedTime() * 2) * 0.05)
    ref.current.rotation.y += still ? 0 : 0.01
  })
  return (
    <mesh ref={ref} position={[0, 0.72, 0]}>
      <octahedronGeometry args={[0.2, 0]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={active ? 1 : 0.4} />
    </mesh>
  )
}

function RulesRings({ active, color }: { active: boolean; color: string }) {
  const ref = useRef<THREE.Group>(null)
  const still = reducedMotion()
  useFrame((_, dt) => {
    if (ref.current && !still) ref.current.rotation.y += dt * (active ? 1.2 : 0.3)
  })
  return (
    <group ref={ref} position={[0, 0.85, 0]}>
      {[0.35, 0.5, 0.65].map((r, i) => (
        <mesh key={r} rotation={[Math.PI / 2 + i * 0.35, i * 0.6, 0]}>
          <torusGeometry args={[r, 0.015, 8, 48]} />
          <meshBasicMaterial color={color} transparent opacity={active ? 0.9 : 0.35} toneMapped={false} />
        </mesh>
      ))}
    </group>
  )
}

// ---- demo application architecture (same model as the dashboard) -------------------------

const day = 86_400_000
const demoHost = {
  id: 'vps-demo', status: 'ONLINE', lastSeen: new Date().toISOString(), firstSeen: new Date().toISOString(), heartbeatIntervalSeconds: 30,
  metrics: { cpuPercent: 34, memPercent: 61, diskPercent: 72 },
  posture: { firewall: { enabled: true, blockedIps: 3 }, ssh: { passwordAuthentication: 'no' }, failedUnits: [] },
  openPorts: [
    { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', exe: '/usr/sbin/sshd' },
    { proto: 'tcp', address: '0.0.0.0', port: 443, process: 'nginx', exe: '/usr/sbin/nginx' },
    { proto: 'tcp', address: '0.0.0.0', port: 4444, process: 'kworkerd', exe: '/tmp/.x/kworkerd' },
  ],
} as unknown as Host

const app = (name: string, pmId: number, health: ServiceView['health'], ports: number[], extra: Record<string, unknown> = {}) => ({
  hostId: 'vps-demo', health, reasons: health === 'DOWN' ? ['caiu e o PM2 parou de reiniciar'] : [],
  pm2: { name, pmId, pm2Home: '/root/.pm2', status: health === 'DOWN' ? 'errored' : 'online', ports, probe: health === 'DOWN' ? undefined : { ok: true, latencyMs: 30 + pmId * 12 }, ...extra },
}) as unknown as ServiceView

const demoServices: ServiceView[] = [
  app('loja-api', 0, 'HEALTHY', [3000], { sites: [{ domains: ['loja.exemplo.com'], proxyPorts: [3000], tls: true, certificate: { notAfter: new Date(Date.now() + 60 * day).toISOString() }, configFile: 'loja' }] }),
  app('site', 1, 'HEALTHY', [3001], { sites: [{ domains: ['exemplo.com'], proxyPorts: [3001], tls: true, certificate: { notAfter: new Date(Date.now() + 80 * day).toISOString() }, configFile: 'site' }] }),
  app('worker-emails', 2, 'DOWN', [3002]),
]

function DemoApps({ visible }: { visible: boolean }) {
  const data = useMemo(() => buildFlow({ host: demoHost, services: demoServices, attackers: { total: 18, breached: 0, blocked: 3 } }), [])
  return <group visible={visible}><ArchScene data={data} labels={visible} /></group>
}
