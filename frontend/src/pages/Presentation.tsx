import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { RoundedBox } from '@react-three/drei'
import * as THREE from 'three'
import { ArrowDown, ArrowRight, BookOpen, Shield } from 'lucide-react'
import type { Host, ServiceView } from '../api'
import { buildFlow } from '../components/InfraFlow'
import { ArchScene } from '../components/three/AppArchitecture3D'
import { Label3D, Link3D, Particles, StateRing, makeCurve, reducedMotion, usePalette, webglAvailable } from '../components/three/kit'

/*
 * Scroll-telling presentation of the project. A 3D model of the whole system stays fixed
 * behind the text; each section moves the camera to the part it talks about and turns on
 * the traffic that matters there (attacks, events, response orders, alerts). The last
 * chapters fly to the application architecture view used in the dashboard.
 * Public route (/apresentacao): no login, demo data only.
 */

interface Chapter {
  kicker: string
  title: string
  body: ReactNode
  cam: [number, number, number]
  look: [number, number, number]
}

const APP_Z = -30

const chapters: Chapter[] = [
  {
    kicker: 'VPS-SOC',
    title: 'Um centro de operações de segurança para a sua VPS',
    body: <>Vigia o servidor 24 horas, entende os ataques, reage sozinho e explica tudo em português. Role para ver como funciona.</>,
    cam: [0, 9, 17], look: [0, 0, -0.5],
  },
  {
    kicker: '1 · O problema',
    title: 'Toda VPS é atacada minutos depois de ligada',
    body: <>Robôs no mundo inteiro tentam adivinhar a senha do SSH o dia todo. Quem cuida do servidor raramente olha os logs, e só percebe a invasão quando o estrago já aconteceu.</>,
    cam: [-9.5, 4, 8.5], look: [-7, 0, 0],
  },
  {
    kicker: '2 · O agente',
    title: 'Um programa pequeno dentro da VPS',
    body: (
      <ul className="space-y-1.5">
        <li>• Lê os logins (SSH e sudo) em tempo real</li>
        <li>• Percebe portas novas e processos suspeitos</li>
        <li>• Vigia arquivos críticos: chaves SSH, sudoers, cron</li>
        <li>• Mede CPU, memória, disco e as aplicações do PM2</li>
      </ul>
    ),
    cam: [-2.4, 3.2, 6.5], look: [-3, 0.2, 0],
  },
  {
    kicker: '3 · Caminho seguro',
    title: 'Os eventos saem da VPS por um túnel criptografado',
    body: <>O agente envia tudo pelo Tailscale para o SOC, que roda <b>fora</b> da VPS. Se um invasor tomar o servidor, não consegue apagar o histórico, e o silêncio do agente vira um alerta.</>,
    cam: [0, 5, 10], look: [0, 0, 0],
  },
  {
    kicker: '4 · Detecção',
    title: 'Regras transformam eventos em incidentes',
    body: <>Força bruta, login depois de força bruta, chave SSH plantada, web shell… Cada incidente vem com nível de risco, técnicas do MITRE ATT&amp;CK e um texto explicando o que aconteceu e o que fazer.</>,
    cam: [4.8, 4.6, 7.5], look: [3, 0, -1.2],
  },
  {
    kicker: '5 · Resposta automática',
    title: 'O SOC manda o agente bloquear o atacante',
    body: <>Em segundos o IP vai para o firewall da VPS e os ataques param de chegar. Ações mais delicadas, como encerrar um processo, esperam a aprovação de uma pessoa.</>,
    cam: [-6, 5.2, 9.5], look: [-5.6, 0, 0],
  },
  {
    kicker: '6 · Painel e alertas',
    title: 'Tudo num painel simples, e o alerta chega no celular',
    body: <>A situação em uma frase, o mapa dos ataques, os incidentes com passo a passo e um relatório pronto para o cliente. Incidentes graves também chegam pelo Telegram.</>,
    cam: [8.8, 4.4, 8.4], look: [5.6, 0.2, 0],
  },
  {
    kicker: '7 · As aplicações',
    title: 'Veja onde está o problema, peça por peça',
    body: <>O caminho de um acesso: internet, firewall, servidor, domínios e portas, aplicações. Cada peça tem a cor do seu estado; o tráfego para onde algo quebrou. No painel, dá para girar e clicar em cada uma.</>,
    cam: [1.5, 12, APP_Z + 15], look: [1.2, 0, APP_Z],
  },
  {
    kicker: 'Feito com',
    title: 'Go, Java/Spring Boot, React e PostgreSQL',
    body: <>Agente em Go (6 MB, sem dependências), backend em Spring Boot com PostgreSQL, painel em React. Tudo sobe com um <code className="font-mono">docker compose up</code>.</>,
    cam: [6, 24, 12], look: [0, 0, -13],
  },
]

/** {@code standalone}: the offline single-file build, without links into the dashboard. */
export default function Presentation({ standalone = false }: { standalone?: boolean }) {
  const [step, setStep] = useState(0)
  const refs = useRef<(HTMLElement | null)[]>([])
  const [progress, setProgress] = useState(0)
  const gl = useMemo(webglAvailable, [])

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

  return (
    <div className="relative bg-page text-ink">
      <div className="fixed inset-0" aria-hidden>
        {gl ? (
          <Canvas camera={{ position: chapters[0].cam, fov: 42 }} dpr={[1, 2]}>
            <ambientLight intensity={0.7} />
            <directionalLight position={[6, 10, 8]} intensity={1.1} />
            <directionalLight position={[-8, 5, -6]} intensity={0.35} />
            <CameraRig step={step} />
            <SystemScene step={step} />
            <group position={[0, 0, APP_Z]}>
              <DemoApps visible={step >= 7} />
            </group>
          </Canvas>
        ) : (
          <div className="h-full w-full" style={{ background: 'radial-gradient(ellipse at 60% 40%, color-mix(in srgb, var(--hud) 14%, var(--page)), var(--page))' }} />
        )}
        <div className="pointer-events-none absolute inset-0" style={{ background: 'linear-gradient(90deg, color-mix(in srgb, var(--page) 85%, transparent) 0%, color-mix(in srgb, var(--page) 40%, transparent) 30%, transparent 50%)' }} />
      </div>

      {/* Top bar */}
      <header className="fixed inset-x-0 top-0 z-20 flex items-center gap-3 px-5 py-4">
        <span className="flex items-center gap-2 font-semibold"><Shield size={20} className="text-hud" aria-hidden /> VPS-SOC</span>
        {!standalone && (
          <div className="ml-auto flex items-center gap-2">
            <Link to="/" className="rounded-lg border border-line bg-surface/80 px-3 py-1.5 text-sm backdrop-blur hover:bg-raised">Abrir o painel</Link>
          </div>
        )}
      </header>
      <div className="fixed inset-x-0 top-0 z-30 h-0.5 bg-transparent">
        <div className="h-full bg-[var(--hud)]" style={{ width: `${progress * 100}%` }} />
      </div>

      {/* Chapter dots */}
      <nav className="fixed right-4 top-1/2 z-20 hidden -translate-y-1/2 flex-col gap-2.5 md:flex" aria-label="Capítulos">
        {chapters.map((c, i) => (
          <button key={c.title} onClick={() => go(i)} title={c.kicker} aria-label={`Ir para: ${c.kicker}`} aria-current={i === step}
            className={`h-2.5 w-2.5 rounded-full border transition-all ${i === step ? 'scale-125 border-[var(--hud)] bg-[var(--hud)]' : 'border-[var(--muted)] bg-transparent hover:bg-[var(--muted)]'}`} />
        ))}
      </nav>

      {/* Chapters */}
      <main className="relative z-10">
        {chapters.map((c, i) => (
          <section key={c.title} ref={(el) => { refs.current[i] = el }} data-step={i}
            className="flex min-h-screen items-end px-4 pb-10 pt-24 md:items-center md:px-12 md:py-24 lg:px-20">
            <div className={`max-w-md rounded-2xl border p-6 backdrop-blur-md transition-all duration-500 ${i === step ? 'translate-y-0 opacity-100' : 'translate-y-6 opacity-40'}`}
              style={{ borderColor: 'var(--line)', background: 'color-mix(in srgb, var(--surface) 82%, transparent)' }}>
              <p className="text-xs font-semibold uppercase tracking-wider text-hud">{c.kicker}</p>
              <h2 className={`mt-2 font-semibold tracking-tight ${i === 0 ? 'text-4xl' : 'text-2xl'}`}>{c.title}</h2>
              <div className="mt-3 text-[15px] leading-relaxed text-ink2">{c.body}</div>
              {i === 0 && (
                <button onClick={() => go(1)} className="mt-6 inline-flex items-center gap-1.5 text-sm font-semibold text-hud">
                  Começar <ArrowDown size={15} aria-hidden />
                </button>
              )}
              {i === chapters.length - 1 && (
                <div className="mt-6 flex flex-wrap gap-2">
                  {!standalone && (
                    <Link to="/" className="inline-flex items-center gap-1.5 rounded-lg bg-[var(--primary)] px-3.5 py-2 text-sm font-semibold text-white hover:brightness-110">
                      Abrir o painel <ArrowRight size={15} aria-hidden />
                    </Link>
                  )}
                  <a href="https://github.com/ThaigoDev/vps-soc/blob/main/docs/GUIA.md" target="_blank" rel="noreferrer"
                    className="inline-flex items-center gap-1.5 rounded-lg border border-line px-3.5 py-2 text-sm hover:bg-raised">
                    <BookOpen size={15} aria-hidden /> Guia do projeto
                  </a>
                </div>
              )}
            </div>
          </section>
        ))}
      </main>
    </div>
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
    else cam.setViewOffset(size.width, size.height, -size.width * 0.17, 0, size.width, size.height)
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
function SystemScene({ step }: { step: number }) {
  const p = usePalette()
  const attack = useMemo(() => makeCurve(P.globe, P.vps, 1.2), [])
  const tunnel = useMemo(() => new THREE.LineCurve3(new THREE.Vector3(-2.2, 0, 0), new THREE.Vector3(2.2, 0, 0)), [])
  const toDb = useMemo(() => makeCurve(P.backend, P.db, 0.3), [])
  const toScreen = useMemo(() => makeCurve(P.backend, P.screen, 0.6), [])
  const toPhone = useMemo(() => makeCurve(P.backend, P.phone, 0.6), [])
  const blocked = step >= 5
  const focus = (...ids: number[]) => step === 0 || step >= 8 || ids.includes(step)

  return (
    <group>
      <gridHelper args={[60, 60, p.line, p.line]} position={[0, -0.56, -10]} />

      {/* Internet / attackers */}
      <Globe position={P.globe} color={p.critical} />
      <Label3D position={[P.globe.x, 1.2, 0]} title="Internet" detail="robôs tentando senhas" color={p.critical} dim={!focus(1, 5)} />
      <Link3D curve={attack} color={p.critical} opacity={0.35} dashed />
      <Particles curve={attack} color={p.critical} count={10} speed={0.3} stopAt={blocked ? 0.38 : 1} visible={step >= 1 || step === 0} />

      {/* Firewall */}
      <mesh position={P.firewall}>
        <boxGeometry args={[0.18, 1.5, 2.2]} />
        <meshStandardMaterial color={blocked ? p.critical : p.good} transparent opacity={blocked ? 0.75 : 0.35}
          emissive={blocked ? p.critical : p.good} emissiveIntensity={blocked ? 0.6 : 0.2} />
      </mesh>
      <StateRing color={blocked ? p.critical : p.good} radius={0.9} pulse={step === 5} />
      <Label3D position={[P.firewall.x, 1.25, 0]} title="Firewall" detail={blocked ? 'atacante bloqueado' : 'nftables na VPS'} color={blocked ? p.critical : p.good} dim={!focus(5)} />

      {/* VPS + agent */}
      <group position={P.vps}>
        <RoundedBox args={[1.4, 0.95, 1.4]} radius={0.12} smoothness={4}>
          <meshStandardMaterial color={p.raised} emissive={p.hud} emissiveIntensity={focus(2) && step === 2 ? 0.25 : 0.05} />
        </RoundedBox>
        {[-0.2, 0.05, 0.3].map((y) => (
          <mesh key={y} position={[0, y - 0.05, 0.71]}>
            <boxGeometry args={[1, 0.05, 0.02]} />
            <meshBasicMaterial color={p.good} toneMapped={false} />
          </mesh>
        ))}
        <AgentChip color={p.hud} active={step === 2} />
        <StateRing color={p.hud} radius={1.15} />
      </group>
      <Label3D position={[P.vps.x, 1.55, 0]} title="Sua VPS + agente" detail="Go · 6 MB" color={p.hud} dim={!focus(1, 2, 3)} />

      {/* Tunnel */}
      <mesh position={[0, 0, 0]} rotation={[0, 0, Math.PI / 2]}>
        <cylinderGeometry args={[0.32, 0.32, 4.4, 32, 1, true]} />
        <meshStandardMaterial color={p.hud} transparent opacity={step >= 3 ? 0.18 : 0.06} side={THREE.DoubleSide} emissive={p.hud} emissiveIntensity={0.2} />
      </mesh>
      <Particles curve={tunnel} color={p.hud} count={8} speed={0.35} visible={step >= 3} />
      <Particles curve={tunnel} color={p.warning} count={3} speed={0.45} reverse visible={step === 5} size={0.08} />
      <Label3D position={[0, 0.85, 0]} title="Túnel Tailscale" detail="criptografado" color={p.hud} dim={!focus(3)} />

      {/* SOC backend */}
      <group position={P.backend}>
        <RoundedBox args={[1.5, 1.1, 1.5]} radius={0.14} smoothness={4}>
          <meshStandardMaterial color={p.raised} emissive={p.hud} emissiveIntensity={step === 4 ? 0.3 : 0.06} />
        </RoundedBox>
        <RulesRings active={step === 4} color={p.hud} />
        <StateRing color={p.hud} radius={1.2} />
      </group>
      <Label3D position={[P.backend.x, 1.65, 0]} title="SOC (backend)" detail="regras · incidentes · resposta" color={p.hud} dim={!focus(3, 4, 5, 6)} />

      {/* Database */}
      <mesh position={P.db}>
        <cylinderGeometry args={[0.55, 0.55, 0.9, 40]} />
        <meshStandardMaterial color={p.raised} emissive={p.s1} emissiveIntensity={step === 4 ? 0.3 : 0.06} />
      </mesh>
      <Link3D curve={toDb} color={p.line} />
      <Particles curve={toDb} color={p.s1} count={3} speed={0.3} visible={step >= 4} />
      <Label3D position={[P.db.x, 1.0, P.db.z]} title="PostgreSQL" detail="histórico" dim={!focus(4)} />

      {/* Dashboard screen */}
      <group position={P.screen} rotation={[0, -0.35, 0]}>
        <RoundedBox args={[1.9, 1.15, 0.08]} radius={0.04} smoothness={4}>
          <meshStandardMaterial color={p.surface} emissive={p.hud} emissiveIntensity={step === 6 ? 0.25 : 0.05} />
        </RoundedBox>
        {[0.32, 0.1, -0.12, -0.34].map((y, i) => (
          <mesh key={y} position={[-0.25 + (i % 2) * 0.1, y, 0.05]}>
            <boxGeometry args={[1.1 - i * 0.15, 0.08, 0.01]} />
            <meshBasicMaterial color={i === 0 ? p.critical : p.line} toneMapped={false} />
          </mesh>
        ))}
      </group>
      <Link3D curve={toScreen} color={p.line} />
      <Particles curve={toScreen} color={p.hud} count={3} speed={0.3} visible={step >= 6} />
      <Label3D position={[P.screen.x, 1.3, P.screen.z]} title="Painel" detail="React" dim={!focus(6)} />

      {/* Phone */}
      <group position={P.phone}>
        <RoundedBox args={[0.5, 0.95, 0.08]} radius={0.06} smoothness={4}>
          <meshStandardMaterial color={p.surface} emissive={p.warning} emissiveIntensity={step === 6 ? 0.35 : 0.05} />
        </RoundedBox>
      </group>
      <Link3D curve={toPhone} color={p.line} />
      <Particles curve={toPhone} color={p.warning} count={2} speed={0.3} visible={step >= 6} />
      <Label3D position={[P.phone.x, 0.95, P.phone.z]} title="Telegram" detail="alerta no celular" dim={!focus(6)} />
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
