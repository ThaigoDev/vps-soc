import { useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Canvas, useFrame, type ThreeEvent } from '@react-three/fiber'
import { OrbitControls, RoundedBox } from '@react-three/drei'
import * as THREE from 'three'
import { ExternalLink, Pause, Play, RotateCcw, X } from 'lucide-react'
import { Label3D, Link3D, Particles, StateRing, makeCurve, reducedMotion, stateColor, usePalette, type Palette, type State3D } from './kit'

/*
 * Minimal 3D model of how traffic reaches the applications of one server:
 *   Internet (globe) → Firewall (wall) → Server (box) → Entrances (portals) → Applications (cubes)
 * Each piece sits on a ring colored by its state; packets flow along the links and die at
 * the piece that is broken. Drag to orbit, scroll to zoom, click a piece for its details.
 */

export interface ArchNode {
  id: string
  col: number
  title: string
  detail: string
  state: State3D
  problem?: string
  to?: string
}

export interface ArchData {
  nodes: ArchNode[]
  links: [string, string][]
}

export const COLUMN_NAMES = ['Internet', 'Firewall', 'Servidor', 'Entradas', 'Aplicações']
const COL_GAP = 3.4
const ROW_GAP = 1.5

export function layout(nodes: ArchNode[]) {
  const pos = new Map<string, THREE.Vector3>()
  for (let c = 0; c < COLUMN_NAMES.length; c++) {
    const col = nodes.filter((n) => n.col === c)
    col.forEach((n, i) => pos.set(n.id, new THREE.Vector3((c - 2) * COL_GAP, 0, (i - (col.length - 1) / 2) * ROW_GAP)))
  }
  return pos
}

/** The scene content, without a canvas (the presentation reuses it). */
export function ArchScene({ data, selected, onSelect, animate = true, labels = true }: {
  data: ArchData
  selected?: string | null
  onSelect?: (id: string | null) => void
  animate?: boolean
  labels?: boolean
}) {
  const p = usePalette()
  const pos = useMemo(() => layout(data.nodes), [data.nodes])
  const byId = useMemo(() => new Map(data.nodes.map((n) => [n.id, n])), [data.nodes])
  const [hover, setHover] = useState<string | null>(null)

  return (
    <group>
      {data.links.map(([a, b]) => {
        const pa = pos.get(a), pb = pos.get(b), nb = byId.get(b)
        if (!pa || !pb || !nb) return null
        const curve = makeCurve(pa, pb, 0.5)
        const broken = nb.state === 'bad'
        const color = broken ? p.critical : nb.state === 'warn' ? p.warning : p.line
        return (
          <group key={`${a}->${b}`}>
            <Link3D curve={curve} color={color} dashed={broken} opacity={broken ? 0.95 : 0.85} width={broken ? 2 : 1.4} />
            {animate && <Particles curve={curve} color={broken ? p.critical : p.hud} count={broken ? 3 : 4} speed={0.22} stopAt={broken ? 0.82 : 1} />}
          </group>
        )
      })}
      {data.nodes.map((n) => (
        <Piece key={n.id} node={n} position={pos.get(n.id)!} palette={p} labels={labels}
          hovered={hover === n.id} selected={selected === n.id}
          onHover={(h) => setHover(h ? n.id : null)} onClick={() => onSelect?.(selected === n.id ? null : n.id)} />
      ))}
    </group>
  )
}

function Piece({ node: n, position, palette: p, hovered, selected, onHover, onClick, labels }: {
  node: ArchNode
  position: THREE.Vector3
  palette: Palette
  hovered: boolean
  selected: boolean
  onHover: (h: boolean) => void
  onClick: () => void
  labels: boolean
}) {
  const ref = useRef<THREE.Group>(null)
  const spin = useRef<THREE.Mesh>(null)
  const color = stateColor(p, n.state)
  const still = reducedMotion()
  useFrame((_, dt) => {
    if (!ref.current) return
    const target = hovered || selected ? 1.12 : 1
    const s = ref.current.scale.x + (target - ref.current.scale.x) * Math.min(1, dt * 10)
    ref.current.scale.setScalar(s)
    if (spin.current && !still) spin.current.rotation.y += dt * 0.3
  })
  const body = p.raised
  const handlers = {
    onPointerOver: (e: ThreeEvent<PointerEvent>) => { e.stopPropagation(); onHover(true); document.body.style.cursor = 'pointer' },
    onPointerOut: () => { onHover(false); document.body.style.cursor = '' },
    onClick: (e: ThreeEvent<MouseEvent>) => { e.stopPropagation(); onClick() },
  }
  const emissive = n.state === 'bad' ? p.critical : n.state === 'warn' ? p.warning : p.hud
  const emissiveIntensity = n.state === 'bad' ? 0.3 : n.state === 'warn' ? 0.1 : hovered || selected ? 0.25 : 0.05

  return (
    <group position={position}>
      <group ref={ref} {...handlers}>
        {n.col === 0 && (
          <mesh ref={spin}>
            <icosahedronGeometry args={[0.62, 1]} />
            <meshStandardMaterial color={body} emissive={emissive} emissiveIntensity={emissiveIntensity} wireframe />
          </mesh>
        )}
        {n.col === 1 && (
          <mesh>
            <boxGeometry args={[0.16, 1.15, 1.5]} />
            <meshStandardMaterial color={color} transparent opacity={0.55} emissive={color} emissiveIntensity={0.35} />
          </mesh>
        )}
        {n.col === 2 && (
          <group>
            <RoundedBox args={[1.25, 0.85, 1.25]} radius={0.12} smoothness={4}>
              <meshStandardMaterial color={body} emissive={emissive} emissiveIntensity={emissiveIntensity} roughness={0.5} metalness={0.1} />
            </RoundedBox>
            {[-0.18, 0.05, 0.28].map((y) => (
              <mesh key={y} position={[0, y - 0.05, 0.63]}>
                <boxGeometry args={[0.9, 0.05, 0.02]} />
                <meshBasicMaterial color={color} toneMapped={false} />
              </mesh>
            ))}
          </group>
        )}
        {n.col === 3 && (
          <mesh rotation={[0, 0, Math.PI / 2]}>
            <torusGeometry args={[0.42, 0.07, 16, 48]} />
            <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.35} />
          </mesh>
        )}
        {n.col === 4 && (
          <RoundedBox args={[0.75, 0.75, 0.75]} radius={0.1} smoothness={4}>
            <meshStandardMaterial color={body} emissive={emissive} emissiveIntensity={emissiveIntensity} roughness={0.45} />
          </RoundedBox>
        )}
      </group>
      <StateRing color={color} radius={n.col === 2 ? 1.05 : 0.7} pulse={n.state === 'bad'} />
      {labels && (
        <Label3D position={[0, n.col === 2 ? 1.0 : 0.85, 0]} title={n.title} detail={hovered || selected ? n.detail : undefined}
          color={color} emphasis={hovered || selected} />
      )}
    </group>
  )
}

/** Canvas + overlays (toolbar, hint, detail panel) for the dashboard. */
export default function ArchitectureView({ data, height = 460 }: { data: ArchData; height?: number }) {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<string | null>(null)
  const [auto, setAuto] = useState(false)
  const [key, setKey] = useState(0)
  const node = data.nodes.find((n) => n.id === selected)
  const rows = Math.max(1, ...COLUMN_NAMES.map((_, c) => data.nodes.filter((n) => n.col === c).length))
  const p = usePalette()

  return (
    <div className="relative overflow-hidden rounded-xl border border-line"
      style={{ height, background: `radial-gradient(ellipse at 50% 35%, color-mix(in srgb, var(--hud) 9%, var(--surface)), var(--page))` }}>
      <Canvas key={key} camera={{ position: [0, 6.2 + rows * 0.45, 8 + rows * 0.95], fov: 32 }} dpr={[1, 2]} onPointerMissed={() => setSelected(null)}
        aria-label="Modelo 3D da arquitetura das aplicações">
        <ambientLight intensity={0.7} />
        <directionalLight position={[5, 10, 6]} intensity={1.1} />
        <directionalLight position={[-6, 4, -4]} intensity={0.35} />
        <gridHelper args={[30, 30, p.line, p.line]} position={[0, -0.56, 0]} />
        <ArchScene data={data} selected={selected} onSelect={setSelected} />
        <OrbitControls makeDefault enablePan={false} enableDamping minDistance={6} maxDistance={22} maxPolarAngle={Math.PI / 2.15}
          autoRotate={auto && !selected} autoRotateSpeed={0.5} />
      </Canvas>

      {/* Column legend */}
      <div className="pointer-events-none absolute left-3 top-3 z-30 flex flex-wrap gap-1.5 text-[11px] text-ink2">
        {COLUMN_NAMES.map((c, i) => (
          <span key={c} className="rounded-full border border-line bg-surface/80 px-2 py-0.5 backdrop-blur">{i + 1}. {c}</span>
        ))}
      </div>

      {/* Toolbar */}
      <div className="absolute bottom-3 left-3 z-30 flex items-center gap-1.5">
        <button onClick={() => setAuto(!auto)} className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface/90 px-2.5 py-1.5 text-xs text-ink2 backdrop-blur hover:text-ink"
          aria-pressed={auto} title={auto ? 'Parar a rotação' : 'Girar sozinho'}>
          {auto ? <Pause size={13} aria-hidden /> : <Play size={13} aria-hidden />} {auto ? 'Pausar' : 'Girar'}
        </button>
        <button onClick={() => { setSelected(null); setKey((k) => k + 1) }} className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface/90 px-2.5 py-1.5 text-xs text-ink2 backdrop-blur hover:text-ink">
          <RotateCcw size={13} aria-hidden /> Recentralizar
        </button>
        <span className="hidden text-[11px] text-muted sm:inline">Arraste para girar · role para aproximar · clique numa peça</span>
      </div>

      {/* Detail panel */}
      {node && (
        <div className="absolute right-3 top-3 z-30 w-72 rounded-xl border border-line bg-surface/95 p-4 shadow-xl backdrop-blur">
          <button onClick={() => setSelected(null)} className="absolute right-2 top-2 rounded-md p-1 text-muted hover:text-ink" aria-label="Fechar">
            <X size={15} aria-hidden />
          </button>
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted">{COLUMN_NAMES[node.col]}</p>
          <p className="mt-0.5 pr-6 font-semibold">{node.title}</p>
          <p className="mt-1 text-sm text-ink2">{node.detail}</p>
          <p className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold" style={{ color: stateColor(p, node.state) }}>
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: stateColor(p, node.state) }} />
            {node.state === 'ok' ? 'Funcionando' : node.state === 'warn' ? 'Atenção' : node.state === 'bad' ? 'Problema' : 'Sem dados'}
          </p>
          {node.problem && <p className="mt-2 rounded-lg bg-raised p-2 text-xs text-ink">{node.problem}</p>}
          {node.to && (
            <button onClick={() => navigate(node.to!)} className="mt-3 inline-flex items-center gap-1 text-xs font-semibold text-hud hover:underline">
              Abrir detalhes <ExternalLink size={12} aria-hidden />
            </button>
          )}
        </div>
      )}
    </div>
  )
}
