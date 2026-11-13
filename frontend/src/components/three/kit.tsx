import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html, Line } from '@react-three/drei'
import * as THREE from 'three'

/*
 * Small toolkit shared by the 3D architecture view and the presentation:
 * theme colors read from the CSS tokens, a state ring under each piece, traffic particles
 * running along a curve, a straight-or-arched link and a DOM label that follows the theme.
 */

export type State3D = 'ok' | 'warn' | 'bad' | 'off'

export interface Palette {
  page: string
  ink: string
  muted: string
  line: string
  surface: string
  raised: string
  hud: string
  good: string
  warning: string
  critical: string
  s1: string
  s2: string
}

function readPalette(): Palette {
  const css = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => css.getPropertyValue(name).trim() || fallback
  return {
    page: v('--page', '#0b0f14'),
    ink: v('--ink', '#e8edf3'),
    muted: v('--muted', '#99a5b4'),
    line: v('--line', '#243040'),
    surface: v('--surface', '#121821'),
    raised: v('--raised', '#1a222d'),
    hud: v('--hud', '#5b9dff'),
    good: v('--good', '#22a35a'),
    warning: v('--warning', '#f0a92b'),
    critical: v('--critical', '#e04848'),
    s1: v('--s1', '#3987e5'),
    s2: v('--s2', '#d95926'),
  }
}

/** Theme colors as hex strings; follows the light/dark toggle. */
export function usePalette(): Palette {
  const [p, setP] = useState(readPalette)
  useEffect(() => {
    const obs = new MutationObserver(() => setP(readPalette()))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])
  return p
}

export function stateColor(p: Palette, s: State3D): string {
  return s === 'ok' ? p.good : s === 'warn' ? p.warning : s === 'bad' ? p.critical : p.muted
}

export { reducedMotion, webglAvailable } from './support'
import { reducedMotion } from './support'

/** Flat ring on the floor under a piece, colored by its state; pulses when broken. */
export function StateRing({ color, radius = 0.9, pulse = false, y = -0.55 }: { color: string; radius?: number; pulse?: boolean; y?: number }) {
  const ref = useRef<THREE.Mesh>(null)
  const still = reducedMotion()
  useFrame(({ clock }) => {
    if (!ref.current || !pulse || still) return
    const t = (clock.getElapsedTime() * 1.2) % 1
    ref.current.scale.setScalar(1 + t * 0.5)
    ;(ref.current.material as THREE.MeshBasicMaterial).opacity = 0.75 * (1 - t)
  })
  return (
    <group position={[0, y, 0]} rotation={[-Math.PI / 2, 0, 0]}>
      <mesh>
        <ringGeometry args={[radius * 0.86, radius, 64]} />
        <meshBasicMaterial color={color} transparent opacity={0.9} side={THREE.DoubleSide} />
      </mesh>
      {pulse && (
        <mesh ref={ref}>
          <ringGeometry args={[radius * 0.9, radius, 64]} />
          <meshBasicMaterial color={color} transparent opacity={0.6} side={THREE.DoubleSide} />
        </mesh>
      )}
    </group>
  )
}

export function makeCurve(a: THREE.Vector3, b: THREE.Vector3, lift = 0.6) {
  const mid = a.clone().add(b).multiplyScalar(0.5)
  mid.y += lift
  return new THREE.QuadraticBezierCurve3(a, mid, b)
}

/** The line itself. Dashed when the destination is broken. */
export function Link3D({ curve, color, dashed = false, opacity = 0.7, width = 1.5 }: {
  curve: THREE.Curve<THREE.Vector3>
  color: string
  dashed?: boolean
  opacity?: number
  width?: number
}) {
  const points = useMemo(() => curve.getPoints(48), [curve])
  return <Line points={points} color={color} lineWidth={width} dashed={dashed} dashSize={0.18} gapSize={0.12} transparent opacity={opacity} />
}

/**
 * Packets running along a curve. With {@code stopAt} < 1 they die before the end and flash,
 * which reads as "traffic does not get through here".
 */
export function Particles({ curve, color, count = 6, speed = 0.25, size = 0.06, stopAt = 1, reverse = false, visible = true }: {
  curve: THREE.Curve<THREE.Vector3>
  color: string
  count?: number
  speed?: number
  size?: number
  stopAt?: number
  reverse?: boolean
  visible?: boolean
}) {
  const ref = useRef<THREE.InstancedMesh>(null)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const offsets = useMemo(() => Array.from({ length: count }, (_, i) => i / count), [count])
  const still = reducedMotion()
  useFrame(({ clock }) => {
    const mesh = ref.current
    if (!mesh) return
    const t0 = still ? 0.35 : clock.getElapsedTime() * speed
    offsets.forEach((o, i) => {
      let t = (t0 + o) % 1
      const dying = t > stopAt
      if (reverse) t = 1 - t
      const pt = curve.getPoint(Math.min(t, 1))
      dummy.position.copy(pt)
      const s = dying ? Math.max(0, 1 - (t - stopAt) / (1 - stopAt + 1e-6)) * 1.8 : 1
      dummy.scale.setScalar(stopAt < 1 && dying ? s : 1)
      dummy.updateMatrix()
      mesh.setMatrixAt(i, dummy.matrix)
    })
    mesh.instanceMatrix.needsUpdate = true
  })
  return (
    <instancedMesh ref={ref} args={[undefined, undefined, count]} visible={visible}>
      <sphereGeometry args={[size, 12, 12]} />
      <meshBasicMaterial color={color} toneMapped={false} />
    </instancedMesh>
  )
}

/** DOM label pinned to a 3D point (crisp text, follows the theme). */
export function Label3D({ position, title, detail, color, emphasis = false, dim = false, children }: {
  position: [number, number, number]
  title: string
  detail?: string
  color?: string
  emphasis?: boolean
  dim?: boolean
  children?: ReactNode
}) {
  return (
    <Html position={position} center distanceFactor={9} zIndexRange={[20, 0]} style={{ pointerEvents: 'none', transition: 'opacity .3s', opacity: dim ? 0.25 : 1 }}>
      <div className={`whitespace-nowrap rounded-lg border bg-surface/90 px-2.5 py-1.5 text-center shadow-lg backdrop-blur ${emphasis ? 'border-[var(--hud)]' : 'border-line'}`}
        style={{ fontSize: 13 }}>
        <div className="flex items-center justify-center gap-1.5 font-semibold text-ink">
          {color && <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />}
          {title}
        </div>
        {detail && <div className="text-ink2" style={{ fontSize: 11.5 }}>{detail}</div>}
        {children}
      </div>
    </Html>
  )
}
