import { useEffect, useMemo, useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { RoundedBox, useTexture } from '@react-three/drei'
import * as THREE from 'three'
import { reducedMotion } from './support'

/*
 * A minimal laptop built from primitives. The screen shows a real screenshot of the
 * dashboard and cross-fades when the screenshot changes; the lid opens with `open` (0..1).
 * Screen aspect 16:10, like the 1600x1000 captures it displays.
 */

const W = 3.2
const D = 2.2
const SCREEN_W = 2.96
const SCREEN_H = SCREEN_W / 1.6

export function Laptop({ screens, current, open = 1, bodyColor = '#3b414b' }: {
  screens: string[]
  current: number
  open?: number
  bodyColor?: string
}) {
  const lid = useRef<THREE.Group>(null)
  const still = reducedMotion()
  const textures = useTexture(screens)
  useEffect(() => {
    for (const t of textures) {
      t.colorSpace = THREE.SRGBColorSpace
      t.anisotropy = 8
    }
  }, [textures])

  // Closed: lid folded flat over the keyboard. Open: tilted ~105° back.
  useFrame((_, dt) => {
    if (!lid.current) return
    const target = THREE.MathUtils.lerp(Math.PI / 2 - 0.02, -0.28, open)
    const k = still ? 1 : 1 - Math.exp(-dt * 3)
    lid.current.rotation.x += (target - lid.current.rotation.x) * k
  })

  const metal = useMemo(() => ({ color: bodyColor, metalness: 0.65, roughness: 0.32 }), [bodyColor])

  return (
    <group>
      {/* Base */}
      <RoundedBox args={[W, 0.12, D]} radius={0.05} smoothness={4} position={[0, 0.06, 0]}>
        <meshStandardMaterial {...metal} />
      </RoundedBox>
      {/* Keyboard well and trackpad */}
      <mesh position={[0, 0.121, -0.28]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[W * 0.86, D * 0.42]} />
        <meshStandardMaterial color="#14171c" roughness={0.8} />
      </mesh>
      <Keys />
      <mesh position={[0, 0.121, 0.62]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[1.1, 0.62]} />
        <meshStandardMaterial color={bodyColor} metalness={0.5} roughness={0.25} />
      </mesh>

      {/* Lid, hinged at the back edge */}
      <group ref={lid} position={[0, 0.12, -D / 2 + 0.04]} rotation={[Math.PI / 2 - 0.02, 0, 0]}>
        <RoundedBox args={[W, 2.08, 0.07]} radius={0.04} smoothness={4} position={[0, 1.04, -0.035]}>
          <meshStandardMaterial {...metal} />
        </RoundedBox>
        <mesh position={[0, 1.04, 0.002]}>
          <planeGeometry args={[W - 0.08, 2.0]} />
          <meshStandardMaterial color="#05070a" roughness={0.2} metalness={0.2} />
        </mesh>
        <Screen textures={textures} current={current} />
      </group>
    </group>
  )
}

/** Two stacked planes: the new screenshot fades in over the previous one. */
function Screen({ textures, current }: { textures: THREE.Texture[]; current: number }) {
  const back = useRef<THREE.MeshBasicMaterial>(null)
  const front = useRef<THREE.MeshBasicMaterial>(null)
  const state = useRef({ shown: current, fade: 1 })
  const still = reducedMotion()

  useFrame((_, dt) => {
    const s = state.current
    if (!back.current || !front.current) return
    if (s.shown !== current) {
      back.current.map = textures[s.shown]
      back.current.needsUpdate = true
      front.current.map = textures[current]
      front.current.needsUpdate = true
      s.shown = current
      s.fade = still ? 1 : 0
    }
    s.fade = Math.min(1, s.fade + dt * 2.5)
    front.current.opacity = s.fade
  })

  return (
    <group position={[0, 1.04, 0.006]}>
      <mesh>
        <planeGeometry args={[SCREEN_W, SCREEN_H]} />
        <meshBasicMaterial ref={back} map={textures[current]} toneMapped={false} />
      </mesh>
      <mesh position={[0, 0, 0.002]}>
        <planeGeometry args={[SCREEN_W, SCREEN_H]} />
        <meshBasicMaterial ref={front} map={textures[current]} toneMapped={false} transparent />
      </mesh>
    </group>
  )
}

/** A grid of low keys, instanced. */
function Keys() {
  const ref = useRef<THREE.InstancedMesh>(null)
  const cols = 14
  const rows = 5
  useEffect(() => {
    const m = ref.current
    if (!m) return
    const d = new THREE.Object3D()
    let i = 0
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        d.position.set((c - (cols - 1) / 2) * 0.19, 0.13, -0.66 + r * 0.19)
        d.updateMatrix()
        m.setMatrixAt(i++, d.matrix)
      }
    }
    m.instanceMatrix.needsUpdate = true
  }, [])
  return (
    <instancedMesh ref={ref} args={[undefined, undefined, cols * rows]}>
      <boxGeometry args={[0.16, 0.02, 0.16]} />
      <meshStandardMaterial color="#20242b" roughness={0.6} />
    </instancedMesh>
  )
}
