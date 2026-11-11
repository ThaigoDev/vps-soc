import { useMemo, useState } from 'react'
import { geoGraticule10, geoNaturalEarth1, geoPath } from 'd3-geo'
import { feature } from 'topojson-client'
import type { Feature, FeatureCollection, Geometry } from 'geojson'
import type { GeometryCollection, Topology } from 'topojson-specification'
import worldData from 'world-atlas/countries-110m.json'
import type { AttackMap, MapAttacker, MapServer } from '../api'

/*
 * World map: servers as pins, attacking IPs as dots sized by how many attempts they made,
 * arcs from each attacker to the server, and attacking countries tinted. Pure SVG (d3-geo
 * only computes the paths), so it follows the theme tokens and prints well.
 */

const W = 960
const H = 470

const world = worldData as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>
const countries = (feature(world, world.objects.countries) as FeatureCollection<Geometry, { name: string }>).features

// ISO 3166 numeric → alpha-2 for the countries the geolocation service reports most; the map
// tints a country only when it can match it, so missing entries just stay neutral.
const NUMERIC_TO_A2: Record<string, string> = {
  '004': 'AF', '008': 'AL', '012': 'DZ', '024': 'AO', '032': 'AR', '036': 'AU', '040': 'AT', '050': 'BD', '056': 'BE',
  '068': 'BO', '076': 'BR', '100': 'BG', '104': 'MM', '112': 'BY', '116': 'KH', '120': 'CM', '124': 'CA', '152': 'CL',
  '156': 'CN', '158': 'TW', '170': 'CO', '180': 'CD', '188': 'CR', '191': 'HR', '192': 'CU', '203': 'CZ', '208': 'DK',
  '214': 'DO', '218': 'EC', '222': 'SV', '231': 'ET', '233': 'EE', '246': 'FI', '250': 'FR', '268': 'GE', '276': 'DE',
  '288': 'GH', '300': 'GR', '320': 'GT', '340': 'HN', '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID', '364': 'IR',
  '368': 'IQ', '372': 'IE', '376': 'IL', '380': 'IT', '384': 'CI', '392': 'JP', '398': 'KZ', '400': 'JO', '404': 'KE',
  '408': 'KP', '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA', '422': 'LB', '428': 'LV', '434': 'LY', '440': 'LT',
  '458': 'MY', '484': 'MX', '496': 'MN', '498': 'MD', '504': 'MA', '508': 'MZ', '524': 'NP', '528': 'NL', '554': 'NZ',
  '558': 'NI', '566': 'NG', '578': 'NO', '586': 'PK', '591': 'PA', '600': 'PY', '604': 'PE', '608': 'PH', '616': 'PL',
  '620': 'PT', '630': 'PR', '642': 'RO', '643': 'RU', '682': 'SA', '686': 'SN', '688': 'RS', '702': 'SG', '703': 'SK',
  '704': 'VN', '705': 'SI', '710': 'ZA', '724': 'ES', '752': 'SE', '756': 'CH', '760': 'SY', '762': 'TJ', '764': 'TH',
  '784': 'AE', '788': 'TN', '792': 'TR', '795': 'TM', '800': 'UG', '804': 'UA', '818': 'EG', '826': 'GB', '834': 'TZ',
  '840': 'US', '858': 'UY', '860': 'UZ', '862': 'VE', '887': 'YE', '894': 'ZM', '716': 'ZW',
}

const regionNames = (() => {
  try {
    return new Intl.DisplayNames(['pt-BR'], { type: 'region' })
  } catch {
    return null
  }
})()

/** Country name in Portuguese from its two-letter code. */
export function countryName(code?: string, fallback?: string): string {
  if (!code) return fallback ?? 'Desconhecido'
  try {
    return regionNames?.of(code) ?? fallback ?? code
  } catch {
    return fallback ?? code
  }
}

type Hover =
  | { kind: 'server'; s: MapServer; x: number; y: number }
  | { kind: 'attacker'; a: MapAttacker; x: number; y: number }
  | null

export function WorldMap({ data, compact = false, onSelectServer }: {
  data: AttackMap
  compact?: boolean
  onSelectServer?: (hostId: string) => void
}) {
  const [hover, setHover] = useState<Hover>(null)
  const projection = useMemo(() => geoNaturalEarth1().fitExtent([[8, 8], [W - 8, H - 8]], { type: 'Sphere' }), [])
  const path = useMemo(() => geoPath(projection), [projection])

  const failuresByCountry = useMemo(() => {
    const m = new Map<string, number>()
    for (const c of data.countries) m.set(c.code, c.failures)
    return m
  }, [data.countries])
  const maxCountry = Math.max(1, ...data.countries.map((c) => c.failures))
  const maxFailures = Math.max(1, ...data.attackers.map((a) => a.failures))

  const servers = data.servers.filter((s) => s.geo)
  const target = servers[0]
  const tp = target?.geo ? projection([target.geo.lon, target.geo.lat]) : null
  const attackers = data.attackers.filter((a) => a.geo)

  const place = (lon: number, lat: number) => projection([lon, lat]) ?? [0, 0]

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="img"
        aria-label={`Mapa-múndi: ${servers.length} servidor(es) e ${attackers.length} origem(ns) de ataque localizadas`}>
        <path d={path({ type: 'Sphere' }) ?? ''} fill="var(--page)" stroke="var(--line)" />
        <path d={path(geoGraticule10()) ?? ''} fill="none" stroke="var(--line)" strokeWidth={0.4} opacity={0.6} />
        {countries.map((f: Feature<Geometry, { name: string }>) => {
          const code = NUMERIC_TO_A2[String(f.id).padStart(3, '0')]
          const n = code ? failuresByCountry.get(code) ?? 0 : 0
          const fill = n > 0 ? `color-mix(in srgb, var(--s2) ${Math.round(18 + (n / maxCountry) * 52)}%, var(--raised))` : 'var(--raised)'
          return (
            <path key={String(f.id) + f.properties.name} d={path(f) ?? ''} fill={fill} stroke="var(--line)" strokeWidth={0.5}>
              <title>{`${countryName(code, f.properties.name)}${n ? `: ${n.toLocaleString('pt-BR')} tentativas de login falhas` : ''}`}</title>
            </path>
          )
        })}

        {/* Arcs: attacker → server */}
        {tp && attackers.map((a) => {
          const [x1, y1] = place(a.geo!.lon, a.geo!.lat)
          const [x2, y2] = tp
          const mx = (x1 + x2) / 2
          const my = (y1 + y2) / 2 - Math.min(140, Math.hypot(x2 - x1, y2 - y1) * 0.3)
          const breached = a.successes > 0 && a.failures > 0
          return (
            <path key={`arc-${a.ip}`} d={`M${x1},${y1} Q${mx},${my} ${x2},${y2}`} fill="none"
              stroke={breached ? 'var(--critical)' : 'var(--s2)'} strokeWidth={breached ? 2 : 1.2} strokeOpacity={a.blocked ? 0.25 : 0.6}
              strokeDasharray="6 6" className={a.blocked ? '' : 'flow-dash'} />
          )
        })}

        {/* Attackers */}
        {attackers.map((a) => {
          const [x, y] = place(a.geo!.lon, a.geo!.lat)
          const r = 3 + Math.sqrt(a.failures / maxFailures) * 9
          const breached = a.successes > 0 && a.failures > 0
          const color = breached ? 'var(--critical)' : 'var(--s2)'
          return (
            <g key={`atk-${a.ip}`} onMouseEnter={() => setHover({ kind: 'attacker', a, x, y })} onMouseLeave={() => setHover(null)}
              className="cursor-pointer">
              <circle cx={x} cy={y} r={r + 6} fill="transparent" />
              <circle cx={x} cy={y} r={r} fill={a.blocked ? 'var(--surface)' : color} fillOpacity={a.blocked ? 1 : 0.85}
                stroke={color} strokeWidth={a.blocked ? 2 : 1} />
              {a.blocked && <line x1={x - r * 0.6} y1={y + r * 0.6} x2={x + r * 0.6} y2={y - r * 0.6} stroke={color} strokeWidth={1.5} />}
            </g>
          )
        })}

        {/* Servers */}
        {servers.map((s) => {
          const [x, y] = place(s.geo!.lon, s.geo!.lat)
          const color = s.status === 'ONLINE' ? 'var(--good)' : 'var(--critical)'
          return (
            <g key={`srv-${s.hostId}`} onMouseEnter={() => setHover({ kind: 'server', s, x, y })} onMouseLeave={() => setHover(null)}
              onClick={() => onSelectServer?.(s.hostId)} className="cursor-pointer">
              <circle cx={x} cy={y} r={6} fill="none" stroke={color} strokeWidth={2} className="ping-ring" />
              <circle cx={x} cy={y} r={7} fill={color} stroke="var(--surface)" strokeWidth={2.5} />
              {!compact && (
                <text x={x + 12} y={y + 4} fontSize={13} fontWeight={600} fill="var(--ink)" stroke="var(--page)" strokeWidth={3} paintOrder="stroke">
                  {s.hostId}
                </text>
              )}
            </g>
          )
        })}
      </svg>

      {hover && <Tooltip hover={hover} />}

      {!compact && (
        <ul className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-ink2">
          <li className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-full" style={{ background: 'var(--good)' }} /> Servidor online</li>
          <li className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-full" style={{ background: 'var(--critical)' }} /> Servidor offline / atacante que conseguiu entrar</li>
          <li className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-full" style={{ background: 'var(--s2)' }} /> Origem de ataque (maior = mais tentativas)</li>
          <li className="flex items-center gap-1.5"><span className="inline-block h-3 w-3 rounded-full border-2" style={{ borderColor: 'var(--s2)' }} /> Atacante já bloqueado</li>
        </ul>
      )}
    </div>
  )
}

function Tooltip({ hover }: { hover: NonNullable<Hover> }) {
  const left = `${(hover.x / W) * 100}%`
  const top = `${(hover.y / H) * 100}%`
  const flip = hover.x > W * 0.65
  return (
    <div className="pointer-events-none absolute z-10 w-64 rounded-lg border border-line bg-surface p-3 text-sm shadow-xl"
      style={{ left, top, transform: `translate(${flip ? 'calc(-100% - 14px)' : '14px'}, -50%)` }}>
      {hover.kind === 'server' ? (
        <>
          <p className="font-semibold">{hover.s.hostId}</p>
          <p className="text-xs text-ink2">{place(hover.s.geo)}</p>
          <p className="mt-1 text-xs text-muted">IP {hover.s.ip} · {hover.s.geo?.org ?? 'provedor desconhecido'}</p>
          <p className={`mt-1 text-xs font-semibold ${hover.s.status === 'ONLINE' ? 'text-good' : 'text-critical'}`}>{hover.s.status === 'ONLINE' ? 'Online' : 'Offline'}</p>
        </>
      ) : (
        <>
          <p className="font-mono font-semibold">{hover.a.ip}</p>
          <p className="text-xs text-ink2">{place(hover.a.geo)}</p>
          {hover.a.geo?.org && <p className="text-xs text-muted">{hover.a.geo.org}</p>}
          <p className="mt-1 text-xs">
            {hover.a.failures.toLocaleString('pt-BR')} tentativas · {hover.a.usernames} usuário(s) testado(s)
          </p>
          {hover.a.successes > 0 && hover.a.failures > 0 && <p className="text-xs font-semibold text-critical">Conseguiu entrar no servidor</p>}
          {hover.a.blocked && <p className="text-xs font-semibold text-good">Bloqueado no firewall</p>}
        </>
      )}
    </div>
  )
}

function place(g?: { city?: string; region?: string; countryCode?: string; country?: string }): string {
  if (!g) return 'Local desconhecido'
  return [g.city, countryName(g.countryCode, g.country)].filter(Boolean).join(', ')
}
