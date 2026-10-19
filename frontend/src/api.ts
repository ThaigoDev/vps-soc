export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IncidentStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE'
export type EventCategory = 'AUTH_FAILURE' | 'AUTH_SUCCESS' | 'PRIVILEGE' | 'NETWORK' | 'AGENT' | 'FILE' | 'PROCESS'

export interface Page<T> {
  content: T[]
  totalElements: number
  page: number
  size: number
  totalPages: number
}

export interface Technique {
  id: string
  name: string
  url: string
}

export interface Incident {
  id: number
  hostId: string
  ruleId: string
  title: string
  description?: string
  severity: Severity
  riskScore: number
  status: IncidentStatus
  sourceIp?: string
  username?: string
  techniques: Technique[]
  eventCount: number
  firstSeen: string
  lastSeen: string
  createdAt: string
  resolvedAt?: string
  resolutionNote?: string
}

export interface SecurityEvent {
  id: number
  hostId: string
  type: string
  category: EventCategory
  severity: Severity
  occurredAt: string
  sourceIp?: string
  username?: string
  message?: string
  metadata?: Record<string, unknown>
}

export interface Summary {
  securityScore: number
  posture: 'HEALTHY' | 'AT_RISK' | 'CRITICAL'
  openIncidents: Record<Severity, number>
  totalOpenIncidents: number
  events24h: number
  authFailures24h: number
  attackerIps24h: number
  hostsOnline: number
  hostsTotal: number
}

export interface TimelineBucket {
  hour: string
  authFailures: number
  authSuccesses: number
  privilege: number
  network: number
  other: number
  integrity: number
}

export interface SourceIpStats {
  ip: string
  failures: number
  successes: number
  usernames: number
  lastSeen: string
}

export interface OpenPort {
  proto: string
  address: string
  port: number
  process?: string
  exe?: string
  pid?: number
  user?: string
}

export interface Host {
  id: string
  hostname?: string
  os?: string
  agentVersion?: string
  lastIp?: string
  status: 'ONLINE' | 'OFFLINE'
  firstSeen: string
  lastSeen: string
  heartbeatIntervalSeconds: number
  metrics?: {
    cpuPercent?: number
    memPercent?: number
    memTotalBytes?: number
    diskPercent?: number
    diskTotalBytes?: number
    load1?: number
    uptimeSeconds?: number
  }
  openPorts?: OpenPort[]
}

export interface MetricPoint {
  t: string
  cpu?: number
  mem?: number
  disk?: number
  load1?: number
}

const TOKEN_KEY = 'vps-soc-token'

export function getToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token: string | null) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token)
    else sessionStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: the user just has to log in again */
  }
}

export class UnauthorizedError extends Error {}

export async function api<T>(path: string, init?: RequestInit & { token?: string }): Promise<T> {
  const token = init?.token ?? getToken()
  const res = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  })
  if (res.status === 401) {
    setToken(null)
    throw new UnauthorizedError('Sessão expirada ou token inválido')
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.detail ?? body.error ?? `Erro ${res.status}`)
  }
  return res.status === 204 ? (undefined as T) : res.json()
}

export function qs(params: Record<string, string | number | undefined | null>) {
  const s = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') s.set(k, String(v))
  }
  const out = s.toString()
  return out ? `?${out}` : ''
}
