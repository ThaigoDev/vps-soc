export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IncidentStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE'
export type EventCategory = 'AUTH_FAILURE' | 'AUTH_SUCCESS' | 'PRIVILEGE' | 'NETWORK' | 'AGENT' | 'FILE' | 'PROCESS' | 'RESPONSE' | 'SERVICE'

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
  acknowledgedAt?: string
  containedAt?: string
  containmentNote?: string
  service?: string
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
    swapPercent?: number
    netRxBps?: number
    netTxBps?: number
    tcpEstablished?: number
    processes?: number
  }
  openPorts?: OpenPort[]
  posture?: Posture
  response?: { enabled?: boolean; autoBlock?: boolean }
  pm2?: { daemons?: string[]; error?: string }
  services?: number
}

export interface Posture {
  sessions?: { user: string; tty: string; host?: string; loginAt: string }[]
  pendingUpdates?: number
  securityUpdates?: number
  rebootRequired?: boolean
  failedUnits?: string[]
  ssh?: { permitRootLogin?: string; passwordAuthentication?: string; maxAuthTries?: string }
  firewall?: { enabled?: boolean; blockedIps?: number; droppedPackets?: number; droppedBytes?: number }
}

export interface MetricPoint {
  t: string
  cpu?: number
  mem?: number
  disk?: number
  load1?: number
  swap?: number
  netRx?: number
  netTx?: number
  tcp?: number
  processes?: number
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

// ---- explanations & active response ------------------------------------------------------

export interface Explanation {
  summary?: string
  impact?: string
  riskFactors: string[]
  evidence: { label: string; value: string }[]
  response?: string
  recommendations: { title: string; detail?: string; command?: string }[]
  falsePositive?: string
}

export interface IpProfile {
  ip: string
  kind: 'LOOPBACK' | 'PRIVATE' | 'TAILSCALE' | 'LINK_LOCAL' | 'PUBLIC' | 'INVALID'
  kindLabel: string
  protectedBy?: string
  trustedSource: boolean
  firstSeen?: string
  lastSeen?: string
  failures: number
  successes: number
  usernamesTried: number
  topUsernames: { username: string; attempts: number }[]
  incidents: number
  blockedUntil?: string
  blockOrigin?: 'SOC' | 'AGENT'
  everLoggedIn: boolean
}

export type ActionStatus = 'PROPOSED' | 'PENDING' | 'SENT' | 'SUCCEEDED' | 'FAILED' | 'REJECTED' | 'DISMISSED' | 'EXPIRED'
export type ActionType = 'BLOCK_IP' | 'UNBLOCK_IP' | 'KILL_PROCESS' | 'DISK_CLEANUP' | 'RESTART_SERVICE' | 'PM2_RESTART'

export interface ResponseAction {
  id: number
  hostId: string
  incidentId?: number
  type: ActionType
  label: string
  target: string
  params: Record<string, unknown>
  status: ActionStatus
  mode: 'AUTO' | 'MANUAL'
  origin: 'SOC' | 'AGENT'
  reason?: string
  result?: string
  details?: Record<string, unknown>
  createdAt: string
  decidedAt?: string
  completedAt?: string
}

export interface IpBlock {
  id: number
  hostId: string
  ip: string
  reason?: string
  origin: 'SOC' | 'AGENT'
  incidentId?: number
  createdAt: string
  expiresAt: string
}

export interface IncidentDetailData {
  incident: Incident
  events: SecurityEvent[]
  explanation: Explanation
  ip?: IpProfile
  actions: ResponseAction[]
}

export type Policy = 'AUTO' | 'APPROVAL' | 'OFF'

export interface ResponsePolicy {
  enabled: boolean
  blockBruteForce: Policy
  blockCompromise: Policy
  killProcess: Policy
  diskCleanup: Policy
  restartService: Policy
  restartPm2: Policy
  bruteForceBlockHours: number
  compromiseBlockHours: number
  allowlist: string[]
}

export interface Kpis {
  windowDays: number
  mttdSeconds?: number
  mttaSeconds?: number
  mttrSeconds?: number
  mttcSeconds?: number
  incidentsOpened: number
  incidentsResolved: number
  falsePositives: number
  falsePositiveRate: number
  contained: number
  containedAutomatically: number
  autoContainmentRate: number
  backlog: number
  actionsAuto: number
  actionsManual: number
  actionsFailed: number
  actionsAwaitingApproval: number
  activeBlocks: number
  droppedPackets: number
  eventsPerMinute: number
  maxDataLagSeconds: number
  topRules: { ruleId: string; incidents: number; falsePositives: number }[]
  topUsernames: { name: string; count: number }[]
  daily: { day: string; opened: number; closed: number }[]
}

// ---- PM2 services ------------------------------------------------------------------------

export interface Pm2App {
  source: 'pm2'
  name: string
  namespace?: string
  pmId: number
  pid: number
  status: 'online' | 'stopping' | 'stopped' | 'launching' | 'errored' | 'one-launch-status' | string
  restarts: number
  unstableRestarts: number
  startedAt?: string
  createdAt?: string
  cpuPercent: number
  memoryBytes: number
  mode?: string
  execPath?: string
  cwd?: string
  version?: string
  nodeVersion?: string
  user?: string
  pm2Home: string
  errLogPath?: string
  outLogPath?: string
  ports?: number[]
}

export type ServiceHealth = 'HEALTHY' | 'DEGRADED' | 'DOWN' | 'UNKNOWN'

export interface IncidentRef {
  id: number
  ruleId: string
  title: string
  severity: Severity
  status: IncidentStatus
  lastSeen: string
}

export interface ServiceView {
  hostId: string
  hostOnline: boolean
  reportedAt: string
  pm2: Pm2App
  health: ServiceHealth
  reasons: string[]
  restartsLastHour: number
  memoryPercent: number
  activeIncidents: IncidentRef[]
  incidents30d: number
}

export interface ServiceDetail {
  service: ServiceView
  samples: { t: string; status: string; cpu?: number; memoryMb?: number; restarts?: number }[]
  events: SecurityEvent[]
  incidents: IncidentRef[]
}
