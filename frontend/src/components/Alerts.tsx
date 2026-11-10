import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertOctagon, Bell, BellOff, Send, ShieldAlert, Siren, Volume2, VolumeX, X } from 'lucide-react'
import { api, qs, type Incident, type Page } from '../api'
import { severityRank, timeAgo } from './ui'

/*
 * Emergency alerting. Every open incident is remembered with the severity it had when we last
 * alerted on it; a new incident, or one that escalated, at HIGH or above raises an alert:
 *   CRITICAL -> full-screen alarm with a looping alarm sound until someone takes it or silences it;
 *   HIGH     -> toast with a short alert sound.
 * Sound effects live in public/sounds (see SFX); the synth siren is only a fallback.
 * Both also fire a browser notification (when allowed) and flash the tab title.
 */

const SEEN_KEY = 'vps-soc-alerted'
const SETTINGS_KEY = 'vps-soc-alert-settings'
const POLL_MS = 5_000

interface Settings {
  sound: boolean
  notify: boolean
}

function load<T>(key: string): T | null {
  try {
    const v = localStorage.getItem(key)
    return v ? (JSON.parse(v) as T) : null
  } catch {
    return null
  }
}

function save(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* private mode: alerts still work, they just are not remembered */
  }
}

// ---- sound -------------------------------------------------------------------------------

let audio: AudioContext | null = null

function audioContext(): AudioContext | null {
  if (!audio) {
    const Ctx = window.AudioContext ?? (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext
    if (!Ctx) return null
    audio = new Ctx()
  }
  return audio
}

/** Browsers only allow audio after a user gesture; call this from a click. */
function unlockAudio() {
  const ctx = audioContext()
  if (ctx && ctx.state === 'suspended') void ctx.resume()
}

/** Whether the browser currently lets the siren play (false until the first click after a reload). */
function useAudioUnlocked(): boolean {
  const [running, setRunning] = useState(() => audioContext()?.state === 'running')
  useEffect(() => {
    const ctx = audioContext()
    if (!ctx) return
    const sync = () => setRunning(ctx.state === 'running')
    ctx.addEventListener('statechange', sync)
    sync()
    return () => ctx.removeEventListener('statechange', sync)
  }, [])
  return running
}

function tone(freqFrom: number, freqTo: number, start: number, duration: number, volume = 0.18) {
  const ctx = audioContext()
  if (!ctx || ctx.state !== 'running') return
  const t = ctx.currentTime + start
  const osc = ctx.createOscillator()
  const gain = ctx.createGain()
  osc.type = 'sawtooth'
  osc.frequency.setValueAtTime(freqFrom, t)
  osc.frequency.linearRampToValueAtTime(freqTo, t + duration)
  gain.gain.setValueAtTime(0.0001, t)
  gain.gain.exponentialRampToValueAtTime(volume, t + 0.03)
  gain.gain.exponentialRampToValueAtTime(0.0001, t + duration)
  osc.connect(gain).connect(ctx.destination)
  osc.start(t)
  osc.stop(t + duration + 0.05)
}

/** One cycle of a two-tone siren (~1.4s): fallback when the sound files cannot load. */
function sirenCycle() {
  tone(650, 1250, 0, 0.6)
  tone(1250, 650, 0.65, 0.6)
}

function beep() {
  tone(880, 880, 0, 0.12, 0.12)
  tone(880, 880, 0.2, 0.12, 0.12)
}

// ---- sound effects -------------------------------------------------------------------------

/** Clips cut from the futuristic UI sound pack (public/sounds), one per kind of moment. */
const SFX = {
  startup: '/sounds/startup.mp3', // power-up swell ending in an impact: entering the console
  alarm: '/sounds/alarm-critical.mp3', // rising chirp with harmonics, looped while a CRITICAL alarm is up
  high: '/sounds/alert-high.mp3', // low hit + chime: HIGH toast
  success: '/sounds/action-success.mp3', // short upward blip: a containment action succeeded
  linkLost: '/sounds/link-lost.mp3', // digital glitch: the dashboard lost the backend
  click: '/sounds/click.mp3', // tick: confirmations
} as const

export type Sfx = keyof typeof SFX

const buffers = new Map<Sfx, Promise<AudioBuffer | null>>()

function loadSfx(name: Sfx): Promise<AudioBuffer | null> {
  const ctx = audioContext()
  if (!ctx) return Promise.resolve(null)
  let p = buffers.get(name)
  if (!p) {
    p = fetch(SFX[name])
      .then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error(r.statusText))))
      .then((b) => ctx.decodeAudioData(b))
      .catch(() => null)
    buffers.set(name, p)
  }
  return p
}

/** Plays a clip; returns false when it could not (audio locked or file missing). */
async function playSfx(name: Sfx, volume = 0.8): Promise<boolean> {
  const ctx = audioContext()
  if (!ctx || ctx.state !== 'running') return false
  const buf = await loadSfx(name)
  if (!buf) return false
  const src = ctx.createBufferSource()
  const gain = ctx.createGain()
  gain.gain.value = volume
  src.buffer = buf
  src.connect(gain).connect(ctx.destination)
  src.start()
  return true
}

function soundOn(): boolean {
  return load<Settings>(SETTINGS_KEY)?.sound ?? true
}

/** For screens outside the alert provider (login): plays only when sound is enabled. */
export async function playStartup() {
  unlockAudio()
  if (soundOn()) await playSfx('startup', 0.7)
}

// ---- context -----------------------------------------------------------------------------

interface AlertState {
  settings: Settings
  setSound: (on: boolean) => void
  setNotify: (on: boolean) => Promise<void>
  notifyPermission: NotificationPermission | 'unsupported'
  testAlarm: () => void
  /** Plays a sound effect if the operator has sound on. */
  play: (name: Sfx) => void
}

const AlertContext = createContext<AlertState | null>(null)

export function useAlertSettings() {
  const ctx = useContext(AlertContext)
  if (!ctx) throw new Error('useAlertSettings outside AlertProvider')
  return ctx
}

const TEST_INCIDENT: Incident = {
  id: -1,
  hostId: 'teste',
  ruleId: 'TESTE_DE_ALARME',
  title: 'Teste de alarme: nenhuma ação necessária',
  description: 'Este é um teste do alarme de emergência. Nenhum incidente real foi criado.',
  severity: 'CRITICAL',
  riskScore: 100,
  status: 'OPEN',
  techniques: [],
  eventCount: 0,
  firstSeen: new Date().toISOString(),
  lastSeen: new Date().toISOString(),
  createdAt: new Date().toISOString(),
}

export function AlertProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(() => load<Settings>(SETTINGS_KEY) ?? { sound: true, notify: false })
  const [notifyPermission, setPermission] = useState<NotificationPermission | 'unsupported'>(() =>
    'Notification' in window ? Notification.permission : 'unsupported')
  const [alarms, setAlarms] = useState<Incident[]>([]) // CRITICAL, shown in the modal queue
  const [toasts, setToasts] = useState<Incident[]>([]) // HIGH
  const settingsRef = useRef(settings)
  settingsRef.current = settings
  const navigate = useNavigate()

  const update = (next: Settings) => {
    setSettings(next)
    save(SETTINGS_KEY, next)
  }

  const setSound = (on: boolean) => {
    if (on) {
      unlockAudio()
      void playSfx('click', 0.6)
    }
    update({ ...settingsRef.current, sound: on })
  }

  const play = useCallback((name: Sfx) => {
    if (settingsRef.current.sound) void playSfx(name, name === 'click' ? 0.6 : 0.8)
  }, [])

  // Decode the clips once audio is available, so the first alarm plays without delay.
  useEffect(() => {
    const warm = () => (Object.keys(SFX) as Sfx[]).forEach((n) => void loadSfx(n))
    warm()
    window.addEventListener('pointerdown', warm, { once: true })
    return () => window.removeEventListener('pointerdown', warm)
  }, [])

  const setNotify = async (on: boolean) => {
    if (on && 'Notification' in window && Notification.permission !== 'granted') {
      const p = await Notification.requestPermission()
      setPermission(p)
      if (p !== 'granted') return
    }
    update({ ...settingsRef.current, notify: on })
  }

  // Resume audio on the first interaction after a reload (autoplay policy).
  useEffect(() => {
    const onGesture = () => unlockAudio()
    window.addEventListener('pointerdown', onGesture)
    window.addEventListener('keydown', onGesture)
    return () => {
      window.removeEventListener('pointerdown', onGesture)
      window.removeEventListener('keydown', onGesture)
    }
  }, [])

  const raise = useCallback((inc: Incident) => {
    const critical = inc.severity === 'CRITICAL'
    if (critical) {
      setAlarms((a) => (a.some((x) => x.id === inc.id) ? a : [...a, inc]))
    } else {
      setToasts((t) => (t.some((x) => x.id === inc.id) ? t : [...t, inc]))
      if (settingsRef.current.sound) void playSfx('high').then((ok) => ok || beep())
      window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== inc.id)), 20_000)
    }
    if (settingsRef.current.notify && 'Notification' in window && Notification.permission === 'granted' && inc.id > 0) {
      const n = new Notification(`${critical ? 'ALERTA CRÍTICO' : 'Alerta alto'} · ${inc.hostId}`, {
        body: inc.title,
        tag: `vps-soc-${inc.id}`,
        requireInteraction: critical,
      })
      n.onclick = () => {
        window.focus()
        navigate(`/incidents/${inc.id}`)
        n.close()
      }
    }
  }, [navigate])

  const testAlarm = () => {
    unlockAudio()
    raise({ ...TEST_INCIDENT, lastSeen: new Date().toISOString() })
  }

  // Watch active incidents.
  const q = useQuery({
    queryKey: ['incidents', 'alert-watch'],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status: 'OPEN,ACKNOWLEDGED', size: 100 })}`),
    refetchInterval: POLL_MS,
    refetchIntervalInBackground: true,
  })

  useEffect(() => {
    if (!q.data) return
    const stored = load<Record<string, number>>(SEEN_KEY)
    const next: Record<string, number> = {}
    for (const inc of q.data.content) {
      const rank = severityRank[inc.severity]
      const before = stored?.[inc.id]
      next[inc.id] = Math.max(rank, before ?? 0)
      // First visit ever: remember what is already open without sounding alarms for it.
      if (stored && inc.status === 'OPEN' && rank >= severityRank.HIGH && (before === undefined || rank > before)) {
        raise(inc)
      }
    }
    save(SEEN_KEY, next)
  }, [q.data, raise])

  // Alarm loop while a critical alarm is on screen (synth siren if the clip cannot play).
  useEffect(() => {
    if (alarms.length === 0 || !settings.sound) return
    const cycle = () => void playSfx('alarm', 0.9).then((ok) => ok || sirenCycle())
    cycle()
    const t = window.setInterval(cycle, 1_600)
    return () => window.clearInterval(t)
  }, [alarms.length, settings.sound])

  // Short confirmation when a containment action succeeds (IP blocked, process killed...).
  const actions = useQuery({
    queryKey: ['actions', 'sound-watch'],
    queryFn: () => api<Page<{ id: number }>>(`/response/actions${qs({ status: 'SUCCEEDED', size: 1 })}`),
    refetchInterval: 10_000,
  })
  const lastAction = useRef<number | null>(null)
  useEffect(() => {
    const top = actions.data?.content[0]?.id ?? 0
    if (lastAction.current !== null && top > lastAction.current) play('success')
    if (actions.data) lastAction.current = top
  }, [actions.data, play])

  // Flash the tab title while alarms are pending.
  useEffect(() => {
    const base = 'VPS-SOC · Centro de Operações'
    if (alarms.length === 0) {
      document.title = base
      return
    }
    let on = false
    const t = window.setInterval(() => {
      on = !on
      document.title = on ? `[!] ALERTA CRÍTICO (${alarms.length})` : base
    }, 900)
    return () => {
      window.clearInterval(t)
      document.title = base
    }
  }, [alarms.length])

  const value = useMemo(
    () => ({ settings, setSound, setNotify, notifyPermission, testAlarm, play }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [settings, notifyPermission],
  )

  return (
    <AlertContext.Provider value={value}>
      {children}
      {alarms.length > 0 && (
        <AlarmModal
          incident={alarms[0]}
          queued={alarms.length - 1}
          onClose={() => setAlarms((a) => a.slice(1))}
          onSilenceAll={() => setAlarms([])}
        />
      )}
      <Toasts toasts={toasts} onClose={(id) => setToasts((t) => t.filter((x) => x.id !== id))} />
    </AlertContext.Provider>
  )
}

// ---- UI ----------------------------------------------------------------------------------

function AlarmModal({ incident: i, queued, onClose, onSilenceAll }: {
  incident: Incident
  queued: number
  onClose: () => void
  onSilenceAll: () => void
}) {
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const isTest = i.id < 0
  const { settings } = useAlertSettings()
  const unlocked = useAudioUnlocked()
  const ack = useMutation({
    mutationFn: () => api<Incident>(`/incidents/${i.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'ACKNOWLEDGED', note: 'Assumido pelo alarme de emergência do painel' }),
    }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['incidents'] })
      void queryClient.invalidateQueries({ queryKey: ['summary'] })
      onClose()
    },
  })
  const take = () => (isTest ? onClose() : ack.mutate())

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4" role="alertdialog" aria-modal="true" aria-labelledby="alarm-title" aria-describedby="alarm-desc">
      <div className="alarm-pulse w-full max-w-xl border-2 border-critical bg-surface">
        <div className="alarm-stripes flex items-center gap-3 border-b-2 border-critical px-5 py-3">
          <Siren size={26} className="alarm-blink shrink-0 text-critical" aria-hidden />
          <div className="min-w-0 flex-1">
            <p className="hud-label font-bold text-critical">Alerta crítico{isTest ? ' · teste' : ''}</p>
            <p className="font-mono text-xs text-ink2">Host {i.hostId} · {timeAgo(i.lastSeen)}</p>
          </div>
          {queued > 0 && <span className="hud-label rounded-md bg-critical px-2 py-1 font-bold text-white">+{queued} na fila</span>}
        </div>
        <div className="space-y-3 px-5 py-4">
          <h2 id="alarm-title" className="text-lg font-semibold leading-snug">{i.title}</h2>
          <p id="alarm-desc" className="text-sm text-ink2">{i.description}</p>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-4">
            <Field label="Regra" value={i.ruleId} />
            <Field label="Risco" value={`${i.riskScore}/100`} />
            <Field label="IP origem" value={i.sourceIp ?? '-'} />
            <Field label="Usuário" value={i.username ?? '-'} />
          </dl>
          {i.techniques.length > 0 && (
            <p className="flex flex-wrap gap-1">
              {i.techniques.map((t) => (
                <span key={t.id} className="rounded-md border border-line bg-raised px-1.5 py-0.5 font-mono text-[11px] text-ink2" title={t.name}>{t.id}</span>
              ))}
            </p>
          )}
          {settings.sound && !unlocked && (
            <button onClick={unlockAudio}
              className="alarm-blink flex w-full items-center justify-center gap-2 rounded-md border-2 border-warning px-3 py-2 text-sm font-semibold text-warning">
              <Volume2 size={16} aria-hidden /> O navegador bloqueou o som: clique para ativar a sirene
            </button>
          )}
          {ack.error && <p className="text-sm text-critical">Falha ao assumir: {ack.error instanceof Error ? ack.error.message : 'erro'}</p>}
        </div>
        <div className="flex flex-wrap gap-2 border-t border-line px-5 py-3">
          <button onClick={take} disabled={ack.isPending} autoFocus
            className="flex-1 rounded-md bg-critical px-3 py-2 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-60">
            {ack.isPending ? 'Assumindo…' : isTest ? 'Encerrar teste' : 'Assumir incidente'}
          </button>
          {!isTest && (
            <button onClick={() => { onClose(); navigate(`/incidents/${i.id}`) }}
              className="rounded-md border border-line px-3 py-2 text-sm hover:bg-raised">
              Ver detalhes
            </button>
          )}
          <button onClick={queued > 0 ? onSilenceAll : onClose} className="rounded-md border border-line px-3 py-2 text-sm text-ink2 hover:bg-raised">
            {queued > 0 ? 'Silenciar todos' : 'Silenciar'}
          </button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted">{label}</dt>
      <dd className="truncate text-ink">{value}</dd>
    </div>
  )
}

function Toasts({ toasts, onClose }: { toasts: Incident[]; onClose: (id: number) => void }) {
  if (toasts.length === 0) return null
  return (
    <div className="fixed bottom-4 right-4 z-40 flex w-[min(380px,calc(100vw-2rem))] flex-col gap-2" role="status" aria-live="polite">
      {toasts.map((i) => (
        <div key={i.id} className="panel border border-serious bg-surface p-3 shadow-lg">
          <div className="flex items-start gap-2">
            <ShieldAlert size={18} className="mt-0.5 shrink-0 text-serious" aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="hud-label font-semibold text-serious">Alerta alto · {i.hostId}</p>
              <Link to={`/incidents/${i.id}`} onClick={() => onClose(i.id)} className="mt-0.5 block text-sm hover:underline">{i.title}</Link>
            </div>
            <button onClick={() => onClose(i.id)} className="text-muted hover:text-ink" aria-label="Fechar alerta">
              <X size={16} />
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

/** Header toggles: sound, browser notifications, alarm test. */
/**
 * One "Alertas" button in the top bar instead of four chips: sound, browser notifications,
 * Telegram and a test alarm all live in its menu.
 */
export function AlertMenu() {
  const { settings, setSound, setNotify, notifyPermission, testAlarm } = useAlertSettings()
  const unlocked = useAudioUnlocked()
  const [open, setOpen] = useState(false)
  const box = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: PointerEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('pointerdown', close)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('pointerdown', close)
      document.removeEventListener('keydown', esc)
    }
  }, [open])
  const needsUnlock = settings.sound && !unlocked
  return (
    <div className="relative" ref={box}>
      {needsUnlock && (
        <button onClick={unlockAudio} className="alarm-blink mr-2 inline-flex items-center gap-1.5 rounded-md border border-warning px-2 py-1 text-xs font-semibold text-warning"
          title="O navegador só libera som depois de um clique. Clique para ativar o alarme sonoro.">
          <VolumeX size={14} aria-hidden /> Ativar som
        </button>
      )}
      <button onClick={() => setOpen(!open)} aria-expanded={open} aria-haspopup="menu"
        className="inline-flex items-center gap-1.5 rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-ink2 hover:bg-raised">
        {settings.sound || settings.notify ? <Bell size={15} className="text-hud" aria-hidden /> : <BellOff size={15} aria-hidden />}
        <span className="hidden sm:inline">Alertas</span>
      </button>
      {open && (
        <div role="menu" className="absolute right-0 z-40 mt-2 w-80 rounded-xl border border-line bg-surface p-2 shadow-xl">
          <p className="px-2 pb-2 pt-1 text-xs text-muted">Como o painel avisa quando surge um incidente grave.</p>
          <MenuToggle on={settings.sound} onClick={() => setSound(!settings.sound)}
            icon={settings.sound ? <Volume2 size={16} className="text-hud" aria-hidden /> : <VolumeX size={16} className="text-muted" aria-hidden />}
            title="Som de alarme" detail="Toca uma sirene em incidente crítico e um aviso em incidente alto." />
          {notifyPermission !== 'unsupported' && (
            <MenuToggle on={settings.notify} onClick={() => void setNotify(!settings.notify)}
              icon={settings.notify ? <Bell size={16} className="text-hud" aria-hidden /> : <BellOff size={16} className="text-muted" aria-hidden />}
              title="Notificações do navegador"
              detail={notifyPermission === 'denied' ? 'Bloqueadas nas configurações do navegador.' : 'Aparecem mesmo com outra aba aberta.'} />
          )}
          <TelegramRow />
          <button role="menuitem" onClick={() => { setOpen(false); testAlarm() }}
            className="mt-1 flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm hover:bg-raised">
            <Siren size={16} className="text-critical" aria-hidden />
            <span>
              <span className="block font-medium">Testar alarme</span>
              <span className="block text-xs text-muted">Mostra como fica um alerta crítico.</span>
            </span>
          </button>
        </div>
      )}
    </div>
  )
}

function MenuToggle({ on, onClick, icon, title, detail }: { on: boolean; onClick: () => void; icon: ReactNode; title: string; detail: string }) {
  return (
    <button role="menuitemcheckbox" aria-checked={on} onClick={onClick} className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm hover:bg-raised">
      {icon}
      <span className="min-w-0 flex-1">
        <span className="block font-medium">{title}</span>
        <span className="block text-xs text-muted">{detail}</span>
      </span>
      <span className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${on ? 'bg-[var(--primary)]' : 'bg-raised border border-line'}`} aria-hidden>
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-all ${on ? 'left-[18px]' : 'left-0.5'}`} />
      </span>
    </button>
  )
}

/**
 * Off-screen channel: the backend pushes incidents to Telegram even with this tab closed.
 * Shows whether it is configured; clicking sends a test message.
 */
function TelegramRow() {
  const q = useQuery({
    queryKey: ['telegram'],
    queryFn: () => api<{ enabled: boolean; minSeverity: string }>('/notifications/telegram'),
    staleTime: 60_000,
  })
  const [result, setResult] = useState<string | null>(null)
  const test = useMutation({
    mutationFn: () => api<{ result: 'SENT' | 'FAILED' | 'DISABLED' }>('/notifications/telegram/test', { method: 'POST' }),
    onSuccess: (r) => setResult(r.result === 'SENT' ? 'Mensagem de teste enviada.' : r.result === 'FAILED' ? 'Falha no envio.' : 'Não configurado.'),
    onError: () => setResult('Falha no envio.'),
    onSettled: () => window.setTimeout(() => setResult(null), 5_000),
  })
  if (!q.data) return null
  const on = q.data.enabled
  return (
    <button role="menuitem" onClick={() => on && test.mutate()} disabled={test.isPending || !on}
      className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm hover:bg-raised disabled:cursor-default">
      <Send size={16} className={on ? 'text-good' : 'text-warning'} aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block font-medium">Telegram {on ? 'ligado' : 'desligado'}</span>
        <span className="block text-xs text-muted">
          {result ?? (test.isPending ? 'Enviando…' : on
            ? `Incidentes a partir de ${q.data.minSeverity} chegam no celular. Clique para testar.`
            : 'Configure SOC_TELEGRAM_BOT_TOKEN e SOC_TELEGRAM_CHAT_ID no .env.')}
        </span>
      </span>
    </button>
  )
}

/** Persistent strip while critical incidents wait for someone to take them. */
export function EmergencyBanner() {
  const q = useQuery({
    queryKey: ['incidents', 'alert-watch'],
    queryFn: () => api<Page<Incident>>(`/incidents${qs({ status: 'OPEN,ACKNOWLEDGED', size: 100 })}`),
    refetchInterval: POLL_MS,
  })
  const waiting = q.data?.content.filter((i) => i.status === 'OPEN' && i.severity === 'CRITICAL') ?? []
  if (waiting.length === 0) return null
  const one = waiting.length === 1
  return (
    <div className="alarm-stripes border-b-2 border-critical" role="alert">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-sm lg:px-8">
        <AlertOctagon size={18} className="alarm-blink shrink-0 text-critical" aria-hidden />
        <span className="font-bold text-critical">Emergência</span>
        <span className="font-semibold">
          {one ? '1 incidente crítico aguardando resposta' : `${waiting.length} incidentes críticos aguardando resposta`}
        </span>
        <span className="hidden min-w-0 flex-1 truncate text-ink2 md:block">{waiting[0].title}</span>
        <Link to={one ? `/incidents/${waiting[0].id}` : '/incidents'} className="rounded-md bg-critical px-2.5 py-1 text-xs font-semibold text-white hover:brightness-110">
          Ver agora
        </Link>
      </div>
    </div>
  )
}

