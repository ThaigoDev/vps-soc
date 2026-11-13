import { useEffect, useSyncExternalStore } from 'react'
import { useQueryClient, type QueryClient } from '@tanstack/react-query'
import { getToken } from './api'

/*
 * Live updates. The backend pushes a short "change" message (incidents, actions, events,
 * hosts) over Server-Sent Events the moment something is committed; we refetch only the
 * data behind that topic. Polling stays on as a fallback, so nothing breaks if the stream
 * drops (proxy, sleep, network); it reconnects with backoff.
 * fetch() is used instead of EventSource because EventSource cannot send the token header.
 */

export type LiveState = 'connecting' | 'live' | 'offline'

let state: LiveState = 'connecting'
const listeners = new Set<() => void>()
function setState(s: LiveState) {
  if (s === state) return
  state = s
  listeners.forEach((l) => l())
}

/** Connection state of the live stream, for the status chip. */
export function useLiveState(): LiveState {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l) }, () => state)
}

const TOPIC_KEYS: Record<string, string[]> = {
  incidents: ['incidents', 'incident', 'summary', 'kpis', 'services', 'service'],
  actions: ['actions', 'blocks', 'incident', 'kpis', 'summary'],
  events: ['events', 'timeline', 'top-ips', 'map', 'summary', 'incident'],
  hosts: ['hosts', 'services', 'service', 'metrics', 'summary', 'map'],
}

function refresh(qc: QueryClient, topic: string) {
  for (const key of TOPIC_KEYS[topic] ?? []) void qc.invalidateQueries({ queryKey: [key] })
}

/** Opens the stream while the user is logged in. */
export function useLiveUpdates(enabled: boolean) {
  const qc = useQueryClient()
  useEffect(() => {
    if (!enabled) return
    let stopped = false
    let ctrl: AbortController | null = null
    let firstConnect = true

    const run = async () => {
      let retry = 1000
      while (!stopped) {
        ctrl = new AbortController()
        setState('connecting')
        try {
          const res = await fetch('/api/v1/stream', {
            headers: { Authorization: `Bearer ${getToken() ?? ''}`, Accept: 'text/event-stream' },
            cache: 'no-store',
            signal: ctrl.signal,
          })
          if (res.status === 401) {
            setState('offline')
            return // the regular queries take the user back to the login screen
          }
          if (!res.ok || !res.body) throw new Error(`stream ${res.status}`)
          setState('live')
          retry = 1000
          if (!firstConnect) void qc.invalidateQueries() // catch up on what happened while away
          firstConnect = false

          const reader = res.body.pipeThrough(new TextDecoderStream()).getReader()
          let buf = ''
          let event = 'message'
          for (;;) {
            const { value, done } = await reader.read()
            if (done) break
            buf += value
            let nl: number
            while ((nl = buf.indexOf('\n')) >= 0) {
              const line = buf.slice(0, nl).replace(/\r$/, '')
              buf = buf.slice(nl + 1)
              if (line === '') event = 'message'
              else if (line.startsWith('event:')) event = line.slice(6).trim()
              else if (line.startsWith('data:') && event === 'change') refresh(qc, line.slice(5).trim())
            }
          }
        } catch {
          if (stopped) return
        }
        if (stopped) return
        setState('offline')
        await new Promise((r) => setTimeout(r, retry))
        retry = Math.min(retry * 2, 15_000)
      }
    }
    void run()
    return () => {
      stopped = true
      ctrl?.abort()
      setState('connecting')
    }
  }, [enabled, qc])
}
