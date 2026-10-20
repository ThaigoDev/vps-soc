import { useState, type FormEvent } from 'react'
import { Shield } from 'lucide-react'
import { api, setToken } from '../api'
import { playStartup } from '../components/Alerts'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [token, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api('/auth/check', { token: token.trim() })
      setToken(token.trim())
      void playStartup()
      onLogin()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Falha no login')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit} className="panel w-full max-w-sm border border-line bg-surface p-6">
        <div className="mb-1 flex items-center gap-2 font-mono text-lg font-bold tracking-widest">
          <Shield className="text-hud" aria-hidden />
          VPS-SOC
        </div>
        <p className="hud-label mb-5 text-[10px] text-muted">Centro de operações de segurança · acesso restrito</p>
        <label htmlFor="token" className="hud-label mb-1 block text-muted">
          Credencial de acesso
        </label>
        <input
          id="token"
          type="password"
          autoComplete="current-password"
          value={token}
          onChange={(e) => setValue(e.target.value)}
          className="w-full rounded-sm border border-line bg-page px-3 py-2 font-mono text-sm outline-none focus:border-hud"
          placeholder="SOC_DASHBOARD_TOKEN"
          autoFocus
        />
        {error && <p className="mt-2 text-sm text-critical">{error}</p>}
        <button
          disabled={busy || !token.trim()}
          className="hud-label mt-4 w-full rounded-sm border border-hud bg-raised px-3 py-2 font-semibold text-ink hover:bg-line disabled:opacity-50"
        >
          {busy ? "Verificando…" : "Autenticar"}
        </button>
      </form>
    </div>
  )
}
