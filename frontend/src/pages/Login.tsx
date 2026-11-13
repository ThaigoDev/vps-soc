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
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-line bg-surface p-7 shadow-xl">
        <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-raised">
          <Shield size={24} className="text-hud" aria-hidden />
        </span>
        <h1 className="mt-4 text-xl font-semibold tracking-tight">Entrar no VPS-SOC</h1>
        <p className="mt-1 text-sm text-ink2">Monitor de segurança dos seus servidores.</p>
        <label htmlFor="token" className="mb-1.5 mt-6 block text-sm font-medium">
          Token de acesso
        </label>
        <input
          id="token"
          type="password"
          autoComplete="current-password"
          value={token}
          onChange={(e) => setValue(e.target.value)}
          className="w-full rounded-lg border border-line bg-page px-3 py-2 font-mono text-sm outline-none focus:border-[var(--hud)]"
          placeholder="Cole aqui o token"
          autoFocus
        />
        <p className="mt-1.5 text-xs text-muted">É o valor de SOC_DASHBOARD_TOKEN no arquivo .env do servidor do SOC.</p>
        {error && <p className="mt-3 text-sm text-critical">{error}</p>}
        <button
          disabled={busy || !token.trim()}
          className="mt-5 w-full rounded-lg bg-[var(--primary)] px-3 py-2 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-50"
        >
          {busy ? 'Verificando…' : 'Entrar'}
        </button>
        <a href="/apresentacao" className="mt-4 block text-center text-sm text-hud hover:underline">Ver a apresentação do projeto</a>
      </form>
    </div>
  )
}
