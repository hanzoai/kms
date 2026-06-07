import { useState, type FormEvent } from 'react'
import { ApiError, login, setOrg, setToken } from '@/lib/api'
import { Button, Card, Input, Label } from '@/components/Button'

// Login — exchanges clientId + clientSecret for an IAM access token via
// /v1/kms/auth/login. Token is stored in localStorage; the org is
// remembered separately because the API path includes {org}.

export function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [org, setOrgInput] = useState('hanzo')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { accessToken } = await login(clientId.trim(), clientSecret.trim())
      setToken(accessToken)
      setOrg(org.trim() || 'hanzo')
      onSuccess()
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : (err as Error).message
      setError(msg || 'login failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-950 p-6">
      <Card className="w-full max-w-sm p-6">
        <div className="mb-6 flex items-center gap-2">
          <span
            className="inline-flex h-7 w-7 items-center justify-center rounded-[4px] font-mono text-[13px] font-bold text-white"
            style={{ background: 'var(--color-brand)' }}
            aria-hidden
          >
            H
          </span>
          <div>
            <div className="text-base font-semibold text-neutral-50">Hanzo KMS</div>
            <div className="text-[11px] text-neutral-500">sign in with a machine identity</div>
          </div>
        </div>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1">
            <Label htmlFor="org">Organization</Label>
            <Input
              id="org"
              type="text"
              autoComplete="off"
              value={org}
              onChange={(e) => setOrgInput(e.target.value)}
              placeholder="hanzo"
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="clientId">Client ID</Label>
            <Input
              id="clientId"
              type="text"
              autoComplete="username"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              required
            />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor="clientSecret">Client Secret</Label>
            <Input
              id="clientSecret"
              type="password"
              autoComplete="current-password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              required
            />
          </div>

          {error && (
            <p className="rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-[12px] text-red-200">
              {error}
            </p>
          )}

          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>

        <p className="mt-4 text-[11px] text-neutral-500">
          Credentials are exchanged at <code className="text-neutral-300">/v1/kms/auth/login</code> for
          an IAM access token. The token lives in localStorage.
        </p>
      </Card>
    </div>
  )
}
