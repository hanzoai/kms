import { useQuery } from '@tanstack/react-query'
import { fetchHealth, fetchStatus, getToken, decodeToken, ApiError } from '@/lib/api'
import { Badge, Card, CodeBlock } from '@/components/Button'

// Status — combines /v1/kms/health (always served) and /v1/kms/status
// (admin-only, surfaces MPC connectivity). Also decodes the active JWT
// locally so operators can confirm the issuer/audience/owner they're
// signed in with.

export function StatusPage() {
  const health = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    refetchInterval: 5000,
    retry: false,
  })
  const status = useQuery({
    queryKey: ['status'],
    queryFn: fetchStatus,
    refetchInterval: 10000,
    retry: false,
  })

  const claims = decodeToken(getToken())

  return (
    <div className="p-6">
      <header className="mb-4">
        <h1 className="text-lg font-semibold text-neutral-50">Status</h1>
        <p className="text-[13px] text-neutral-400">
          Liveness from <code>/v1/kms/health</code>, MPC connectivity from <code>/v1/kms/status</code>.
        </p>
      </header>

      <div className="grid grid-cols-2 gap-4">
        <Card className="p-5">
          <header className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-neutral-200">KMS</h2>
            <Badge variant={health.data?.status === 'ok' ? 'success' : 'danger'}>
              {health.isLoading ? '…' : health.data?.status || 'unknown'}
            </Badge>
          </header>
          <dl className="grid grid-cols-3 gap-1 text-[12px]">
            <dt className="text-neutral-500">service</dt>
            <dd className="col-span-2 text-neutral-200">{health.data?.service || '—'}</dd>
            <dt className="text-neutral-500">version</dt>
            <dd className="col-span-2 font-mono text-neutral-200">{health.data?.version || '—'}</dd>
          </dl>
        </Card>

        <Card className="p-5">
          <header className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-neutral-200">MPC</h2>
            <Badge variant={mpcVariant(status.data, status.error)}>
              {mpcLabel(status.data, status.error, status.isLoading)}
            </Badge>
          </header>
          {status.error && status.error instanceof ApiError && status.error.status === 403 ? (
            <p className="text-[12px] text-neutral-500">
              Admin role required to view MPC status.
            </p>
          ) : (
            <pre className="overflow-auto rounded-md border border-neutral-900 bg-neutral-925/60 p-3 font-mono text-[11px] text-neutral-200">
              {status.isLoading
                ? 'loading…'
                : JSON.stringify(status.data?.mpc ?? status.error, null, 2)}
            </pre>
          )}
        </Card>
      </div>

      {claims && (
        <Card className="mt-6 p-5">
          <h2 className="mb-2 text-sm font-semibold text-neutral-200">Active token</h2>
          <p className="text-[12px] text-neutral-500">
            Decoded locally — signature is verified by kmsd on every request, not by the browser.
          </p>
          <dl className="mt-3 grid grid-cols-3 gap-2 text-[12px]">
            <Field label="iss" value={claims.iss} />
            <Field label="aud" value={Array.isArray(claims.aud) ? claims.aud.join(', ') : claims.aud} />
            <Field label="sub" value={claims.sub} />
            <Field label="owner" value={claims.owner} />
            <Field label="roles" value={(claims.roles || []).join(', ') || '—'} />
            <Field label="expires" value={claims.exp ? new Date(claims.exp * 1000).toISOString() : '—'} />
          </dl>
          <CodeBlock>{JSON.stringify(claims, null, 2)}</CodeBlock>
        </Card>
      )}
    </div>
  )
}

function Field({ label, value }: { label: string; value?: string }) {
  return (
    <>
      <dt className="text-neutral-500">{label}</dt>
      <dd className="col-span-2 font-mono text-neutral-200">{value || '—'}</dd>
    </>
  )
}

function mpcLabel(
  d: { mpc: unknown; details?: string } | undefined,
  err: unknown,
  loading: boolean,
): string {
  if (loading) return 'loading'
  if (err instanceof ApiError && err.status === 403) return 'forbidden'
  if (err) return 'error'
  if (typeof d?.mpc === 'string') return d.mpc
  if (d?.mpc && typeof d.mpc === 'object' && 'Ready' in d.mpc) {
    return (d.mpc as { Ready: boolean }).Ready ? 'ready' : 'unready'
  }
  return 'unknown'
}

function mpcVariant(
  d: { mpc: unknown } | undefined,
  err: unknown,
): 'success' | 'warn' | 'danger' | 'neutral' {
  if (err) return 'danger'
  if (typeof d?.mpc === 'string' && d.mpc !== 'unreachable') return 'success'
  if (d?.mpc && typeof d.mpc === 'object' && 'Ready' in d.mpc) {
    return (d.mpc as { Ready: boolean }).Ready ? 'success' : 'warn'
  }
  return 'neutral'
}
