import { useQuery } from '@tanstack/react-query'
import { fetchHealth } from '@/lib/api'
import type { Config } from '@/lib/kms'
import { who } from '@/lib/session'
import { Badge, Card } from '@/components/ui'
import { Failure } from '@/components/Failure'

// Status: readiness from GET /v1/kms/health, and the configuration this console
// signed in with.

export function StatusPage({ config }: { config: Config }) {
  const health = useQuery({ queryKey: ['health'], queryFn: fetchHealth, refetchInterval: 10_000 })

  return (
    <div className="mx-auto max-w-5xl p-6">
      <header className="mb-5">
        <h1 className="text-lg font-semibold text-neutral-50">Status</h1>
        <p className="text-[13px] text-neutral-400">Whether the store can serve secrets right now.</p>
      </header>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card className="p-5">
          <header className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-neutral-200">Store</h2>
            {health.data && (
              <Badge variant={health.data.ready ? 'success' : 'danger'}>{health.data.ready ? 'ready' : 'not ready'}</Badge>
            )}
          </header>
          {health.isPending && <p className="text-[13px] text-neutral-500">Checking</p>}
          {health.isError && <Failure error={health.error} />}
          {health.data && (
            <dl className="grid grid-cols-3 gap-y-1 text-[13px]">
              <Field label="Service" value={health.data.service} />
              <Field label="Status" value={health.data.status} />
              {health.data.signing !== undefined && (
                <Field label="Signing" value={health.data.signing ? 'configured' : 'not configured'} />
              )}
              {health.data.error && <Field label="Reason" value={health.data.error} />}
            </dl>
          )}
        </Card>

        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold text-neutral-200">Session</h2>
          <dl className="grid grid-cols-3 gap-y-1 text-[13px]">
            <Field label="Signed in as" value={who()} />
            <Field label="Issuer" value={config.issuer} />
            <Field label="API" value={config.apiBase} />
          </dl>
        </Card>
      </div>
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-neutral-500">{label}</dt>
      <dd className="col-span-2 break-all font-mono text-neutral-200">{value || 'none'}</dd>
    </>
  )
}
