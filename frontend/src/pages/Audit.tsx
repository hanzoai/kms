import { useQuery } from '@tanstack/react-query'
import { fetchAuditStats } from '@/lib/api'
import { Card } from '@/components/Button'

// Audit — read-only. The canonical /v1/kms/audit/stats only exposes the
// background-writer counters (written + dropped). Per-event tailing is
// not on the public surface; the audit ledger is a side-table SQLite at
// $KMS_AUDIT_DB that operators inspect on the host. This page surfaces
// what's available and signposts the rest.

export function AuditPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['audit-stats'],
    queryFn: fetchAuditStats,
    refetchInterval: 5000,
    retry: false,
  })
  const errMsg =
    error instanceof Error
      ? error.message.includes('admin role')
        ? 'Admin role required.'
        : error.message
      : null

  return (
    <div className="p-6">
      <header className="mb-4">
        <h1 className="text-lg font-semibold text-neutral-50">Audit</h1>
        <p className="text-[13px] text-neutral-400">
          Background-writer counters from <code>/v1/kms/audit/stats</code>. Every secret read, write,
          rotate, and delete is recorded to a host-side SQLite ledger; per-event tailing is operator
          tooling, not a UI surface.
        </p>
      </header>

      {errMsg ? (
        <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
          {errMsg}
        </div>
      ) : (
        <div className="grid grid-cols-2 gap-4">
          <StatCard label="Entries written" value={isLoading ? '…' : data?.written ?? 0} />
          <StatCard
            label="Entries dropped"
            value={isLoading ? '…' : data?.dropped ?? 0}
            highlight={data?.dropped ? data.dropped > 0 : false}
          />
        </div>
      )}

      <Card className="mt-6 p-4 text-[12px] text-neutral-400">
        <h2 className="mb-2 text-sm font-semibold text-neutral-200">How to read the ledger</h2>
        <p>
          The audit ledger lives at the path configured by <code>KMS_AUDIT_DB</code> (default{' '}
          <code>/tmp/kms-aux.db</code>). It is append-only, buffered, and never blocks the request
          path. To inspect entries, exec into the pod and use the <code>kms</code> CLI:
        </p>
        <pre className="mt-2 overflow-auto rounded-md border border-neutral-900 bg-neutral-925/60 p-3 font-mono text-[12px] text-neutral-200">
          {`kubectl exec deploy/kms -- /usr/local/bin/kms audit tail --since 1h`}
        </pre>
      </Card>
    </div>
  )
}

function StatCard({
  label,
  value,
  highlight,
}: {
  label: string
  value: number | string
  highlight?: boolean
}) {
  return (
    <Card className="p-5">
      <div className="text-[11px] font-medium uppercase tracking-wider text-neutral-500">{label}</div>
      <div
        className={
          'mt-1 text-3xl font-semibold ' + (highlight ? 'text-red-400' : 'text-neutral-50')
        }
      >
        {value}
      </div>
    </Card>
  )
}
