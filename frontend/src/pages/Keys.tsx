import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listKeys, type ValidatorKeySet } from '@/lib/api'
import { CollectionCRUD, SearchInput, useFilter, type Column } from '@/components/CollectionCRUD'
import { Badge, CodeBlock } from '@/components/Button'

// MPC keys — the one resource with a real list endpoint in the canonical
// surface (/v1/kms/keys, admin role required). Renders flat via
// CollectionCRUD. Row click expands the full key set into the side
// panel.

const columns: Column<ValidatorKeySet>[] = [
  {
    key: 'id',
    header: 'ID',
    render: (r) => <code className="text-[12px] text-neutral-200">{r.id}</code>,
  },
  {
    key: 'validator',
    header: 'Validator',
    render: (r) => <code className="text-[12px] text-neutral-200">{r.validator_id || '—'}</code>,
  },
  {
    key: 'threshold',
    header: 'Threshold',
    render: (r) =>
      r.threshold && r.parties ? `${r.threshold} of ${r.parties}` : '—',
  },
  {
    key: 'created',
    header: 'Created',
    render: (r) => <span className="text-[12px] text-neutral-400">{r.created_at || '—'}</span>,
  },
]

export function KeysPage() {
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState<ValidatorKeySet | null>(null)
  const { data, isLoading, error } = useQuery({
    queryKey: ['keys'],
    queryFn: listKeys,
    retry: false,
  })
  const filtered = useFilter(data, query, ['id', 'validator_id'])
  const errMsg =
    error instanceof Error
      ? error.message.includes('admin role')
        ? 'Admin role required to list keys.'
        : error.message
      : null

  return (
    <div className="flex h-full min-h-0">
      <div className="flex-1 overflow-y-auto">
        <CollectionCRUD<ValidatorKeySet>
          title="MPC Keys"
          description="Threshold-signing key sets managed via the MPC daemon. Admin role required."
          rows={filtered}
          columns={columns}
          rowKey={(r) => r.id}
          loading={isLoading}
          error={errMsg}
          onRowClick={(r) => setOpen(r)}
          headerExtra={<SearchInput value={query} onChange={setQuery} placeholder="Filter…" />}
          empty={
            <div className="rounded-lg border border-neutral-900 bg-neutral-950 px-4 py-12 text-center">
              <p className="text-sm text-neutral-300">No key sets yet.</p>
              <p className="mt-1 text-[12px] text-neutral-500">
                MPC keys are generated via{' '}
                <code>POST /v1/kms/keys/generate</code> — provide validator_id, threshold, parties.
              </p>
            </div>
          }
        />
      </div>
      {open && <KeyDetail item={open} onClose={() => setOpen(null)} />}
    </div>
  )
}

function KeyDetail({ item, onClose }: { item: ValidatorKeySet; onClose: () => void }) {
  return (
    <aside className="w-96 shrink-0 overflow-y-auto border-l border-neutral-900 bg-neutral-950 p-5">
      <header className="mb-4 flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Badge variant="brand">key set</Badge>
            {item.threshold && item.parties && (
              <Badge>{`${item.threshold} of ${item.parties}`}</Badge>
            )}
          </div>
          <h2 className="mt-2 break-all text-sm font-semibold text-neutral-50">{item.id}</h2>
        </div>
        <button
          onClick={onClose}
          className="text-[20px] leading-none text-neutral-500 hover:text-neutral-200"
        >
          ×
        </button>
      </header>
      <pre className="overflow-auto rounded-md border border-neutral-900 bg-neutral-925/60 p-3 font-mono text-[11px] text-neutral-200">
        {JSON.stringify(item, null, 2)}
      </pre>
      <p className="mt-3 text-[11px] text-neutral-500">
        Sign and rotate calls live at <code>/v1/kms/keys/&#123;id&#125;/sign</code> and{' '}
        <code>/v1/kms/keys/&#123;id&#125;/rotate</code>. Use the <code>kms</code> CLI for those —
        signing payloads should not pass through a browser session.
      </p>
      {(item.bls_public_key || item.ringtail_public_key) && (
        <div className="mt-4 flex flex-col gap-2">
          {item.bls_public_key && (
            <div>
              <div className="text-[11px] font-medium text-neutral-400">BLS public key</div>
              <CodeBlock>{String(item.bls_public_key)}</CodeBlock>
            </div>
          )}
          {item.ringtail_public_key && (
            <div>
              <div className="text-[11px] font-medium text-neutral-400">Ringtail public key</div>
              <CodeBlock>{String(item.ringtail_public_key)}</CodeBlock>
            </div>
          )}
        </div>
      )}
    </aside>
  )
}
