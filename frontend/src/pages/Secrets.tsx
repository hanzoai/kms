import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { deleteSecret, listSecrets, openSecret, putSecret } from '@/lib/api'
import type { Draft, SecretMeta } from '@/lib/kms'
import { Badge, Button, Card, CodeBlock, Input, Label, TextArea } from '@/components/ui'
import { Failure } from '@/components/Failure'

// Secrets: the organization's listing from GET /v1/kms/secrets, narrowed by path
// and environment. A value is fetched only when a row is opened, and written or
// removed one secret at a time.

export function SecretsPage() {
  const qc = useQueryClient()
  const [path, setPath] = useState('')
  const [env, setEnv] = useState('')
  const [filter, setFilter] = useState({ path: '', env: '' })
  const [creating, setCreating] = useState(false)

  const list = useQuery({
    queryKey: ['secrets', filter.path, filter.env],
    queryFn: () => listSecrets(filter.path, filter.env),
  })

  const refresh = () => qc.invalidateQueries({ queryKey: ['secrets'] })

  function apply(e: FormEvent) {
    e.preventDefault()
    setFilter({ path, env })
  }

  return (
    <div className="mx-auto max-w-5xl p-6">
      <header className="mb-5 flex items-end justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-neutral-50">Secrets</h1>
          <p className="text-[13px] text-neutral-400">
            What your organization holds, by path and environment. A value stays sealed until you open it.
          </p>
        </div>
        <Button variant="primary" onClick={() => setCreating((v) => !v)}>
          {creating ? 'Close' : 'New secret'}
        </Button>
      </header>

      {creating && (
        <Editor
          title="New secret"
          initial={{ path: filter.path, name: '', env: filter.env || '', value: '' }}
          onSaved={() => {
            setCreating(false)
            refresh()
          }}
        />
      )}

      <form onSubmit={apply} className="mb-4 flex flex-wrap items-end gap-3">
        <div className="flex w-64 flex-col gap-1">
          <Label htmlFor="filter-path">Path</Label>
          <Input id="filter-path" placeholder="/ci" value={path} onChange={(e) => setPath(e.target.value)} />
        </div>
        <div className="flex w-40 flex-col gap-1">
          <Label htmlFor="filter-env">Environment</Label>
          <Input id="filter-env" placeholder="all" value={env} onChange={(e) => setEnv(e.target.value)} />
        </div>
        <Button type="submit">Filter</Button>
      </form>

      {list.isPending && <p className="text-[13px] text-neutral-500">Loading secrets</p>}
      {list.isError && <Failure error={list.error} />}
      {list.data &&
        (list.data.secrets.length === 0 ? (
          <Card className="p-6 text-[13px] text-neutral-400">
            No secrets here yet. Create one with New secret.
          </Card>
        ) : (
          <Card className="overflow-hidden">
            <table className="w-full text-left text-[13px]">
              <thead className="border-b border-neutral-900 text-[11px] uppercase tracking-wider text-neutral-500">
                <tr>
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="px-4 py-2 font-medium">Path</th>
                  <th className="px-4 py-2 font-medium">Environment</th>
                  <th className="px-4 py-2 font-medium">Sealing</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {list.data.secrets.map((s) => (
                  <Row key={`${s.env}|${s.path}|${s.name}`} secret={s} onChanged={refresh} />
                ))}
              </tbody>
            </table>
          </Card>
        ))}
    </div>
  )
}

function Row({ secret, onChanged }: { secret: SecretMeta; onChanged: () => void }) {
  const [value, setValue] = useState<string | null>(null)
  const [replacing, setReplacing] = useState(false)

  const open = useMutation({ mutationFn: () => openSecret(secret), onSuccess: (o) => setValue(o.value) })
  const remove = useMutation({ mutationFn: () => deleteSecret(secret), onSuccess: onChanged })

  const error = open.error ?? remove.error

  return (
    <>
      <tr className="border-b border-neutral-900 last:border-0">
        <td className="px-4 py-2 font-mono text-neutral-100">{secret.name}</td>
        <td className="px-4 py-2 font-mono text-neutral-400">{secret.path || '/'}</td>
        <td className="px-4 py-2">
          <Badge>{secret.env}</Badge>
        </td>
        <td className="px-4 py-2 text-neutral-500">{secret.scheme}</td>
        <td className="px-4 py-2">
          <div className="flex justify-end gap-1">
            {value === null ? (
              <Button variant="ghost" onClick={() => open.mutate()} disabled={open.isPending}>
                {open.isPending ? 'Opening' : 'Open'}
              </Button>
            ) : (
              <Button variant="ghost" onClick={() => setValue(null)}>
                Hide
              </Button>
            )}
            <Button variant="ghost" onClick={() => setReplacing((v) => !v)}>
              Replace
            </Button>
            <Button
              variant="danger"
              disabled={remove.isPending}
              onClick={() => {
                if (window.confirm(`Delete ${secret.name} from ${secret.env}?`)) remove.mutate()
              }}
            >
              Delete
            </Button>
          </div>
        </td>
      </tr>
      {(value !== null || replacing || error) && (
        <tr className="border-b border-neutral-900">
          <td colSpan={5} className="space-y-3 bg-black px-4 py-3">
            {error && <Failure error={error} />}
            {value !== null && (
              <div className="flex flex-col gap-2">
                <CodeBlock>{value}</CodeBlock>
                <div>
                  <Button variant="secondary" onClick={() => void navigator.clipboard.writeText(value)}>
                    Copy
                  </Button>
                </div>
              </div>
            )}
            {replacing && (
              <Editor
                title={`Replace ${secret.name}`}
                initial={{ path: secret.path, name: secret.name, env: secret.env, value: '' }}
                fixed
                onSaved={() => {
                  setReplacing(false)
                  setValue(null)
                  onChanged()
                }}
              />
            )}
          </td>
        </tr>
      )}
    </>
  )
}

function Editor({
  title,
  initial,
  fixed = false,
  onSaved,
}: {
  title: string
  initial: Draft
  fixed?: boolean
  onSaved: () => void
}) {
  const [draft, setDraft] = useState<Draft>(initial)
  const save = useMutation({ mutationFn: () => putSecret(draft), onSuccess: onSaved })
  const set = (key: keyof Draft) => (e: { target: { value: string } }) => setDraft({ ...draft, [key]: e.target.value })

  function submit(e: FormEvent) {
    e.preventDefault()
    save.mutate()
  }

  return (
    <Card className="mb-4 p-4">
      <form onSubmit={submit} className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-neutral-100">{title}</h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div className="flex flex-col gap-1">
            <Label htmlFor={`${title}-path`}>Path</Label>
            <Input id={`${title}-path`} placeholder="/ci" value={draft.path} onChange={set('path')} disabled={fixed} />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor={`${title}-name`}>Name</Label>
            <Input id={`${title}-name`} placeholder="NPM_TOKEN" value={draft.name} onChange={set('name')} disabled={fixed} required />
          </div>
          <div className="flex flex-col gap-1">
            <Label htmlFor={`${title}-env`}>Environment</Label>
            <Input id={`${title}-env`} placeholder="prod" value={draft.env} onChange={set('env')} disabled={fixed} required />
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <Label htmlFor={`${title}-value`}>Value</Label>
          <TextArea id={`${title}-value`} rows={3} value={draft.value} onChange={set('value')} required autoComplete="off" spellCheck={false} />
        </div>
        {save.error && <Failure error={save.error} />}
        <div>
          <Button type="submit" variant="primary" disabled={save.isPending || !draft.value}>
            {save.isPending ? 'Saving' : 'Save'}
          </Button>
        </div>
      </form>
    </Card>
  )
}
