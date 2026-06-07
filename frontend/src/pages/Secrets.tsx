import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ApiError,
  deleteSecret,
  getOrg,
  getSecret,
  patchSecret,
  putSecret,
} from '@/lib/api'
import { Badge, Button, Card, CodeBlock, Input, Label } from '@/components/Button'

// Secrets — bespoke browser, NOT a flat CollectionCRUD.
//
// The canonical /v1/kms/* surface has NO list endpoint for secrets — it
// is strictly path-addressed CRUD. So the "tree view" is a client-side
// breadcrumb of paths the operator has visited in this session, plus a
// direct lookup by (path, name, env).
//
// LocalStorage stores the visited paths so reloads don't lose the
// browsing context. Nothing else is cached — value lookups always hit
// the server.

const HISTORY_KEY = 'KMS_SECRET_HISTORY'

interface SecretRef {
  path: string
  name: string
  env: string
}

function loadHistory(): SecretRef[] {
  try {
    const raw = window.localStorage.getItem(HISTORY_KEY)
    if (!raw) return []
    const v = JSON.parse(raw)
    if (!Array.isArray(v)) return []
    return v.filter(
      (r): r is SecretRef =>
        typeof r === 'object' &&
        typeof r.path === 'string' &&
        typeof r.name === 'string' &&
        typeof r.env === 'string',
    )
  } catch {
    return []
  }
}

function saveHistory(refs: SecretRef[]): void {
  window.localStorage.setItem(HISTORY_KEY, JSON.stringify(refs.slice(0, 50)))
}

function refKey(r: SecretRef): string {
  return `${r.env}|${r.path}|${r.name}`
}

export function SecretsPage() {
  const [history, setHistory] = useState<SecretRef[]>(() => loadHistory())
  const [selected, setSelected] = useState<SecretRef | null>(null)

  useEffect(() => {
    saveHistory(history)
  }, [history])

  function record(ref: SecretRef) {
    setHistory((prev) => {
      const next = [ref, ...prev.filter((r) => refKey(r) !== refKey(ref))]
      return next
    })
  }

  function forget(ref: SecretRef) {
    setHistory((prev) => prev.filter((r) => refKey(r) !== refKey(ref)))
  }

  const tree = useMemo(() => buildTree(history), [history])

  return (
    <div className="flex h-full min-h-0">
      <aside className="w-72 shrink-0 overflow-y-auto border-r border-neutral-900 bg-neutral-950 p-3">
        <div className="px-1 pb-2 text-[11px] font-semibold uppercase tracking-wider text-neutral-500">
          Visited paths
        </div>
        {history.length === 0 ? (
          <p className="px-1 text-[12px] text-neutral-500">
            Nothing here yet. Look up a secret on the right to populate the tree.
          </p>
        ) : (
          <TreeView
            tree={tree}
            selected={selected}
            onSelect={(ref) => setSelected(ref)}
            onForget={forget}
          />
        )}
      </aside>

      <section className="flex flex-1 flex-col overflow-y-auto p-6">
        <header className="mb-4">
          <h1 className="text-lg font-semibold text-neutral-50">Secrets</h1>
          <p className="text-[13px] text-neutral-400">
            Read, write, rotate, and delete one secret at a time. The canonical
            <code className="ml-1 text-neutral-300">/v1/kms/orgs/&#123;org&#125;/secrets</code> surface
            is path-addressed — no listing — so the tree on the left only shows what you have visited
            in this session.
          </p>
        </header>

        <LookupForm onLookup={(ref) => { record(ref); setSelected(ref) }} initial={selected} />

        {selected && <SecretInspector ref_={selected} onForget={() => forget(selected)} />}
      </section>
    </div>
  )
}

interface LookupFormProps {
  onLookup: (ref: SecretRef) => void
  initial: SecretRef | null
}

function LookupForm({ onLookup, initial }: LookupFormProps) {
  const [path, setPath] = useState(initial?.path || '')
  const [name, setName] = useState(initial?.name || '')
  const [env, setEnv] = useState(initial?.env || 'default')

  useEffect(() => {
    if (initial) {
      setPath(initial.path)
      setName(initial.name)
      setEnv(initial.env)
    }
  }, [initial])

  function submit(e: FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    onLookup({
      path: normalizePath(path),
      name: name.trim(),
      env: env.trim() || 'default',
    })
  }

  return (
    <Card className="mb-6 p-4">
      <form onSubmit={submit} className="grid grid-cols-12 gap-3">
        <div className="col-span-5 flex flex-col gap-1">
          <Label htmlFor="path">Path</Label>
          <Input
            id="path"
            placeholder="commerce/prod"
            value={path}
            onChange={(e) => setPath(e.target.value)}
          />
        </div>
        <div className="col-span-3 flex flex-col gap-1">
          <Label htmlFor="name">Name</Label>
          <Input
            id="name"
            placeholder="STRIPE_LIVE_KEY"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </div>
        <div className="col-span-2 flex flex-col gap-1">
          <Label htmlFor="env">Env</Label>
          <Input id="env" placeholder="default" value={env} onChange={(e) => setEnv(e.target.value)} />
        </div>
        <div className="col-span-2 flex items-end">
          <Button type="submit" variant="primary" className="w-full">
            Open
          </Button>
        </div>
      </form>
    </Card>
  )
}

interface SecretInspectorProps {
  ref_: SecretRef
  onForget: () => void
}

function SecretInspector({ ref_, onForget }: SecretInspectorProps) {
  const qc = useQueryClient()
  const org = getOrg()
  const queryKey = ['secret', org, ref_.path, ref_.name, ref_.env]
  const { data, error, isLoading, isFetching } = useQuery({
    queryKey,
    queryFn: () => getSecret(org, ref_.path, ref_.name, ref_.env),
    retry: false,
  })

  const [value, setValue] = useState('')
  const [reveal, setReveal] = useState(false)
  const [editing, setEditing] = useState(false)
  const [mutError, setMutError] = useState<string | null>(null)

  useEffect(() => {
    setValue(data?.secret.value || '')
    setEditing(false)
    setMutError(null)
    setReveal(false)
  }, [data, ref_.env, ref_.path, ref_.name])

  const patchMut = useMutation({
    mutationFn: () =>
      patchSecret(org, ref_.path, ref_.name, {
        value,
        version: data!.version,
        env: ref_.env,
      }),
    onSuccess: () => {
      setEditing(false)
      qc.invalidateQueries({ queryKey })
    },
    onError: (e) => setMutError((e as Error).message),
  })

  const putMut = useMutation({
    mutationFn: () =>
      putSecret(org, {
        path: ref_.path,
        name: ref_.name,
        env: ref_.env,
        value,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey })
    },
    onError: (e) => setMutError((e as Error).message),
  })

  const delMut = useMutation({
    mutationFn: () => deleteSecret(org, ref_.path, ref_.name, ref_.env),
    onSuccess: () => {
      qc.removeQueries({ queryKey })
      onForget()
    },
    onError: (e) => setMutError((e as Error).message),
  })

  const notFound = error instanceof ApiError && error.status === 404
  const otherErr = error && !notFound ? (error as Error).message : null

  return (
    <Card className="flex flex-col gap-3 p-4">
      <header className="flex items-start justify-between gap-4">
        <div>
          <div className="text-[12px] text-neutral-500">
            <code className="text-neutral-300">{ref_.path || '/'}</code> ·{' '}
            <Badge variant="brand">{ref_.env}</Badge>
          </div>
          <h2 className="text-base font-semibold text-neutral-50">{ref_.name}</h2>
        </div>
        <div className="flex items-center gap-2">
          {data && <Badge>v{data.version}</Badge>}
          {isFetching && <span className="text-[11px] text-neutral-500">refreshing…</span>}
        </div>
      </header>

      {isLoading && <p className="text-[12px] text-neutral-500">Loading…</p>}

      {otherErr && (
        <p className="rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-[12px] text-red-200">
          {otherErr}
        </p>
      )}

      {notFound && (
        <div className="flex flex-col gap-3 rounded-md border border-amber-900/60 bg-amber-950/40 px-3 py-3 text-[12px] text-amber-200">
          <p>Secret not found. Type a value and write it to create v1.</p>
          <textarea
            value={value}
            onChange={(e) => setValue(e.target.value)}
            rows={3}
            className="w-full rounded-md border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[12px] text-neutral-100"
            placeholder="secret value"
          />
          <div className="flex gap-2">
            <Button
              variant="primary"
              onClick={() => {
                setMutError(null)
                putMut.mutate()
              }}
              disabled={!value.trim() || putMut.isPending}
            >
              {putMut.isPending ? 'Creating…' : 'Create v1'}
            </Button>
          </div>
        </div>
      )}

      {data && !notFound && (
        <>
          <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <Label>Value</Label>
              <div className="flex gap-2">
                <Button variant="ghost" onClick={() => setReveal((v) => !v)}>
                  {reveal ? 'Hide' : 'Reveal'}
                </Button>
                <Button
                  variant="ghost"
                  onClick={async () => {
                    await navigator.clipboard.writeText(data.secret.value)
                  }}
                >
                  Copy
                </Button>
              </div>
            </div>
            {editing ? (
              <textarea
                value={value}
                onChange={(e) => setValue(e.target.value)}
                rows={4}
                className="w-full rounded-md border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[12px] text-neutral-100"
              />
            ) : reveal ? (
              <CodeBlock>{data.secret.value}</CodeBlock>
            ) : (
              <CodeBlock>{'•'.repeat(Math.min(data.secret.value.length, 48))}</CodeBlock>
            )}
          </div>

          {mutError && (
            <p className="rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-[12px] text-red-200">
              {mutError}
            </p>
          )}

          <div className="flex items-center justify-between">
            <div className="flex gap-2">
              {!editing && (
                <Button variant="primary" onClick={() => setEditing(true)}>
                  Rotate
                </Button>
              )}
              {editing && (
                <>
                  <Button
                    variant="primary"
                    onClick={() => {
                      setMutError(null)
                      patchMut.mutate()
                    }}
                    disabled={patchMut.isPending || !value.trim()}
                  >
                    {patchMut.isPending ? 'Saving…' : `Save v${data.version + 1}`}
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setEditing(false)
                      setValue(data.secret.value)
                    }}
                  >
                    Cancel
                  </Button>
                </>
              )}
            </div>
            <Button
              variant="danger"
              onClick={() => {
                if (window.confirm(`Delete ${ref_.name}@${ref_.env}? Versioning resets to 0.`)) {
                  setMutError(null)
                  delMut.mutate()
                }
              }}
              disabled={delMut.isPending}
            >
              {delMut.isPending ? 'Deleting…' : 'Delete'}
            </Button>
          </div>

          <p className="text-[11px] text-neutral-500">
            PATCH bumps version with strict CAS via the <code>If-Match</code> header. POST is upsert.
            DELETE clears the version record so a re-create starts at v1.
          </p>
        </>
      )}
    </Card>
  )
}

// --- Tree view --------------------------------------------------------

interface TreeNode {
  segment: string
  full: string
  children: TreeNode[]
  refs: SecretRef[]
}

function buildTree(refs: SecretRef[]): TreeNode {
  const root: TreeNode = { segment: '', full: '', children: [], refs: [] }
  for (const ref of refs) {
    const parts = ref.path.split('/').filter(Boolean)
    let cur = root
    let acc = ''
    for (const p of parts) {
      acc = acc ? `${acc}/${p}` : p
      let next = cur.children.find((c) => c.segment === p)
      if (!next) {
        next = { segment: p, full: acc, children: [], refs: [] }
        cur.children.push(next)
      }
      cur = next
    }
    cur.refs.push(ref)
  }
  return root
}

function TreeView({
  tree,
  selected,
  onSelect,
  onForget,
}: {
  tree: TreeNode
  selected: SecretRef | null
  onSelect: (ref: SecretRef) => void
  onForget: (ref: SecretRef) => void
}) {
  return (
    <ul className="flex flex-col gap-px">
      {tree.refs.map((r) => (
        <RefLine
          key={refKey(r)}
          ref_={r}
          active={selected && refKey(selected) === refKey(r)}
          onSelect={onSelect}
          onForget={onForget}
        />
      ))}
      {tree.children.map((c) => (
        <TreeBranch
          key={c.full}
          node={c}
          depth={0}
          selected={selected}
          onSelect={onSelect}
          onForget={onForget}
        />
      ))}
    </ul>
  )
}

function TreeBranch({
  node,
  depth,
  selected,
  onSelect,
  onForget,
}: {
  node: TreeNode
  depth: number
  selected: SecretRef | null
  onSelect: (ref: SecretRef) => void
  onForget: (ref: SecretRef) => void
}) {
  const [open, setOpen] = useState(true)
  return (
    <li>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-1 rounded-sm px-1 py-0.5 text-left text-[12px] text-neutral-300 hover:bg-neutral-900"
        style={{ paddingLeft: depth * 12 + 4 }}
      >
        <span className="font-mono text-[10px] text-neutral-500">{open ? '▾' : '▸'}</span>
        <span>{node.segment}/</span>
      </button>
      {open && (
        <ul className="flex flex-col gap-px">
          {node.refs.map((r) => (
            <RefLine
              key={refKey(r)}
              ref_={r}
              depth={depth + 1}
              active={selected && refKey(selected) === refKey(r)}
              onSelect={onSelect}
              onForget={onForget}
            />
          ))}
          {node.children.map((c) => (
            <TreeBranch
              key={c.full}
              node={c}
              depth={depth + 1}
              selected={selected}
              onSelect={onSelect}
              onForget={onForget}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

function RefLine({
  ref_,
  depth = 0,
  active,
  onSelect,
  onForget,
}: {
  ref_: SecretRef
  depth?: number
  active: boolean | null
  onSelect: (r: SecretRef) => void
  onForget: (r: SecretRef) => void
}) {
  return (
    <li className="group flex items-center gap-1" style={{ paddingLeft: depth * 12 + 16 }}>
      <button
        onClick={() => onSelect(ref_)}
        className={
          'flex-1 truncate rounded-sm px-1.5 py-0.5 text-left text-[12px] ' +
          (active
            ? 'bg-neutral-800/80 text-neutral-50'
            : 'text-neutral-300 hover:bg-neutral-900 hover:text-neutral-100')
        }
        title={`${ref_.path}/${ref_.name} (${ref_.env})`}
      >
        {ref_.name}
        <span className="ml-1 text-[10px] text-neutral-500">{ref_.env}</span>
      </button>
      <button
        onClick={() => onForget(ref_)}
        className="opacity-0 transition-opacity group-hover:opacity-100"
        title="Forget"
      >
        <span className="text-[10px] text-neutral-500 hover:text-neutral-200">×</span>
      </button>
    </li>
  )
}

function normalizePath(p: string): string {
  return p
    .split('/')
    .map((s) => s.trim())
    .filter(Boolean)
    .join('/')
}
