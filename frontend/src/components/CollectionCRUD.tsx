import { useMemo, type ReactNode } from 'react'

// CollectionCRUD — the one abstraction we keep. Renders a flat
// collection: header, optional create row, error/empty/loading states,
// a typed table.
//
// What it is NOT:
//  - It is not a god-component. It does not own data fetching, mutation,
//    URL state, or pagination. Pages decide all of that — this only
//    renders.
//  - It does not own row clicks. Pass `onRowClick` if you need them.
//  - It does not own filters. Render them as part of `headerExtra`.

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  className?: string
  width?: string | number
}

export interface CollectionCRUDProps<T> {
  title: string
  description?: string
  rows: T[] | undefined
  columns: Column<T>[]
  rowKey: (row: T) => string
  loading?: boolean
  error?: string | null
  empty?: ReactNode
  headerExtra?: ReactNode
  onRowClick?: (row: T) => void
}

export function CollectionCRUD<T>(props: CollectionCRUDProps<T>) {
  const { title, description, rows, columns, rowKey, loading, error, empty, headerExtra, onRowClick } =
    props
  const isEmpty = !loading && !error && (!rows || rows.length === 0)
  return (
    <div className="flex flex-col gap-4 p-6">
      <header className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold text-neutral-50">{title}</h1>
          {description && <p className="mt-0.5 text-[13px] text-neutral-400">{description}</p>}
        </div>
        <div className="flex items-center gap-2">{headerExtra}</div>
      </header>

      {error && <ErrorBanner message={error} />}

      {loading && (
        <div className="rounded-lg border border-neutral-900 bg-neutral-950 px-4 py-8 text-center text-sm text-neutral-500">
          Loading…
        </div>
      )}

      {!loading && !error && !isEmpty && (
        <DataTable rows={rows!} columns={columns} rowKey={rowKey} onRowClick={onRowClick} />
      )}

      {isEmpty && (empty || <EmptyBanner />)}
    </div>
  )
}

interface DataTableProps<T> {
  rows: T[]
  columns: Column<T>[]
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
}

function DataTable<T>({ rows, columns, rowKey, onRowClick }: DataTableProps<T>) {
  return (
    <div className="overflow-x-auto rounded-lg border border-neutral-900">
      <table className="w-full text-left text-[13px]">
        <thead className="bg-neutral-925/40">
          <tr className="border-b border-neutral-900">
            {columns.map((c) => (
              <th
                key={c.key}
                style={c.width ? { width: c.width } : undefined}
                className="px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-neutral-500"
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={
                onRowClick
                  ? 'cursor-pointer border-b border-neutral-900 last:border-0 hover:bg-neutral-900/40'
                  : 'border-b border-neutral-900 last:border-0'
              }
            >
              {columns.map((c) => (
                <td key={c.key} className={'px-3 py-2 text-neutral-200 ' + (c.className || '')}>
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-red-900/60 bg-red-950/40 px-4 py-3 text-sm text-red-200">
      {message}
    </div>
  )
}

function EmptyBanner() {
  return (
    <div className="rounded-lg border border-neutral-900 bg-neutral-950 px-4 py-12 text-center">
      <p className="text-sm text-neutral-400">No records found.</p>
    </div>
  )
}

// useFilter — small helper for client-side filtering. Pages use it to
// power the SearchInput → rows pipeline without each one re-inventing
// the case-insensitive substring match.
export function useFilter<T>(rows: T[] | undefined, query: string, fields: (keyof T)[]): T[] {
  return useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q || !rows) return rows || []
    return rows.filter((r) =>
      fields.some((f) => {
        const v = r[f]
        if (typeof v !== 'string') return false
        return v.toLowerCase().includes(q)
      }),
    )
  }, [rows, query, fields])
}

export function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
}) {
  return (
    <input
      type="search"
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      className="w-56 rounded-md border border-neutral-800 bg-neutral-950 px-3 py-1.5 text-[13px] text-neutral-100 placeholder-neutral-500 focus:border-[color:var(--color-brand)] focus:outline-none focus:ring-1 focus:ring-[color:var(--color-brand)]"
    />
  )
}

