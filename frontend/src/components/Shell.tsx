import type { ReactNode } from 'react'
import { Link, useLocation } from 'wouter'
import { cn } from '@/lib/cn'
import { Button } from '@/components/ui'

// The console chrome: a sidebar of pages, a top bar naming who is signed in,
// and the page itself.

const pages = [
  { href: '/', label: 'Secrets' },
  { href: '/status', label: 'Status' },
]

export interface ShellProps {
  product: string
  user: string
  onSignOut: () => void
  children: ReactNode
}

export function Shell({ product, user, onSignOut, children }: ShellProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-neutral-950 text-neutral-100">
      <aside className="flex w-56 shrink-0 flex-col border-r border-neutral-900">
        <Link href="/" className="flex items-center gap-2 px-4 py-4 text-sm font-semibold text-neutral-50">
          <img src="/favicon.svg" alt="" className="h-5 w-5" />
          <span>{product}</span>
        </Link>
        <nav className="flex flex-1 flex-col gap-px px-2">
          {pages.map((p) => (
            <NavLink key={p.href} href={p.href} label={p.label} />
          ))}
        </nav>
        <a
          href="https://docs.hanzo.ai/docs/openapi/kms/"
          target="_blank"
          rel="noreferrer"
          className="border-t border-neutral-900 px-4 py-3 text-[12px] text-neutral-500 hover:text-neutral-200"
        >
          API reference
        </a>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-end gap-3 border-b border-neutral-900 px-4">
          {user && <span className="text-[12px] text-neutral-400">{user}</span>}
          <Button variant="ghost" onClick={onSignOut}>
            Sign out
          </Button>
        </header>
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  )
}

function NavLink({ href, label }: { href: string; label: string }) {
  const [location] = useLocation()
  const active = location === href
  return (
    <Link
      href={href}
      className={cn(
        'rounded-md px-3 py-1.5 text-[13px] transition-colors',
        active ? 'bg-neutral-800/80 text-neutral-50' : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-100',
      )}
    >
      {label}
    </Link>
  )
}
