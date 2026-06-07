import type { ReactNode } from 'react'
import { Link, useLocation } from 'wouter'
import { brand } from '@hanzo/brand'
import { cn } from '@/lib/cn'

// AdminShell — the chrome wrapper. Sidebar on the left, topbar across
// the top, content fills the rest. One layout for every admin page.
// Pages compose by passing children; the shell never knows what's in
// them.

export interface NavItem {
  href: string
  label: string
  badge?: string
}

export interface NavSection {
  title: string
  items: NavItem[]
}

export interface AdminShellProps {
  sections: NavSection[]
  title: string
  topRight?: ReactNode
  children: ReactNode
}

export function AdminShell({ sections, title, topRight, children }: AdminShellProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-neutral-950 text-neutral-100">
      <Sidebar sections={sections} title={title} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar title={title} topRight={topRight} />
        <main className="flex-1 overflow-auto bg-neutral-950">{children}</main>
      </div>
    </div>
  )
}

interface SidebarProps {
  sections: NavSection[]
  title: string
}

function Sidebar({ sections, title }: SidebarProps) {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-neutral-900 bg-neutral-950">
      <Link
        href="/"
        className="flex items-center gap-2 px-4 py-4 text-sm font-semibold text-neutral-50"
      >
        <BrandMark />
        <span>{title}</span>
      </Link>
      <nav className="flex flex-1 flex-col gap-3 overflow-y-auto px-2 pb-4">
        {sections.map((s) => (
          <NavSectionView key={s.title} section={s} />
        ))}
      </nav>
      <SidebarFooter />
    </aside>
  )
}

function NavSectionView({ section }: { section: NavSection }) {
  return (
    <div className="flex flex-col gap-px">
      <div className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.08em] text-neutral-500">
        {section.title}
      </div>
      {section.items.map((it) => (
        <NavLink key={it.href} item={it} />
      ))}
    </div>
  )
}

function NavLink({ item }: { item: NavItem }) {
  const [location] = useLocation()
  const active =
    item.href === '/' ? location === '/' : location === item.href || location.startsWith(`${item.href}/`)
  return (
    <Link
      href={item.href}
      className={cn(
        'flex items-center justify-between rounded-md px-3 py-1.5 text-[13px] transition-colors',
        active
          ? 'bg-neutral-800/80 text-neutral-50'
          : 'text-neutral-400 hover:bg-neutral-900 hover:text-neutral-100',
      )}
    >
      <span>{item.label}</span>
      {item.badge && (
        <span className="rounded-full bg-neutral-800 px-1.5 py-0.5 text-[10px] font-medium text-neutral-300">
          {item.badge}
        </span>
      )}
    </Link>
  )
}

function SidebarFooter() {
  return (
    <div className="border-t border-neutral-900 px-4 py-3 text-[11px] text-neutral-500">
      <div>{brand.name} KMS</div>
      <a
        href="https://docs.hanzo.ai"
        target="_blank"
        rel="noreferrer"
        className="text-neutral-400 hover:text-neutral-200"
      >
        docs.hanzo.ai
      </a>
    </div>
  )
}

interface TopBarProps {
  title: string
  topRight?: ReactNode
}

function TopBar({ topRight }: TopBarProps) {
  const [location] = useLocation()
  const crumbs = location.split('/').filter(Boolean)
  return (
    <header className="flex h-12 shrink-0 items-center justify-between border-b border-neutral-900 bg-neutral-950 px-4">
      <div className="flex items-center gap-2 text-[13px] text-neutral-400">
        <span>/</span>
        {crumbs.map((c, i) => (
          <span key={i} className="flex items-center gap-2">
            <span className="text-neutral-200">{decodeURIComponent(c)}</span>
            {i < crumbs.length - 1 && <span>/</span>}
          </span>
        ))}
      </div>
      <div className="flex items-center gap-3">{topRight}</div>
    </header>
  )
}

function BrandMark() {
  return (
    <span
      className="inline-flex h-5 w-5 items-center justify-center rounded-[3px] font-mono text-[11px] font-bold text-white"
      style={{ background: 'var(--color-brand)' }}
      aria-hidden
    >
      H
    </span>
  )
}
