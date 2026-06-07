import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cn } from '@/lib/cn'

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  children: ReactNode
}

const base =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-[13px] font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-neutral-950 disabled:cursor-not-allowed disabled:opacity-50'

const variants: Record<ButtonVariant, string> = {
  primary:
    'bg-[color:var(--color-brand)] text-white hover:bg-[color:var(--color-brand-hover)] focus:ring-[color:var(--color-brand)]',
  secondary:
    'border border-neutral-800 bg-neutral-900 text-neutral-100 hover:bg-neutral-800 focus:ring-neutral-700',
  danger:
    'bg-red-700 text-white hover:bg-red-800 focus:ring-red-700',
  ghost:
    'text-neutral-300 hover:bg-neutral-900 hover:text-neutral-100 focus:ring-neutral-700',
}

export function Button({ variant = 'secondary', className, children, ...rest }: ButtonProps) {
  return (
    <button {...rest} className={cn(base, variants[variant], className)}>
      {children}
    </button>
  )
}

export function Input({
  className,
  ...rest
}: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={cn(
        'w-full rounded-md border border-neutral-800 bg-neutral-950 px-3 py-1.5 text-[13px] text-neutral-100 placeholder-neutral-500 focus:border-[color:var(--color-brand)] focus:outline-none focus:ring-1 focus:ring-[color:var(--color-brand)] disabled:opacity-50',
        className,
      )}
    />
  )
}

export function Label({
  children,
  htmlFor,
}: {
  children: ReactNode
  htmlFor?: string
}) {
  return (
    <label htmlFor={htmlFor} className="text-[12px] font-medium text-neutral-400">
      {children}
    </label>
  )
}

export function Badge({
  variant = 'neutral',
  children,
}: {
  variant?: 'neutral' | 'success' | 'warn' | 'danger' | 'brand'
  children: ReactNode
}) {
  const v = {
    neutral: 'bg-neutral-800 text-neutral-300',
    success: 'bg-emerald-900/60 text-emerald-200',
    warn: 'bg-amber-900/60 text-amber-200',
    danger: 'bg-red-900/60 text-red-200',
    brand: 'text-white',
  }[variant]
  const style =
    variant === 'brand' ? { background: 'var(--color-brand)' } : undefined
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium',
        v,
      )}
      style={style}
    >
      {children}
    </span>
  )
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('rounded-lg border border-neutral-900 bg-neutral-950', className)}>
      {children}
    </div>
  )
}

export function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="overflow-auto rounded-md border border-neutral-900 bg-neutral-925/60 p-3 font-mono text-[12px] text-neutral-200">
      {children}
    </pre>
  )
}
