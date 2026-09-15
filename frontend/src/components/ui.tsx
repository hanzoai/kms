import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  children: ReactNode
}

const base =
  'inline-flex items-center justify-center gap-2 rounded-md px-3 py-1.5 text-[13px] font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-neutral-600 disabled:cursor-not-allowed disabled:opacity-50'

const variants: Record<ButtonVariant, string> = {
  primary: 'bg-white text-black hover:bg-neutral-200',
  secondary: 'border border-neutral-800 bg-neutral-900 text-neutral-100 hover:bg-neutral-800',
  danger: 'border border-red-900/70 text-red-300 hover:bg-red-950/60',
  ghost: 'text-neutral-300 hover:bg-neutral-900 hover:text-neutral-100',
}

export function Button({ variant = 'secondary', className, children, type = 'button', ...rest }: ButtonProps) {
  return (
    <button {...rest} type={type} className={cn(base, variants[variant], className)}>
      {children}
    </button>
  )
}

const field =
  'w-full rounded-md border border-neutral-800 bg-black px-3 py-1.5 text-[13px] text-neutral-100 placeholder-neutral-600 focus:border-neutral-500 focus:outline-none disabled:opacity-50'

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...rest} className={cn(field, className)} />
}

export function TextArea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...rest} className={cn(field, 'font-mono', className)} />
}

export function Label({ children, htmlFor }: { children: ReactNode; htmlFor?: string }) {
  return (
    <label htmlFor={htmlFor} className="text-[12px] font-medium text-neutral-400">
      {children}
    </label>
  )
}

export function Badge({ variant = 'neutral', children }: { variant?: 'neutral' | 'success' | 'danger'; children: ReactNode }) {
  const tone = {
    neutral: 'bg-neutral-900 text-neutral-300',
    success: 'bg-emerald-950 text-emerald-300',
    danger: 'bg-red-950 text-red-300',
  }[variant]
  return <span className={cn('inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium', tone)}>{children}</span>
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn('rounded-lg border border-neutral-900 bg-neutral-950', className)}>{children}</div>
}

export function CodeBlock({ children }: { children: ReactNode }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md border border-neutral-900 bg-black p-3 font-mono text-[12px] text-neutral-200">
      {children}
    </pre>
  )
}

export function Notice({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-red-900/60 bg-red-950/40 px-3 py-2 text-[12px] text-red-200" role="alert">
      {children}
    </p>
  )
}
