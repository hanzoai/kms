import clsx, { type ClassValue } from 'clsx'

// One way to compose class strings. No tailwind-merge — we don't allow
// conflicting class lists in this codebase; if it happens, fix the call
// site.
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs)
}
