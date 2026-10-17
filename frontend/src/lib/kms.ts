// The KMS surface the console calls, as types and addresses. cloud serves all of
// it under /v1/kms, and the org is the caller's, read from the token: no address
// here names one.

export const base = '/v1/kms'

/** GET /v1/kms/config: what the console needs before anyone signs in. */
export interface Config {
  apiBase: string
  brand: string
  issuer: string
  loginPath: string
}

/** GET /v1/kms/health: the same body at 200 (ready) and 503 (not ready). */
export interface Health {
  ready: boolean
  service: string
  status: string
  signing?: boolean
  error?: string
}

/** One secret's descriptor. A listing never carries a value. */
export interface SecretMeta {
  name: string
  path: string
  env: string
  scheme: string
}

export interface Listing {
  names: string[]
  secrets: SecretMeta[]
  total: number
}

export interface Opened {
  env: string
  name: string
  value: string
}

export interface Draft {
  path: string
  name: string
  env: string
  value: string
}

/** The IAM client a brand's console signs in through, named <org>-<app>. */
export function clientId(brand: string): string {
  return `${brand}-kms`
}

/** Where a brand's people sign in, and where its console reads IAM's discovery.
 *  Only Hanzo signs in on its own site (hanzo.ai/login finishes this console's own
 *  request); a brand absent here signs in at its issuer, as the server names it.
 *  Brands never cross. */
export interface Home {
  /** The page that finishes this console's authorize request. */
  signin: string
  /** IAM's public endpoints (discovery). */
  api: string
}

const HOMES: Readonly<Record<string, Home>> = {
  hanzo: { signin: 'https://hanzo.ai/login', api: 'https://api.hanzo.ai' },
}

export function home(brand: string): Home | null {
  return Object.hasOwn(HOMES, brand) ? HOMES[brand] : null
}

/** The address that finishes an authorize request: the brand's sign-in page carrying
 *  the request's own query, or the authorize address itself where there is none. */
export function signinAddress(page: string | null, authorize: string): string {
  return page ? `${page}${new URL(authorize).search}` : authorize
}

/** A same-origin path to come back to, or `/`: one leading slash and nothing the
 *  URL parser would read as another host. */
export function back(path: string | null): string {
  if (!path || !path.startsWith('/')) return '/'
  try {
    const base = 'https://kms.invalid'
    const u = new URL(path, base)
    return u.origin === base ? `${u.pathname}${u.search}${u.hash}` : '/'
  } catch {
    return '/'
  }
}

/** A path as the API stores it: `/a/b`, or empty for the org root. */
export function cleanPath(path: string): string {
  const parts = path
    .split('/')
    .map((s) => s.trim())
    .filter(Boolean)
  return parts.length ? `/${parts.join('/')}` : ''
}

/** The listing of a subtree in one environment. Empty values mean all of it. */
export function listUrl(path: string, env: string): string {
  const q = new URLSearchParams()
  const p = cleanPath(path)
  if (p) q.set('path', p)
  const e = env.trim()
  if (e) q.set('env', e)
  const s = q.toString()
  return s ? `${base}/secrets?${s}` : `${base}/secrets`
}

/** One secret's address: its path segments, then its name, each encoded. */
export function secretUrl(path: string, name: string, env: string): string {
  const segments = [...cleanPath(path).split('/').filter(Boolean), name.trim()]
  const tail = segments.map(encodeURIComponent).join('/')
  return `${base}/secrets/${tail}?env=${encodeURIComponent(env.trim())}`
}

/** The body of a write, with the path in the stored form. */
export function draftBody(d: Draft): string {
  return JSON.stringify({
    path: cleanPath(d.path),
    name: d.name.trim(),
    env: d.env.trim(),
    value: d.value,
  })
}

/** What a refused response says: the problem detail, a message, else the status. */
export function failure(status: number, body: unknown): string {
  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>
    for (const key of ['detail', 'message', 'title']) {
      if (typeof b[key] === 'string' && b[key]) return b[key] as string
    }
  }
  if (typeof body === 'string' && body.trim()) return body.trim()
  return `HTTP ${status}`
}

/** Who a token names, for display. The server verifies it; this only reads it. */
export function subject(token: string | null): string {
  const payload = token?.split('.')[1]
  if (!payload) return ''
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    const claims = JSON.parse(json) as Record<string, unknown>
    for (const key of ['email', 'preferred_username', 'name', 'sub']) {
      if (typeof claims[key] === 'string' && claims[key]) return claims[key] as string
    }
  } catch {
    return ''
  }
  return ''
}
