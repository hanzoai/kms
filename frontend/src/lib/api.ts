// One way to talk to /v1/kms: same origin, with the signed-in session's bearer.

import { getSession } from '@hanzo/iam/browser'
import {
  base,
  draftBody,
  failure,
  listUrl,
  secretUrl,
  type Config,
  type Draft,
  type Health,
  type Listing,
  type Opened,
  type SecretMeta,
} from './kms'

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function send(url: string, init: RequestInit = {}): Promise<{ status: number; body: unknown }> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body) headers.set('Content-Type', 'application/json')
  const token = getSession().accessToken
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const res = await fetch(url, { ...init, headers })
  const text = await res.text()
  let body: unknown = text
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    // A body that is not JSON is carried as text.
  }
  return { status: res.status, body }
}

async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const { status, body } = await send(url, init)
  if (status < 200 || status > 299) throw new ApiError(status, failure(status, body))
  return body as T
}

/** Public, fetched before sign-in, so it carries no bearer. */
export async function fetchConfig(): Promise<Config> {
  const res = await fetch(`${base}/config`, { headers: { Accept: 'application/json' } })
  const body: unknown = await res.json().catch(() => null)
  if (!res.ok) throw new ApiError(res.status, failure(res.status, body))
  return body as Config
}

/** Readiness answers 503 with the same body when it is not ready, so both are data. */
export async function fetchHealth(): Promise<Health> {
  const { status, body } = await send(`${base}/health`)
  if (status === 200 || status === 503) return body as Health
  throw new ApiError(status, failure(status, body))
}

export function listSecrets(path: string, env: string): Promise<Listing> {
  return call<Listing>(listUrl(path, env))
}

export function openSecret(s: SecretMeta): Promise<Opened> {
  return call<Opened>(secretUrl(s.path, s.name, s.env))
}

export function putSecret(d: Draft): Promise<unknown> {
  return call(`${base}/secrets`, { method: 'POST', body: draftBody(d) })
}

export function deleteSecret(s: SecretMeta): Promise<unknown> {
  return call(secretUrl(s.path, s.name, s.env), { method: 'DELETE' })
}
