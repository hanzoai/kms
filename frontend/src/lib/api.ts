// Thin fetch wrapper for /v1/kms/*. One way to talk to the KMS API.
//
// Auth: bearer token persisted in localStorage under KMS_TOKEN. The
// /v1/kms/auth/login endpoint exchanges clientId + clientSecret for the
// IAM access token; everything else carries that token as
// `Authorization: Bearer <jwt>`. No cookies, no CSRF — purely
// JWT-in-localStorage. The token lives in the operator's browser tab;
// signing out clears it.

const TOKEN_KEY = 'KMS_TOKEN'
const ORG_KEY = 'KMS_ORG'

export function getToken(): string | null {
  return window.localStorage.getItem(TOKEN_KEY)
}

export function setToken(value: string | null): void {
  if (value) window.localStorage.setItem(TOKEN_KEY, value)
  else window.localStorage.removeItem(TOKEN_KEY)
}

export function getOrg(): string {
  return window.localStorage.getItem(ORG_KEY) || 'hanzo'
}

export function setOrg(value: string): void {
  window.localStorage.setItem(ORG_KEY, value)
}

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.status = status
    this.body = body
    this.name = 'ApiError'
  }
}

interface ApiOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
  headers?: Record<string, string>
  signal?: AbortSignal
}

export async function api<T>(path: string, opts: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
    ...opts.headers,
  }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  let body: BodyInit | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }
  const res = await fetch(path, {
    method: opts.method || 'GET',
    headers,
    body,
    signal: opts.signal,
  })
  const text = await res.text()
  let parsed: unknown
  try {
    parsed = text ? JSON.parse(text) : null
  } catch {
    parsed = text
  }
  if (!res.ok) {
    const msg =
      (parsed && typeof parsed === 'object' && 'message' in parsed
        ? String((parsed as Record<string, unknown>).message)
        : null) || res.statusText || `HTTP ${res.status}`
    throw new ApiError(res.status, msg, parsed)
  }
  return parsed as T
}

// --- Typed endpoints --------------------------------------------------

export interface LoginResponse {
  accessToken: string
  expiresIn: number
  tokenType: string
}

export async function login(clientId: string, clientSecret: string): Promise<LoginResponse> {
  return api<LoginResponse>('/v1/kms/auth/login', {
    method: 'POST',
    body: { clientId, clientSecret },
  })
}

export interface HealthResponse {
  status: string
  service: string
  version: string
}

export function fetchHealth(): Promise<HealthResponse> {
  return api<HealthResponse>('/v1/kms/health')
}

// --- Secrets ----------------------------------------------------------

export interface SecretValue {
  secret: { value: string }
  version: number
}

export function getSecret(
  org: string,
  path: string,
  name: string,
  env: string,
): Promise<SecretValue> {
  const u = secretUrl(org, path, name, env)
  return api<SecretValue>(u)
}

export interface PutSecretBody {
  path: string
  name: string
  env: string
  value: string
}

export function putSecret(
  org: string,
  body: PutSecretBody,
): Promise<{ ok: boolean; version: number }> {
  return api(`/v1/kms/orgs/${encodeURIComponent(org)}/secrets`, {
    method: 'POST',
    body,
  })
}

export interface PatchSecretBody {
  value: string
  version: number
  env?: string
}

export function patchSecret(
  org: string,
  path: string,
  name: string,
  body: PatchSecretBody,
): Promise<{ ok: boolean; version: number }> {
  const u = `/v1/kms/orgs/${encodeURIComponent(org)}/secrets/${encodePath(path, name)}`
  return api(u, {
    method: 'PATCH',
    body,
    headers: { 'If-Match': String(body.version) },
  })
}

export function deleteSecret(
  org: string,
  path: string,
  name: string,
  env: string,
): Promise<{ ok: boolean }> {
  const u = secretUrl(org, path, name, env)
  return api(u, { method: 'DELETE' })
}

function secretUrl(org: string, path: string, name: string, env: string): string {
  const qs = env ? `?env=${encodeURIComponent(env)}` : ''
  return `/v1/kms/orgs/${encodeURIComponent(org)}/secrets/${encodePath(path, name)}${qs}`
}

function encodePath(p: string, name: string): string {
  // /a/b/c + name → "a/b/c/name" with each segment encoded. Strip
  // leading/trailing slashes and empty segments so user input is
  // tolerated.
  const parts = `${p}/${name}`.split('/').filter(Boolean)
  return parts.map(encodeURIComponent).join('/')
}

// --- MPC keys ---------------------------------------------------------

export interface ValidatorKeySet {
  id: string
  validator_id?: string
  threshold?: number
  parties?: number
  bls_public_key?: string
  ringtail_public_key?: string
  created_at?: string
  [key: string]: unknown
}

export function listKeys(): Promise<ValidatorKeySet[]> {
  return api<ValidatorKeySet[]>('/v1/kms/keys')
}

export function getKey(id: string): Promise<ValidatorKeySet> {
  return api<ValidatorKeySet>(`/v1/kms/keys/${encodeURIComponent(id)}`)
}

export interface KMSStatus {
  kms: string
  mpc: unknown
  details?: string
}

export function fetchStatus(): Promise<KMSStatus> {
  return api<KMSStatus>('/v1/kms/status')
}

export interface AuditStats {
  written: number
  dropped: number
}

export function fetchAuditStats(): Promise<AuditStats> {
  return api<AuditStats>('/v1/kms/audit/stats')
}

// --- Token claim helpers (no signature verify; UI hint only) ----------

export interface TokenClaims {
  sub?: string
  owner?: string
  iss?: string
  aud?: string | string[]
  exp?: number
  roles?: string[]
  email?: string
}

export function decodeToken(token: string | null): TokenClaims | null {
  if (!token) return null
  const parts = token.split('.')
  if (parts.length < 2) return null
  try {
    const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))
    return JSON.parse(json)
  } catch {
    return null
  }
}
