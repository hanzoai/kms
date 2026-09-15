// Sign-in is Hanzo IAM: authorization code with PKCE against the issuer the
// server names in /v1/kms/config, as the brand's `<org>-kms` client.

import { configureIam, getSession, handleCallback, logout, startLogin } from '@hanzo/iam/browser'
import { clientId, subject, type Config } from './kms'

export const callbackPath = '/auth/callback'

export function configure(config: Config): void {
  configureIam({
    issuer: config.issuer,
    clientId: clientId(config.brand),
    redirect: `${window.location.origin}${callbackPath}`,
  })
}

/** Finishes a sign-in that returned to the callback path and says where to go next. */
export async function finishSignIn(): Promise<string> {
  const { redirect } = await handleCallback()
  return redirect.startsWith('/') && !redirect.startsWith('//') ? redirect : '/'
}

export function signIn(): Promise<void> {
  const here = `${window.location.pathname}${window.location.search}`
  return startLogin({ redirect: here === callbackPath ? '/' : here })
}

export function signOut(): Promise<void> {
  return logout()
}

export function signedIn(): boolean {
  return getSession().authenticated
}

export function who(): string {
  return subject(getSession().accessToken)
}
