// Sign-in is Hanzo IAM: authorization code with PKCE, as the brand's `<org>-kms`
// client. The SDK mints this console's own request (its client, its /auth/callback, an
// S256 challenge whose verifier stays on this origin) and the browser takes it to the
// brand's sign-in page: hanzo.ai/login for Hanzo, which finishes it and sends the code
// back here. The callback redeems it on this origin's /v1/iam, which the host routes to
// cloud; discovery is read from the brand's API. A brand without a sign-in page goes to
// its issuer, as /v1/kms/config names it.

import { configureIam, getIam, getLoginUrl, getSession, handleCallback } from '@hanzo/iam/browser'
import { back, clientId, home, signinAddress, subject, type Config } from './kms'

export const callbackPath = '/auth/callback'

/** Where the page a sign-in started from waits for the callback. */
const RETURN_KEY = 'hanzo_kms_return'

let page: string | null = null

export function configure(config: Config): void {
  const h = home(config.brand)
  page = h?.signin ?? null
  configureIam({
    issuer: h?.api ?? config.issuer,
    clientId: clientId(config.brand),
    redirect: `${window.location.origin}${callbackPath}`,
    ...(h ? { proxyBaseUrl: window.location.origin } : {}),
  })
}

/** Finishes a sign-in that returned to the callback path and says where to go next. */
export async function finishSignIn(): Promise<string> {
  await handleCallback()
  let to: string | null = null
  try {
    to = sessionStorage.getItem(RETURN_KEY)
    sessionStorage.removeItem(RETURN_KEY)
  } catch {
    // Private mode: the console's home.
  }
  return back(to)
}

/** Leaves for sign-in with this console's own request, to come back to this page. */
export async function signIn(): Promise<void> {
  const here = `${window.location.pathname}${window.location.search}`
  try {
    sessionStorage.setItem(RETURN_KEY, back(here === callbackPath ? '/' : here))
  } catch {
    // Private mode: the callback lands on the home.
  }
  window.location.replace(signinAddress(page, await getLoginUrl()))
}

/** Hands both tokens back and ends the session on this origin, then starts over here. */
export async function signOut(): Promise<void> {
  await getIam().end()
  window.location.replace('/')
}

export function signedIn(): boolean {
  return getSession().authenticated
}

export function who(): string {
  return subject(getSession().accessToken)
}
