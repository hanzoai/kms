import { useEffect, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, Route, Switch, useLocation } from 'wouter'
import { fetchConfig } from '@/lib/api'
import type { Config } from '@/lib/kms'
import { callbackPath, configure, finishSignIn, signIn, signOut, signedIn, who } from '@/lib/session'
import { Shell } from '@/components/Shell'
import { Button, Card, Notice } from '@/components/ui'
import { SecretsPage } from '@/pages/Secrets'
import { StatusPage } from '@/pages/Status'

// The console loads its configuration, finishes a sign-in that returned to the
// callback path, and shows either the sign-in screen or the pages.

export function App() {
  const config = useQuery({ queryKey: ['config'], queryFn: fetchConfig, staleTime: Infinity })
  if (config.isPending) return <Centered>Loading</Centered>
  if (config.isError) {
    return (
      <Centered>
        <Notice>{config.error.message}</Notice>
      </Centered>
    )
  }
  return <Console config={config.data} />
}

function Console({ config }: { config: Config }) {
  const [, navigate] = useLocation()
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const product = `${config.brand.charAt(0).toUpperCase()}${config.brand.slice(1)} KMS`

  useEffect(() => {
    document.title = product
    configure(config)
    if (window.location.pathname !== callbackPath) {
      setReady(true)
      return
    }
    finishSignIn()
      .then((to) => navigate(to, { replace: true }))
      .catch((e: Error) => {
        setError(e.message)
        navigate('/', { replace: true })
      })
      .finally(() => setReady(true))
  }, [config])

  if (!ready) return <Centered>Signing in</Centered>
  if (!signedIn()) return <SignIn product={product} issuer={config.issuer} error={error} />

  return (
    <Shell product={product} user={who()} onSignOut={() => void signOut()}>
      <Switch>
        <Route path="/">
          <SecretsPage />
        </Route>
        <Route path="/status">
          <StatusPage config={config} />
        </Route>
        <Route>
          <div className="p-6 text-[13px] text-neutral-400">
            No page here. <Link href="/" className="text-neutral-100 underline">Go to secrets</Link>
          </div>
        </Route>
      </Switch>
    </Shell>
  )
}

function SignIn({ product, issuer, error }: { product: string; issuer: string; error: string | null }) {
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState<string | null>(null)
  const host = issuer.replace(/^https?:\/\//, '')

  function start() {
    setBusy(true)
    setFailed(null)
    signIn().catch((e: Error) => {
      setFailed(e.message)
      setBusy(false)
    })
  }

  return (
    <Centered>
      <Card className="w-full max-w-sm p-6">
        <div className="mb-5 flex items-center gap-2">
          <img src="/favicon.svg" alt="" className="h-7 w-7" />
          <div className="text-base font-semibold text-neutral-50">{product}</div>
        </div>
        <p className="mb-5 text-[13px] text-neutral-400">
          Your organization's secrets, sealed at rest. Sign in with your account at {host} to see them.
        </p>
        {(error || failed) && (
          <div className="mb-4">
            <Notice>{failed ?? error}</Notice>
          </div>
        )}
        <Button variant="primary" className="w-full" onClick={start} disabled={busy}>
          {busy ? 'Opening sign-in' : `Sign in with ${host}`}
        </Button>
      </Card>
    </Centered>
  )
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-black p-6 text-[13px] text-neutral-400">
      {children}
    </div>
  )
}
