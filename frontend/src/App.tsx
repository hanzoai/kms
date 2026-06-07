import { useEffect, useState } from 'react'
import { Router, Route, Switch } from 'wouter'
import { useHashLocation } from 'wouter/use-hash-location'
import { decodeToken, getOrg, getToken, setOrg, setToken } from '@/lib/api'
import { AdminShell, type NavSection } from '@/components/AdminShell'
import { Badge, Button } from '@/components/Button'
import { LoginPage } from '@/pages/Login'
import { SecretsPage } from '@/pages/Secrets'
import { KeysPage } from '@/pages/Keys'
import { AuditPage } from '@/pages/Audit'
import { StatusPage } from '@/pages/Status'
import { EndpointGap } from '@/pages/EndpointGap'

const sections: NavSection[] = [
  {
    title: 'Secrets',
    items: [{ href: '/', label: 'Browser' }],
  },
  {
    title: 'Cryptography',
    items: [
      { href: '/keys', label: 'MPC keys' },
      { href: '/certificates', label: 'Certificates' },
    ],
  },
  {
    title: 'Identity',
    items: [
      { href: '/identities', label: 'Identities' },
      { href: '/projects', label: 'Projects' },
      { href: '/workspaces', label: 'Workspaces' },
      { href: '/integrations', label: 'Integrations' },
    ],
  },
  {
    title: 'Observability',
    items: [
      { href: '/audit', label: 'Audit' },
      { href: '/status', label: 'Status' },
    ],
  },
]

export function App() {
  // Force a re-render after sign-in/sign-out so AdminShell flips on the
  // token presence. The hash router handles the deep links itself.
  const [, setTick] = useState(0)
  const refresh = () => setTick((v) => v + 1)

  const token = getToken()
  const claims = decodeToken(token)

  useEffect(() => {
    // Auto sign-out when the cached token is expired. The server would
    // reject the next request anyway; this just bounces faster.
    if (claims?.exp && claims.exp * 1000 < Date.now()) {
      setToken(null)
      refresh()
    }
  }, [claims?.exp])

  if (!token) {
    return <LoginPage onSuccess={refresh} />
  }

  return (
    <Router hook={useHashLocation}>
      <AdminShell
        sections={sections}
        title="Hanzo KMS"
        topRight={<TopRight subject={claims?.sub} onSignOut={refresh} />}
      >
        <Switch>
          <Route path="/" component={SecretsPage} />
          <Route path="/keys" component={KeysPage} />
          <Route path="/audit" component={AuditPage} />
          <Route path="/status" component={StatusPage} />
          <Route path="/certificates">
            <EndpointGap
              title="Certificates"
              description="X.509 issuance, sync, lifecycle alerts."
              endpoints={[
                'GET /v1/kms/orgs/{org}/certs',
                'POST /v1/kms/orgs/{org}/certs',
                'GET /v1/kms/orgs/{org}/certs/{id}',
              ]}
              rationale="kmsd serves the ZAP-encoded certificate primitives via the in-process server, but the HTTP surface has not been wired yet. Read-only view ships first; CA issuance follows once the storage shape lands."
            />
          </Route>
          <Route path="/identities">
            <EndpointGap
              title="Identities"
              description="Universal Auth machine identities — clientId/clientSecret pairs that exchange for IAM access tokens."
              endpoints={[
                'POST /v1/iam/users/identities (managed via IAM)',
                'GET /v1/iam/users/identities',
              ]}
              rationale="Machine identities live in Hanzo IAM, not in kmsd. Use the IAM admin UI to mint and revoke clients; KMS only enforces the issued tokens."
            />
          </Route>
          <Route path="/projects">
            <EndpointGap
              title="Projects"
              description="Project / namespace organisation for secrets."
              endpoints={[
                'GET /v1/kms/orgs/{org}/projects',
                'POST /v1/kms/orgs/{org}/projects',
              ]}
              rationale="The current secrets API is path-addressed (the path itself is the namespace). A formal projects resource is on the HIP-0027 roadmap; for now, treat the first segment of the secret path as the project."
            />
          </Route>
          <Route path="/workspaces">
            <EndpointGap
              title="Workspaces"
              description="Per-environment workspace shape (legacy Infisical terminology)."
              endpoints={['GET /v1/kms/orgs/{org}/workspaces']}
              rationale="Workspaces are not a first-class concept on the canonical surface — environments are passed per-secret via ?env=. Kept here for migration tooling that maps legacy workspace IDs."
            />
          </Route>
          <Route path="/integrations">
            <EndpointGap
              title="Integrations"
              description="Secret syncs to GitHub, Vercel, AWS, Terraform, etc."
              endpoints={['GET /v1/kms/orgs/{org}/integrations']}
              rationale="Integrations are operator-side jobs that read from KMS via the kmsclient. They are not modelled on the kmsd HTTP surface — register them through the platform operator's CRDs."
            />
          </Route>
        </Switch>
      </AdminShell>
    </Router>
  )
}

function TopRight({ subject, onSignOut }: { subject?: string; onSignOut: () => void }) {
  const org = getOrg()
  return (
    <div className="flex items-center gap-3">
      <div className="flex items-center gap-2 text-[12px]">
        <span className="text-neutral-500">org</span>
        <OrgSwitcher
          value={org}
          onChange={(v) => {
            setOrg(v)
            window.location.reload()
          }}
        />
      </div>
      {subject && (
        <div className="flex items-center gap-2 text-[12px]">
          <span className="text-neutral-500">subject</span>
          <Badge>{subject}</Badge>
        </div>
      )}
      <Button
        variant="ghost"
        onClick={() => {
          setToken(null)
          onSignOut()
        }}
      >
        Sign out
      </Button>
    </div>
  )
}

function OrgSwitcher({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-28 rounded-md border border-neutral-800 bg-neutral-950 px-2 py-1 font-mono text-[12px] text-neutral-100 focus:border-[color:var(--color-brand)] focus:outline-none"
    />
  )
}
