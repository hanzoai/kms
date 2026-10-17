import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import { back, cleanPath, clientId, draftBody, failure, home, listUrl, secretUrl, signinAddress, subject } from './kms.ts'

describe('addresses', () => {
  it('names the IAM client <org>-kms', () => {
    assert.equal(clientId('hanzo'), 'hanzo-kms')
  })

  it('stores paths as /a/b, with the org root empty', () => {
    assert.equal(cleanPath(''), '')
    assert.equal(cleanPath('/'), '')
    assert.equal(cleanPath('ci'), '/ci')
    assert.equal(cleanPath(' /ci//deploy/ '), '/ci/deploy')
  })

  it('lists the whole org when no filter is given', () => {
    assert.equal(listUrl('', ''), '/v1/kms/secrets')
    assert.equal(listUrl('ci', ' prod '), '/v1/kms/secrets?path=%2Fci&env=prod')
  })

  it('addresses one secret by path segments and name, never by org', () => {
    assert.equal(secretUrl('', 'TOKEN', 'prod'), '/v1/kms/secrets/TOKEN?env=prod')
    assert.equal(secretUrl('/ci/deploy', 'NPM TOKEN', 'dev'), '/v1/kms/secrets/ci/deploy/NPM%20TOKEN?env=dev')
    assert.ok(!secretUrl('/ci', 'X', 'prod').includes('/orgs/'))
  })

  it('writes the path in stored form and keeps the value as typed', () => {
    assert.deepEqual(JSON.parse(draftBody({ path: 'ci/', name: ' A ', env: ' prod', value: ' v ' })), {
      path: '/ci',
      name: 'A',
      env: 'prod',
      value: ' v ',
    })
  })
})

describe('responses', () => {
  it('reads the problem detail first', () => {
    assert.equal(failure(403, { title: 'Forbidden', detail: 'authentication required' }), 'authentication required')
    assert.equal(failure(502, { message: 'kms login failed' }), 'kms login failed')
    assert.equal(failure(404, 'not found\n'), 'not found')
    assert.equal(failure(500, null), 'HTTP 500')
  })

  it('names the signed-in subject from the token payload', () => {
    const payload = btoa(JSON.stringify({ sub: 'u1', email: 'z@hanzo.ai' })).replace(/=+$/, '')
    assert.equal(subject(`h.${payload}.s`), 'z@hanzo.ai')
    assert.equal(subject(null), '')
    assert.equal(subject('not-a-jwt'), '')
  })
})

describe('sign-in', () => {
  it('signs Hanzo in on hanzo.ai and reads IAM at the API, never hanzo.id', () => {
    assert.deepEqual(home('hanzo'), { signin: 'https://hanzo.ai/login', api: 'https://api.hanzo.ai' })
    assert.ok(!JSON.stringify(home('hanzo')).includes('hanzo.id'))
  })

  it('leaves every other brand at its own issuer', () => {
    assert.equal(home('lux'), null)
    assert.equal(home('zoo'), null)
    assert.equal(home('constructor'), null)
    assert.equal(home('__proto__'), null)
  })

  it("carries the console's own authorize query whole to the sign-in page", () => {
    const authorize =
      'https://hanzo.id/v1/iam/oauth/authorize?client_id=hanzo-kms&redirect_uri=https%3A%2F%2Fkms.hanzo.ai%2Fauth%2Fcallback&response_type=code&scope=openid+profile+email&state=S&code_challenge=C&code_challenge_method=S256'
    const to = new URL(signinAddress('https://hanzo.ai/login', authorize))
    assert.equal(to.origin + to.pathname, 'https://hanzo.ai/login')
    assert.equal(to.searchParams.get('client_id'), 'hanzo-kms')
    assert.equal(to.searchParams.get('redirect_uri'), 'https://kms.hanzo.ai/auth/callback')
    assert.equal(to.searchParams.get('code_challenge'), 'C')
    assert.equal(to.searchParams.get('code_challenge_method'), 'S256')
    assert.equal(to.searchParams.get('state'), 'S')
    assert.equal(signinAddress(null, authorize), authorize)
  })

  it('comes back only to a path on this origin', () => {
    assert.equal(back('/status?x=1'), '/status?x=1')
    assert.equal(back(null), '/')
    for (const bad of ['https://evil.example/', '//evil.example/x', '/\\evil.example/x', '/\t/evil.example/x', 'status']) {
      assert.equal(back(bad), '/', bad)
    }
  })
})
