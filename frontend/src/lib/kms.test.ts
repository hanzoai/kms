import { strict as assert } from 'node:assert'
import { describe, it } from 'node:test'
import { cleanPath, clientId, draftBody, failure, listUrl, secretUrl, subject } from './kms.ts'

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
