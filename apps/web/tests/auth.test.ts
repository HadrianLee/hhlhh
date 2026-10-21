import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import { ApiError, clearCsrf, get, getCsrf, mutate } from '../src/lib/api.ts'
import { captureLinkToken } from '../src/lib/link-token.ts'
import { newPassword } from '../src/lib/forms.ts'

const originalFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = originalFetch; clearCsrf() })

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

test('writes use anonymous CSRF, adopt login CSRF, and never expose bearer tokens', async () => {
  const calls: { path: string; init: RequestInit }[] = []
  globalThis.fetch = async (input, init = {}) => {
    const path = String(input)
    calls.push({ path, init })
    if (path.endsWith('/csrf')) return json({ csrf_token: 'anonymous' })
    if (path.endsWith('/login')) return json({ csrf_token: 'session' })
    return new Response(null, { status: 204 })
  }
  await mutate('/api/auth/login', { email: 'user@example.com', password: 'synthetic' })
  await mutate('/api/identity/users/me', { username: 'updated' }, 'PATCH')
  assert.deepEqual(calls.map((call) => call.path), ['/api/auth/csrf', '/api/auth/login', '/api/identity/users/me'])
  assert.equal(new Headers(calls[1].init.headers).get('X-CSRF-Token'), 'anonymous')
  assert.equal(new Headers(calls[2].init.headers).get('X-CSRF-Token'), 'session')
  for (const { init } of calls) {
    assert.equal(init.credentials, 'same-origin')
    assert.equal(init.cache, 'no-store')
    assert.equal(init.redirect, 'error')
    assert.equal(new Headers(init.headers).has('Authorization'), false)
  }
})

test('concurrent initial writes share a single CSRF request', async () => {
  let csrfRequests = 0
  globalThis.fetch = async (path) => {
    if (String(path).endsWith('/csrf')) { csrfRequests += 1; return json({ csrf_token: 'anonymous' }) }
    return new Response(null, { status: 204 })
  }
  await Promise.all([mutate('/api/auth/register', {}), mutate('/api/auth/password/forgot', {})])
  assert.equal(csrfRequests, 1)
})

test('passkey sign-in adopts the new session CSRF token before the next write', async () => {
  let csrf = ''
  globalThis.fetch = async (path, init) => {
    if (String(path).endsWith('/csrf')) return json({ csrf_token: 'anonymous' })
    if (String(path).endsWith('/passkey/login')) return json({ csrf_token: 'passkey-session' })
    csrf = new Headers(init?.headers).get('X-CSRF-Token') || ''
    return new Response(null, { status: 204 })
  }
  await mutate('/api/auth/passkey/login', {})
  await mutate('/api/identity/users/me', {}, 'PATCH')
  assert.equal(csrf, 'passkey-session')
})

test('403 never retries a mutation and the next explicit attempt obtains fresh CSRF', async () => {
  let writes = 0
  let csrfRequests = 0
  globalThis.fetch = async (path) => {
    if (String(path).endsWith('/csrf')) { csrfRequests += 1; return json({ csrf_token: 'fresh' }) }
    writes += 1
    return json({ detail: 'Complete a recent MFA challenge for this session' }, 403)
  }
  await assert.rejects(mutate('/api/identity/auth/password/change', {}), (error: ApiError) => error.status === 403)
  assert.equal(writes, 1)
  await getCsrf()
  assert.equal(csrfRequests, 2)
})

test('logout invalidates cached session CSRF', async () => {
  let csrfRequests = 0
  globalThis.fetch = async (path) => {
    if (String(path).endsWith('/csrf')) { csrfRequests += 1; return json({ csrf_token: 'token' }) }
    return new Response(null, { status: 204 })
  }
  await mutate('/api/auth/logout')
  await getCsrf()
  assert.equal(csrfRequests, 2)
})

test('authenticated 401 signals session expiry; a bad public verification token does not', async () => {
  let expired = 0
  const previous = globalThis.window
  Object.assign(globalThis, { window: { dispatchEvent: () => { expired += 1 } } })
  try {
    globalThis.fetch = async (path) => String(path).endsWith('/csrf') ? json({ csrf_token: 'token' }) : json({ detail: 'Invalid token' }, 401)
    await assert.rejects(mutate('/api/auth/email/verification/confirm', { token: 'bad' }), ApiError)
    assert.equal(expired, 0)
    await assert.rejects(get('/api/identity/users/me'), ApiError)
    assert.equal(expired, 1)
  } finally { Object.assign(globalThis, { window: previous }) }
})

test('verification and reset fragments are decoded, removed from history, and bounded', () => {
  for (const pathname of ['/verify-email', '/reset-password']) {
    let cleaned = ''
    const result = captureLinkToken({ pathname, search: '', hash: '#token=primary.a%2Bb%26c' }, {
      state: { preserved: true },
      replaceState(state, _unused, url) { assert.deepEqual(state, { preserved: true }); cleaned = String(url) },
    })
    assert.deepEqual(result, { path: pathname, token: 'primary.a+b&c' })
    assert.equal(cleaned, pathname)
  }
  assert.equal(captureLinkToken({ pathname: '/verify-email', search: '', hash: '#token=' + 'x'.repeat(513) }, { state: null, replaceState() {} }), null)
  assert.equal(captureLinkToken({ pathname: '/login', search: '', hash: '#token=secret' }, { state: null, replaceState() { assert.fail('Unrelated fragment must not be removed') } }), null)
})

test('new passwords require eight characters and confirmation without composition rules', () => {
  function password(value: string, confirmation = value) {
    const data = new FormData()
    data.set('password', value)
    data.set('confirm_password', confirmation)
    return () => newPassword(data)
  }
  for (const value of ['password', '12345678', 'with spaces', '😀'.repeat(8), 'x'.repeat(200), 'Local\tTesting123!']) assert.equal(password(value)(), value)
  for (const value of ['', 'short', '1234567', '😀'.repeat(7)]) assert.throws(password(value), /at least 8/)
  assert.throws(password('LocalTestingPassword123!', 'OtherPassword123!'), /do not match/)
})
