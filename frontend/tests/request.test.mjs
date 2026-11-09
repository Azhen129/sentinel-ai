import assert from 'node:assert/strict'
import test from 'node:test'
import { requestJson } from '../src/request.ts'

function hangingFetch(_url, options) {
  return new Promise((_resolve, reject) => {
    if (options.signal.aborted) reject(options.signal.reason)
    else options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true })
  })
}

test('a polling cancellation signal does not remove the deadline on a hanging fetch', async t => {
  t.mock.method(globalThis, 'fetch', hangingFetch)
  const caller = new AbortController()
  await assert.rejects(requestJson('http://127.0.0.1.invalid/api/overview', { signal: caller.signal }, 25), { name: 'TimeoutError' })
  assert.equal(caller.signal.aborted, false)
})

test('caller cancellation immediately aborts a pending request', async t => {
  t.mock.method(globalThis, 'fetch', hangingFetch)
  const caller = new AbortController()
  const request = requestJson('http://127.0.0.1.invalid/api/overview', { signal: caller.signal }, 10000)
  caller.abort(new DOMException('View changed', 'AbortError'))
  await assert.rejects(request, { name: 'AbortError', message: 'View changed' })
})

test('already cancelled requests preserve the caller reason', async t => {
  t.mock.method(globalThis, 'fetch', hangingFetch)
  const caller = new AbortController()
  caller.abort(new DOMException('Closed', 'AbortError'))
  await assert.rejects(requestJson('http://127.0.0.1.invalid/api/overview', { signal: caller.signal }), { name: 'AbortError', message: 'Closed' })
})

test('successful JSON and API error detail are retained with explicit Headers', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.get('X-Test-Key'), 'non-secret-fixture')
    assert.equal(options.headers.get('Content-Type'), 'application/json')
    return new Response(JSON.stringify({ items: [] }), { status: 200 })
  })
  assert.deepEqual(await requestJson('http://127.0.0.1.invalid/api/connections', { headers: new Headers({ 'X-Test-Key': 'non-secret-fixture' }) }), { items: [] })
  mock.mock.mockImplementation(async () => new Response(JSON.stringify({ detail: 'Read-only demonstration' }), { status: 403 }))
  await assert.rejects(requestJson('http://127.0.0.1.invalid/api/incidents/fixture'), /Read-only demonstration/)
})
