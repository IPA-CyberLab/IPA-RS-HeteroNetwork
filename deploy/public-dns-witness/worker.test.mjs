import test from 'node:test';
import assert from 'node:assert/strict';
import {handle, probe} from './worker.mjs';

const origin = {id: 'one', host: 'probe.example.net'};
const secret = '0123456789abcdef0123456789abcdef';
const nonce = '1234567890abcdef1234567890abcdef';
const env = {WITNESS_TOKEN: secret, WITNESS_ORIGINS: JSON.stringify([origin])};
function request(token = secret, query = `nonce=${nonce}`) {
  return new Request(`https://example.workers.dev/v1/probe?${query}`,
    {headers: {Authorization: `Bearer ${token}`}});
}
function successful(url) {
  return Promise.resolve(url.startsWith('https:')
    ? new Response('HeteroNetwork public gateway ready\n')
    : new Response(null, {status: 308, headers: {Location: 'https://probe.example.net/healthz'}}));
}

test('returns a nonce-bound fresh observation without cache', async () => {
  const result = await handle(request(), env, successful);
  assert.equal(result.status, 200);
  assert.equal(result.headers.get('Cache-Control'), 'no-store');
  assert.deepEqual(await result.json(), {schema_version: 1, nonce,
    origins: {one: {healthy: true, reason: 'ok'}}});
});
test('does not probe without the shared secret or a fresh nonce', async () => {
  let calls = 0;
  const fake = () => { calls++; throw new Error('should not fetch'); };
  assert.equal((await handle(request('incorrect'), env, fake)).status, 401);
  assert.equal((await handle(request(secret, 'nonce=x'), env, fake)).status, 400);
  assert.equal((await handle(request(secret, `nonce=${nonce}&nonce=${nonce}`), env, fake)).status, 400);
  assert.equal(calls, 0);
});
test('treats network failure, incorrect response and redirects as unhealthy', async () => {
  assert.deepEqual(await probe(origin, () => Promise.reject(new Error('offline'))),
    {healthy: false, reason: 'network'});
  assert.deepEqual(await probe(origin, () => Promise.resolve(new Response('wrong'))),
    {healthy: false, reason: 'body'});
  assert.deepEqual(await probe(origin, url => Promise.resolve(url.startsWith('https:')
    ? new Response('HeteroNetwork public gateway ready\n')
    : new Response(null, {status: 308, headers: {Location: 'https://other.example/'}}))),
    {healthy: false, reason: 'http'});
});
test('rejects oversized responses and untrusted inventory', async () => {
  assert.deepEqual(await probe(origin, () => Promise.resolve(new Response('x'.repeat(257)))),
    {healthy: false, reason: 'body'});
  assert.equal((await handle(request(), {...env, WITNESS_ORIGINS: '[{"id":"x","host":"127.0.0.1"}]'}, successful)).status, 503);
});
