// An external observation point, not a DNS writer. Its only outbound requests
// are to the statically configured gateway probes. Unknown/errors never vote.
const encoder = new TextEncoder();
const idPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const hostPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const noncePattern = /^[0-9a-f]{32}$/;

function equalSecret(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const a = encoder.encode(actual);
  const b = encoder.encode(expected);
  if (b.length < 32 || b.length > 256 || a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a[i] ^ b[i];
  return mismatch === 0;
}

function inventory(env) {
  const origins = JSON.parse(env.WITNESS_ORIGINS);
  if (!Array.isArray(origins) || origins.length < 1 || origins.length > 16) throw new Error('inventory');
  const ids = new Set(), hosts = new Set();
  for (const origin of origins) {
    if (!origin || Object.keys(origin).sort().join(',') !== 'host,id' ||
        !idPattern.test(origin.id) || !hostPattern.test(origin.host) ||
        ids.has(origin.id) || hosts.has(origin.host)) throw new Error('inventory');
    ids.add(origin.id); hosts.add(origin.host);
  }
  return origins;
}

async function boundedBody(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const parts = [];
  let size = 0;
  try {
    for (;;) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 256) return null;
      parts.push(value);
    }
    const joined = new Uint8Array(size);
    let offset = 0;
    for (const part of parts) { joined.set(part, offset); offset += part.byteLength; }
    return new TextDecoder('utf-8', {fatal: true}).decode(joined);
  } finally { await reader.cancel().catch(() => {}); }
}

export async function probe(origin, fetcher = fetch) {
  const path = '/healthz';
  try {
    const options = {redirect: 'manual', signal: AbortSignal.timeout(2500),
      headers: {'User-Agent': 'HeteroNetwork-DNS-Witness/1.0', 'Cache-Control': 'no-cache'}};
    const response = await fetcher(`https://${origin.host}${path}`, options);
    if (response.status !== 200) return {healthy: false, reason: 'http'};
    if (await boundedBody(response) !== 'HeteroNetwork public gateway ready\n')
      return {healthy: false, reason: 'body'};
    const redirect = await fetcher(`http://${origin.host}${path}`,
      {...options, signal: AbortSignal.timeout(2500)});
    if (![301, 302, 307, 308].includes(redirect.status) ||
        redirect.headers.get('Location') !== `https://${origin.host}${path}`)
      return {healthy: false, reason: 'http'};
    return {healthy: true, reason: 'ok'};
  } catch (error) {
    return {healthy: false, reason: error?.name === 'TimeoutError' || error?.name === 'AbortError' ? 'timeout' : 'network'};
  }
}

export async function handle(request, env, fetcher = fetch) {
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.pathname !== '/v1/probe') return new Response(null, {status: 404});
  const headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'};
  if (!equalSecret(request.headers.get('Authorization'), `Bearer ${env.WITNESS_TOKEN || ''}`))
    return new Response(null, {status: 401, headers});
  if ([...url.searchParams.keys()].join(',') !== 'nonce' || !noncePattern.test(url.searchParams.get('nonce') || ''))
    return new Response(null, {status: 400, headers});
  try {
    const origins = inventory(env);
    const results = await Promise.all(origins.map(origin => probe(origin, fetcher)));
    return new Response(JSON.stringify({schema_version: 1, nonce: url.searchParams.get('nonce'),
      origins: Object.fromEntries(origins.map((origin, index) => [origin.id, results[index]]))}), {headers});
  } catch {
    return new Response(null, {status: 503, headers});
  }
}

export default {fetch(request, env) { return handle(request, env); }};
