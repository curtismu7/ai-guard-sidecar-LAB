import assert from 'node:assert/strict';
import http from 'node:http';
import { test } from 'node:test';
import express from 'express';
import { assertBindAllowed, assertSidecarUrl, credentialGuard, hostGuard, isLoopbackHost, originGuard, parseHost, portInRange } from '../src/safety.js';
import net from 'node:net';
import { startHttpServer } from '../src/app.js';
import { freeBase, request } from './helpers.js';

test('loopback hosts', () => {
  for (const h of ['localhost', '127.0.0.1', '127.9.9.9', '::1', '[::1]']) assert.ok(isLoopbackHost(h), h);
  for (const h of ['example.com', '10.0.0.1', '0.0.0.0', '127.0.0.1.evil.com', '128.0.0.1']) assert.ok(!isLoopbackHost(h), h);
});

test('parseHost is strict', () => {
  assert.equal(parseHost('127.0.0.1:6500').port, 6500);
  assert.equal(parseHost('LOCALHOST').hostname, 'localhost');
  for (const h of ['evil.com', '127.0.0.1.evil.com:6500', '127.0.0.1:99999', '', undefined, 'localhost@evil.com', '127.0.0.1:6500/x']) assert.equal(parseHost(h), null, String(h));
});

test('port range is 6500-6549', () => {
  assert.ok(portInRange(6500) && portInRange(6549));
  for (const p of [6499, 6550, 8086, 5173, NaN, 6500.5]) assert.ok(!portInRange(p), String(p));
});

test('bind: loopback only unless AI_GUARD_BIND opts in', () => {
  assert.equal(assertBindAllowed('127.0.0.1', {}), '127.0.0.1');
  assert.throws(() => assertBindAllowed('0.0.0.0', {}), /loopback only/);
  assert.equal(assertBindAllowed('0.0.0.0', { AI_GUARD_BIND: '0.0.0.0' }), '0.0.0.0');
});

test('the gateway may only call an http loopback sidecar inside the port range', () => {
  assert.equal(assertSidecarUrl('http://127.0.0.1:6501'), 'http://127.0.0.1:6501');
  for (const u of ['http://example.com:6501', 'https://127.0.0.1:6501', 'http://127.0.0.1:8086', 'http://127.0.0.1', 'http://user:pw@127.0.0.1:6501', 'nonsense', 'http://10.0.0.5:6501']) assert.throws(() => assertSidecarUrl(u), undefined, u);
});

async function guarded() {
  const app = express();
  app.use(hostGuard); app.use(originGuard); app.use(credentialGuard); app.use(express.json());
  app.get('/x', (_q, r) => r.json({ ok: 1 }));
  app.post('/x', (_q, r) => r.json({ ok: 1 }));
  const port = await freeBase('safety');
  const server = await new Promise((r) => { const s = app.listen(port, '127.0.0.1', () => r(s)); });
  return { port, close: () => new Promise((r) => server.close(r)) };
}

test('guards: Host (DNS rebinding), cross-site, Origin, content type, credentials', async () => {
  const g = await guarded();
  try {
    assert.equal((await request(g.port, 'GET', '/x')).status, 200);
    assert.equal((await request(g.port, 'GET', '/x', { host: 'evil.example' })).status, 421);
    assert.equal((await request(g.port, 'POST', '/x', { body: {}, headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
    assert.equal((await request(g.port, 'POST', '/x', { body: {}, headers: { origin: 'http://evil.example' } })).status, 403);
    assert.equal((await request(g.port, 'POST', '/x', { body: {}, headers: { origin: `http://127.0.0.1:${g.port + 1}` } })).status, 403, 'different port is a different origin');
    assert.equal((await request(g.port, 'POST', '/x', { body: {}, headers: { origin: `http://127.0.0.1:${g.port}` } })).status, 200);
    assert.equal((await request(g.port, 'POST', '/x', { body: 'a=b', headers: { 'content-type': 'text/plain' } })).status, 415);
    assert.equal((await request(g.port, 'GET', '/x', { headers: { authorization: 'Bearer abcdef' } })).status, 400);
    assert.equal((await request(g.port, 'GET', '/x', { headers: { 'x-api-key': 'k' } })).status, 400);
  } finally { await g.close(); }
});

test('guards: the Origin must be exactly the canonical http origin (not https, not a differently written scheme)', async () => {
  const g = await guarded();
  try {
    const post = (origin) => request(g.port, 'POST', '/x', { body: {}, headers: { origin } });
    assert.equal((await post(`http://127.0.0.1:${g.port}`)).status, 200);
    assert.equal((await post(`https://127.0.0.1:${g.port}`)).status, 403, 'https is a different origin');
    assert.equal((await post(`HTTP://127.0.0.1:${g.port}`)).status, 403, 'not the canonical spelling');
    assert.equal((await post(`http://127.0.0.1:${g.port}/`)).status, 403, 'an origin has no path');
    assert.equal((await post('null')).status, 403);
  } finally { await g.close(); }
});

const canBind = (port) => new Promise((resolve) => { const s = net.createServer(); s.once('error', () => resolve(false)); s.listen(port, '127.0.0.1', () => s.close(() => resolve(true))); });
const PROXY_HOST = 'ai-guard-sidecar.local.ping-devops.com';

test('LAB_ALLOWED_HOSTS: the lab-proxy name is served on any port, other names stay 421, a bad name refuses to start and leaves nothing running', async () => {
  const base = await freeBase('safety', 2);
  const srv = await startHttpServer({ port: base, embeddedPort: base + 1, env: { LAB_ALLOWED_HOSTS: `${PROXY_HOST}, Other.Example` }, webDist: null });
  try {
    for (const host of [`${PROXY_HOST}:6500`, PROXY_HOST, 'AI-Guard-Sidecar.Local.Ping-Devops.com:8443', 'other.example', 'OTHER.example:8443', `127.0.0.1:${base}`]) {
      assert.equal((await request(base, 'GET', '/api/health', { host })).status, 200, host);
    }
    for (const host of ['evil.example.com', `${PROXY_HOST}.evil.com`, 'xai-guard-sidecar.local.ping-devops.example', 'local.ping-devops.com:8443', 'ping-devops.com']) {
      assert.equal((await request(base, 'GET', '/api/health', { host })).status, 421, host);
    }
  } finally { await srv.close(); }
  const b2 = await freeBase('safety', 2);
  await assert.rejects(startHttpServer({ port: b2, embeddedPort: b2 + 1, env: { LAB_ALLOWED_HOSTS: 'not a host name' }, webDist: null }), /LAB_ALLOWED_HOSTS: not a host name: not a host name/);
  await assert.rejects(startHttpServer({ port: b2, embeddedPort: b2 + 1, env: { MODE: 'se-mock', LAB_ALLOWED_HOSTS: 'a.example,-bad-' }, webDist: null }), /LAB_ALLOWED_HOSTS: not a host name: -bad-/);
  assert.equal(await canBind(b2), true, 'no server left on the main port');
  assert.equal(await canBind(b2 + 1), true, 'no embedded sidecar left running');
  // unset: the default stays loopback only
  const plain = await startHttpServer({ port: b2, embeddedPort: b2 + 1, env: {}, webDist: null });
  try {
    assert.equal((await request(b2, 'GET', '/api/health', { host: `${PROXY_HOST}:6500` })).status, 421);
    assert.equal((await request(b2, 'GET', '/api/health', { host: `127.0.0.1:${b2}` })).status, 200);
  } finally { await plain.close(); }
});

test('behind the lab-proxy: a write is accepted only with the proxy\'s forwarded origin AND an allowed Host; AI_GUARD_PUBLIC_ORIGIN still works', async () => {
  const base = await freeBase('safety', 2);
  const pub = 'https://guard.demo.example';
  const srv = await startHttpServer({ port: base, embeddedPort: base + 1, env: { MODE: 'se-mock', LAB_ALLOWED_HOSTS: PROXY_HOST, AI_GUARD_PUBLIC_ORIGIN: pub }, webDist: null });
  try {
    const proxyHost = `${PROXY_HOST}:6500`;
    const fwd = { 'x-forwarded-host': 'local.ping-devops.com:8443', 'x-forwarded-proto': 'https' };
    const body = { mode: 'none', delayMs: 0 };
    const via = (headers, host = proxyHost) => request(base, 'PUT', '/api/fault', { host, body, headers });
    // what the browser and the proxy really send for a same-origin write
    assert.equal((await via({ ...fwd, origin: 'https://local.ping-devops.com:8443', 'sec-fetch-site': 'same-origin' })).status, 200);
    assert.equal((await via({ ...fwd, origin: 'https://local.ping-devops.com:8443' })).status, 200);
    assert.equal((await via({ 'x-forwarded-host': 'local.ping-devops.com:8443', origin: 'https://local.ping-devops.com:8443' })).status, 200, 'proto defaults to https');
    assert.equal((await via({ ...fwd, origin: 'https://local.ping-devops.com:8443' }, PROXY_HOST.toUpperCase())).status, 200, 'Host without a port, any case');
    // refused: a foreign origin, a mismatched forwarded host, a wrong scheme, a cross-site fetch, no forwarded host at all
    for (const headers of [
      { ...fwd, origin: 'https://evil.example.com' },
      { ...fwd, origin: 'https://local.ping-devops.com:9999' },
      { ...fwd, origin: 'http://local.ping-devops.com:8443' },
      { ...fwd, origin: 'https://local.ping-devops.com:8443', 'sec-fetch-site': 'cross-site' },
      { origin: 'https://local.ping-devops.com:8443' },
      { 'x-forwarded-host': 'evil.example.com', 'x-forwarded-proto': 'https', origin: 'https://local.ping-devops.com:8443' },
      { 'x-forwarded-host': 'local.ping-devops.com:8443', 'x-forwarded-proto': 'ftp', origin: 'ftp://local.ping-devops.com:8443' },
    ]) assert.equal((await via(headers)).status, 403, JSON.stringify(headers));
    // the forwarded headers are not believed on a loopback Host: a page that did not come through the proxy cannot use them
    assert.equal((await via({ ...fwd, origin: 'https://local.ping-devops.com:8443' }, `127.0.0.1:${base}`)).status, 403);
    // the old hosted setting is unchanged
    assert.equal((await via({ origin: pub }, `127.0.0.1:${base}`)).status, 200, 'AI_GUARD_PUBLIC_ORIGIN on a loopback Host');
    assert.equal((await via({ origin: `http://127.0.0.1:${base}` }, `127.0.0.1:${base}`)).status, 200, 'loopback origin');
  } finally { await srv.close(); }
  // without LAB_ALLOWED_HOSTS the same request is refused at the Host check
  const b2 = await freeBase('safety', 2);
  const plain = await startHttpServer({ port: b2, embeddedPort: b2 + 1, env: {}, webDist: null });
  try {
    const r = await request(b2, 'PUT', '/api/fault', { host: `${PROXY_HOST}:6500`, body: { mode: 'none', delayMs: 0 }, headers: { 'x-forwarded-host': 'local.ping-devops.com:8443', 'x-forwarded-proto': 'https', origin: 'https://local.ping-devops.com:8443' } });
    assert.equal(r.status, 421);
  } finally { await plain.close(); }
});

test('guards: a chunked body (no Content-Length) that is not JSON is refused with 415', async () => {
  const g = await guarded();
  try {
    const status = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: g.port, method: 'POST', path: '/x', headers: { 'content-type': 'text/plain', 'transfer-encoding': 'chunked' } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject);
      req.write('a=b'); req.end();
    });
    assert.equal(status, 415);
  } finally { await g.close(); }
});
