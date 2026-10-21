import assert from 'node:assert/strict';
import { test } from 'node:test';
import express from 'express';
import { assertBindAllowed, assertSidecarUrl, credentialGuard, hostGuard, isLoopbackHost, originGuard, parseHost, portInRange } from '../src/safety.js';
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
