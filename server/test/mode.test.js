import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startHttpServer } from '../src/app.js';
import { startSidecar } from '../src/sidecar.js';
import { freeBase, request } from './helpers.js';

const mode = (base, source, raw) => request(base, 'POST', '/api/mode', { body: raw ?? { source } });

test('local with no external sidecar: Mock is the only source, Real is refused with how to enable it', async () => {
  const base = await freeBase('api', 2);
  const s = await startHttpServer({ port: base, embeddedPort: base + 1, webDist: null });
  try {
    const info = (await request(base, 'GET', '/api/info')).json;
    assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false);
    const real = await mode(base, 'real');
    assert.equal(real.status, 409); assert.match(real.json.message, /AI_GUARD_SIDECAR_URL/);
    assert.equal((await mode(base, 'mock')).status, 200);
    for (const bad of [{}, { source: 'live' }, { source: 'mock', extra: 1 }, []]) assert.equal((await mode(base, null, bad)).status, 400, JSON.stringify(bad));
  } finally { await s.close(); }
});

test('local with an external sidecar: Real is the default, and the toggle really changes which sidecar answers', async () => {
  const base = await freeBase('api', 3);
  const external = await startSidecar({ port: base + 2 });
  const s = await startHttpServer({ port: base, embeddedPort: base + 1, sidecarUrl: external.url, webDist: null });
  try {
    const info = (await request(base, 'GET', '/api/info')).json;
    assert.equal(info.source, 'real'); assert.equal(info.realAvailable, true);
    // A fault set while Real is selected lands on the external sidecar only.
    assert.equal((await request(base, 'PUT', '/api/fault', { body: { mode: 'error', delayMs: 0 } })).status, 200);
    assert.equal((await request(base, 'GET', '/api/fault')).json.fault.mode, 'error');
    const toMock = await mode(base, 'mock');
    assert.equal(toMock.status, 200); assert.equal(toMock.json.source, 'mock');
    assert.equal((await request(base, 'GET', '/api/fault')).json.fault.mode, 'none');
    assert.equal((await request(base, 'GET', '/api/info')).json.source, 'mock');
    const back = await mode(base, 'real');
    assert.equal(back.json.source, 'real');
    assert.equal((await request(base, 'GET', '/api/fault')).json.fault.mode, 'error');
    await request(base, 'PUT', '/api/fault', { body: { mode: 'none', delayMs: 0 } });
  } finally { await s.close(); await external.close(); }
});

test('the hosted build is fail-closed Mock: it reports it and refuses to be switched', async () => {
  const base = await freeBase('api', 2);
  const s = await startHttpServer({ port: base, embeddedPort: base + 1, env: { MODE: 'se-mock' }, webDist: null });
  try {
    const info = (await request(base, 'GET', '/api/info')).json;
    assert.equal(info.source, 'mock'); assert.equal(info.realAvailable, false);
    assert.equal((await mode(base, 'real')).status, 403);
    assert.equal((await mode(base, 'mock')).status, 403);
  } finally { await s.close(); }
});
