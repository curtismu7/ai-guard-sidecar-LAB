import assert from 'node:assert/strict';
import { test } from 'node:test';
import { startHttpServer } from '../src/app.js';
import { guardNetwork } from './netguard.js';
import { freeBase } from './helpers.js';

test('the guard itself works: a non-loopback fetch is blocked and recorded', async () => {
  const g = guardNetwork();
  try {
    await assert.rejects(fetch('http://example.com/'), /network blocked/);
    assert.deepEqual(g.attempts, ['fetch:example.com']);
  } finally { g.restore(); }
});

test('zero non-loopback connections while every scenario runs, and every listener is loopback', async () => {
  const g = guardNetwork();
  const base = await freeBase('net', 2);
  const s = await startHttpServer({ port: base, embeddedPort: base + 1 });
  try {
    const list = await (await fetch(`${s.url}api/scenarios`)).json();
    for (const sc of list.scenarios) {
      const r = await fetch(`${s.url}api/run`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ scenario: sc.id }) });
      assert.equal(r.status, 200, sc.id);
    }
    await fetch(`${s.url}api/config`);
    assert.deepEqual(g.attempts, [], `non-loopback attempts: ${g.attempts.join()}`);
    assert.match(s.sidecarUrl, /^http:\/\/127\.0\.0\.1:/);
    assert.match(s.url, /^http:\/\/127\.0\.0\.1:/);
  } finally { g.restore(); await s.close(); }
});

test('both servers listen on 127.0.0.1 only', async () => {
  const base = await freeBase('net', 2);
  const s = await startHttpServer({ port: base, embeddedPort: base + 1 });
  try {
    assert.equal(s.address, '127.0.0.1');
    assert.equal(s.embedded.url, `http://127.0.0.1:${base + 1}`);
    for (const p of [base, base + 1]) assert.ok(p >= 6500 && p <= 6549);
  } finally { await s.close(); }
});

test('startHttpServer refuses a non-loopback bind without the opt-in, and a bad sidecar URL', { timeout: 15000 }, async () => {
  const base = await freeBase('net', 2);
  // If a guard is removed the server would START (and a wildcard listener would outlive the test): close it and fail.
  const mustRefuse = async (opts, pattern) => {
    let started = null;
    try { started = await startHttpServer(opts); } catch (e) { assert.match(String(e.message), pattern); return; }
    await started.close();
    assert.fail(`startHttpServer should have refused ${JSON.stringify(opts)}`);
  };
  await mustRefuse({ port: base, host: '0.0.0.0', env: {}, embeddedPort: base + 1 }, /loopback only/);
  await mustRefuse({ port: base, env: {}, sidecarUrl: 'http://example.com:6501' }, /loopback/);
  await mustRefuse({ port: 8086, embeddedPort: base + 1 }, /outside 6500-6549/);
});
