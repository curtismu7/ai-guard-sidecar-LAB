import assert from 'node:assert/strict';
import http from 'node:http';
import { after, test } from 'node:test';
import { MAX_RESPONSE_BYTES, UNKNOWN_CATEGORY_THRESHOLD, callSidecar, createGateway, decide, findingBlocks, sanitizeFindings, validateGatewayConfig } from '../src/gateway.js';
import { startSidecar } from '../src/sidecar.js';
import { CARD_DIGITS, INJECTION, SSN, freeBase } from './helpers.js';

const T = { prompt_injection: 'medium', jailbreak: 'none', pii: 'high' };
const f = (category, severity) => ({ category, severity, index: 0, messages: [], contents: [] });

test('findingBlocks compares severity to the category threshold: at or above blocks', () => {
  assert.ok(findingBlocks(f('prompt_injection', 'medium'), T), 'equal blocks');
  assert.ok(findingBlocks(f('prompt_injection', 'high'), T), 'above blocks');
  assert.ok(!findingBlocks(f('prompt_injection', 'low'), T), 'below does not');
  assert.ok(!findingBlocks(f('pii', 'medium'), T), 'medium pii is below the high threshold');
  assert.ok(findingBlocks(f('pii', 'high'), T));
  assert.ok(!findingBlocks(f('jailbreak', 'high'), T), 'none = alert only');
  assert.ok(findingBlocks(f('prompt_injection', 'low'), { ...T, prompt_injection: 'low' }));
});

test('unknown categories and unknown severities fail safe', () => {
  assert.equal(UNKNOWN_CATEGORY_THRESHOLD, 'high');
  assert.ok(findingBlocks(f('weird', 'high'), T));
  assert.ok(!findingBlocks(f('weird', 'medium'), T));
  assert.ok(findingBlocks(f('prompt_injection', 'unknown'), T), 'unknown severity counts as high');
});

test('decide: empty = allow, alert below threshold = allow with alert, threshold met = block', () => {
  const pol = { failClosed: true, blockThresholds: T };
  assert.deepEqual(decide({ ok: true, findings: [] }, pol), { decision: 'allow', reason: 'no_findings', alert: false, evaluations: [] });
  assert.equal(decide({ ok: true, findings: [f('pii', 'medium')] }, pol).reason, 'alert_only_below_threshold');
  assert.equal(decide({ ok: true, findings: [f('pii', 'high')] }, pol).decision, 'block');
  const none = { failClosed: true, blockThresholds: { ...T, prompt_injection: 'none' } };
  assert.equal(decide({ ok: true, findings: [f('prompt_injection', 'high')] }, none).reason, 'alert_only_not_enforcing', 'observe-only must not read as a low score');
  assert.equal(decide({ ok: true, findings: [f('prompt_injection', 'high'), f('pii', 'medium')] }, none).reason, 'alert_only_below_threshold');
});

test('decide: sidecar failure follows the fail-closed toggle', () => {
  const call = { ok: false, error: 'sidecar_http_502' };
  const closed = decide(call, { failClosed: true, blockThresholds: T });
  const open = decide(call, { failClosed: false, blockThresholds: T });
  assert.equal(closed.decision, 'block'); assert.equal(closed.reason, 'sidecar_error_fail_closed');
  assert.equal(open.decision, 'allow'); assert.equal(open.reason, 'sidecar_error_fail_open');
});

test('validateGatewayConfig is strict', () => {
  const good = { failClosed: true, timeoutMs: 500, blockThresholds: T };
  assert.deepEqual(validateGatewayConfig(good), good);
  for (const bad of [null, [], { ...good, extra: 1 }, { ...good, failClosed: 'yes' }, { ...good, timeoutMs: 5 }, { ...good, timeoutMs: 1.5 }, { ...good, blockThresholds: { ...T, pii: 'extreme' } }, { ...good, blockThresholds: { pii: 'high' } }]) {
    assert.throws(() => validateGatewayConfig(bad), undefined, JSON.stringify(bad));
  }
});

test('sanitizeFindings treats the sidecar as untrusted: shape, masking, inert text', () => {
  const out = sanitizeFindings({ findings: [{ category: 'pii​', severity: 'catastrophic', location: { index: 0 }, messages: [`found ${SSN}`], contents: [`card ${CARD_DIGITS} ‮`] }] });
  assert.equal(out[0].severity, 'unknown');
  assert.ok(!JSON.stringify(out).includes(SSN) && !JSON.stringify(out).includes(CARD_DIGITS));
  assert.match(out[0].category, /\[U\+200B\]/);
  for (const bad of [null, {}, { findings: 'x' }, { findings: [{}] }, { findings: [{ category: 'a', severity: 'high', location: { index: -1 } }] }, { findings: Array(101).fill({ category: 'a', severity: 'high', location: { index: 0 } }) }]) {
    assert.throws(() => sanitizeFindings(bad), undefined, JSON.stringify(bad)?.slice(0, 60));
  }
});

// Every stub is also closed in after(): a test that fails by timeout never reaches its own finally, and an open
// listener would keep the test process (and the port) alive.
const stubs = new Set();
after(() => Promise.all([...stubs].map((s) => s.close())));
function stub(handler) {
  return freeBase('gateway').then((port) => new Promise((resolve) => {
    const server = http.createServer(handler).listen(port, '127.0.0.1', () => {
      const s = { port, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { stubs.delete(s); server.closeAllConnections(); server.close(r); }) };
      stubs.add(s); resolve(s);
    });
  }));
}
const json = (obj) => (_q, r) => { r.setHeader('content-type', 'application/json'); r.end(JSON.stringify(obj)); };
const units = [{ role: 'user_prompt', direction: 'request', text: 'x' }];

test('the reply cap is 256 KB: a huge but VALID JSON reply is refused, one just under the cap is read', async () => {
  assert.equal(MAX_RESPONSE_BYTES, 256 * 1024, 'docs/safety.md states 256 KB');
  const pad = (n) => ({ findings: [], pad: 'x'.repeat(n) });
  const over = await stub(json(pad(MAX_RESPONSE_BYTES + 1000)));
  const under = await stub(json(pad(MAX_RESPONSE_BYTES - 1000)));
  try {
    const a = await callSidecar(over.url, units, 5000);
    assert.equal(a.ok, false); assert.equal(a.error, 'sidecar_bad_response');
    const b = await callSidecar(under.url, units, 5000);
    assert.equal(b.ok, true); assert.deepEqual(b.findings, []);
  } finally { await over.close(); await under.close(); }
});

test('callSidecar maps every failure to an error kind, never throws', { timeout: 30000 }, async () => {
  const cases = [
    ['sidecar_http_502', (_q, r) => { r.statusCode = 502; r.end('{}'); }],
    ['sidecar_http_400', (_q, r) => { r.statusCode = 400; r.end('{}'); }],
    ['sidecar_bad_response', (_q, r) => { r.setHeader('content-type', 'application/json'); r.end('not json'); }],
    ['sidecar_bad_response', (_q, r) => { r.end(JSON.stringify({ nope: 1 })); }],
    ['sidecar_bad_response', (_q, r) => { r.end('x'.repeat(300 * 1024)); }],
    ['sidecar_unreachable', (_q, r) => { r.statusCode = 302; r.setHeader('location', 'http://127.0.0.1:6549/'); r.end(); }],
    ['sidecar_timeout', () => { /* never answers */ }],
  ];
  for (const [want, handler] of cases) {
    const s = await stub(handler);
    try {
      // Generous timeout for the cases that expect a fast answer (a loaded machine must not turn a 502 into a timeout);
      // only the case that never answers uses a short one.
      const r = await callSidecar(s.url, units, want === 'sidecar_timeout' ? 250 : 5000);
      assert.equal(r.ok, false); assert.equal(r.error, want);
    } finally { await s.close(); }
  }
  const s = await stub((_q, r) => { r.setHeader('content-type', 'application/json'); r.end(JSON.stringify({ findings: [] })); });
  try { assert.deepEqual((await callSidecar(s.url, units, 500)).findings, []); } finally { await s.close(); }
  const dead = await freeBase('gateway');
  assert.equal((await callSidecar(`http://127.0.0.1:${dead}`, units, 300)).error, 'sidecar_unreachable');
});

test('the gateway refuses a sidecar URL that is not loopback, http and in range', () => {
  for (const u of ['http://example.com:6501', 'http://127.0.0.1:8086', 'https://127.0.0.1:6501']) assert.throws(() => createGateway({ sidecarUrl: u }), undefined, u);
});

let sc; let gw;
const boot = async () => { if (!sc) { sc = await startSidecar({ port: await freeBase('gateway') }); gw = createGateway({ sidecarUrl: sc.url }); } };
after(() => sc?.close());
const policy = { failClosed: true, timeoutMs: 800, blockThresholds: T };

test('a blocked request never reaches the upstream; a clean request is inspected again on the response', async () => {
  await boot(); sc.state.reset();
  const blocked = await gw.run({ requestText: INJECTION, upstreamText: 'leak', policy });
  assert.equal(blocked.blockedAt, 'request');
  assert.equal(blocked.stages.find((s) => s.stage === 'upstream').skipped, true);
  assert.equal(blocked.stages.find((s) => s.stage === 'response').skipped, true);
  const clean = await gw.run({ requestText: 'hello', upstreamText: 'fine', policy });
  assert.equal(clean.outcome, 'allow');
  assert.equal(clean.stages.filter((s) => s.sidecar).length, 2, 'request and response were both inspected');
});

test('response-direction scanning blocks a leak in a clean exchange; without it the leak would pass', async () => {
  await boot(); sc.state.reset();
  const leak = await gw.run({ requestText: 'what is on file?', upstreamText: `SSN ${SSN}`, policy });
  assert.equal(leak.blockedAt, 'response');
  const resp = leak.stages.find((s) => s.stage === 'response');
  assert.equal(resp.unit.direction, 'response');
  assert.ok(!JSON.stringify(leak).includes(SSN));
});

test('fail-closed vs fail-open against a faulted real sidecar', async () => {
  await boot(); sc.state.reset(); sc.state.fault = { mode: 'error', delayMs: 0 };
  const closed = await gw.run({ requestText: INJECTION, upstreamText: 'x', policy });
  const open = await gw.run({ requestText: INJECTION, upstreamText: 'x', policy: { ...policy, failClosed: false } });
  sc.state.reset();
  assert.equal(closed.outcome, 'block'); assert.equal(closed.reason, 'sidecar_error_fail_closed');
  assert.equal(open.outcome, 'allow'); assert.equal(open.reason, 'sidecar_error_fail_open');
  assert.equal(open.stages[0].sidecar.status, 502);
});

test('a timeout is reported as a timeout and honours the toggle', { timeout: 15000 }, async () => {
  await boot(); sc.state.reset(); sc.state.fault = { mode: 'timeout', delayMs: 0 };
  const r = await gw.run({ requestText: 'hi', upstreamText: 'x', policy: { ...policy, timeoutMs: 200 } });
  sc.state.reset();
  assert.equal(r.stages[0].sidecar.error, 'sidecar_timeout');
  assert.equal(r.outcome, 'block');
});
