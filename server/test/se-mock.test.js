// MODE=se-mock (rule 18): live features refused, one runtime per workspace, the banner, and the embedded sidecar keeping
// one fault and config state per workspace. Loopback only, zero outbound.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { startHttpServer } from '../src/app.js';
import { runChecks } from '../src/doctor.js';
import { SE_MOCK_BANNER } from '../src/config.js';
import { freeBase, request } from './helpers.js';

const env = { MODE: 'se-mock' };
let srv; let port; let sidecarPort;
before(async () => {
  const base = await freeBase('gateway', 2);
  port = base; sidecarPort = base + 1;
  srv = await startHttpServer({ port, embeddedPort: sidecarPort, env, webDist: null });
});
after(() => srv?.close());

const ws = (id) => (id === undefined ? {} : { 'x-workspace-id': id });
const get = (p, id) => request(port, 'GET', p, { headers: ws(id) });
const put = (p, body, id) => request(port, 'PUT', p, { body, headers: ws(id) });
const post = (p, body, id) => request(port, 'POST', p, { body, headers: ws(id) });
const OPEN_GATEWAY = { failClosed: false, timeoutMs: 1000, blockThresholds: { prompt_injection: 'medium', jailbreak: 'none', pii: 'high' } };

// A refusal must throw. If a guard is missing and the server starts, close it before failing, so the runner exits.
async function mustRefuse(opts, re) {
  let s;
  try { s = await startHttpServer(opts); } catch (e) { assert.match(e.message, re); return; }
  await s.close();
  assert.fail(`started, expected a refusal matching ${re}`);
}

test('a second live-feature flag or an unknown MODE is refused before anything is bound', async () => {
  await mustRefuse({ port: sidecarPort + 4, embeddedPort: sidecarPort + 5, env: { MODE: 'se-mock', AI_GUARD_SIDECAR_URL: 'http://127.0.0.1:6549' }, webDist: null }, /refusing to start in MODE=se-mock: AI_GUARD_SIDECAR_URL set/);
  await mustRefuse({ port: sidecarPort + 4, embeddedPort: sidecarPort + 5, env: { MODE: 'se-mock', AI_GUARD_SIDECAR_PORT: '6501' }, webDist: null }, /AI_GUARD_SIDECAR_PORT set/);
  await mustRefuse({ port: sidecarPort + 4, embeddedPort: sidecarPort + 5, env: { MODE: 'live' }, webDist: null }, /not available/);
  await mustRefuse({ port: sidecarPort + 4, embeddedPort: sidecarPort + 5, env: { MODE: 'se-mock', AI_GUARD_PUBLIC_ORIGIN: 'http://guard.demo.example' }, webDist: null }, /AI_GUARD_PUBLIC_ORIGIN must be/);
  await mustRefuse({ port: sidecarPort + 4, embeddedPort: sidecarPort + 5, env: { MODE: 'se-mock', AI_GUARD_PUBLIC_ORIGIN: 'https://guard.demo.example/x' }, webDist: null }, /AI_GUARD_PUBLIC_ORIGIN must be/);
});

test('the hosted UI can write: the ingress rewrites Host to loopback but passes the public Origin through, so that origin (and only it) is allowed', async () => {
  const base = await freeBase('gateway', 2);
  const pub = 'https://guard.demo.example';
  const hosted = await startHttpServer({ port: base, embeddedPort: base + 1, env: { MODE: 'se-mock', AI_GUARD_PUBLIC_ORIGIN: pub }, webDist: null });
  try {
    // The hosted UI always sends its tab's X-Workspace-Id; the fault, run and reset below must land in that one workspace.
    const w = (method, p, body, origin) => request(base, method, p, { body, host: `127.0.0.1:${base}`, headers: { origin, 'x-workspace-id': 'hosted-ui' } });
    assert.equal((await w('PUT', '/api/config', { gateway: OPEN_GATEWAY }, pub)).status, 200, 'config from the public origin');
    assert.equal((await w('PUT', '/api/fault', { mode: 'error', delayMs: 0 }, pub)).status, 200, 'fault from the public origin');
    const run = await w('POST', '/api/run', { scenario: 'benign' }, pub);
    assert.equal(run.status, 200, 'run from the public origin');
    assert.equal(run.json.runs[0].reason, 'sidecar_error_fail_open', 'the run really reached the faulted workspace');
    assert.equal((await w('POST', '/api/reset', undefined, pub)).status, 200, 'reset from the public origin');
    assert.equal((await w('PUT', '/api/fault', { mode: 'none', delayMs: 0 }, `http://127.0.0.1:${base}`)).status, 200, 'loopback origin still works');
    for (const origin of ['https://evil.example', 'https://guard.demo.example.evil', 'http://guard.demo.example', 'https://guard.demo.example:8443']) {
      assert.equal((await w('PUT', '/api/fault', { mode: 'none', delayMs: 0 }, origin)).status, 403, origin);
    }
  } finally { await hosted.close(); }
  const local = await startHttpServer({ port: base + 0, embeddedPort: base + 1, env: { MODE: 'se-mock' }, webDist: null });
  try {
    assert.equal((await request(base, 'PUT', '/api/fault', { body: { mode: 'none', delayMs: 0 }, host: `127.0.0.1:${base}`, headers: { origin: pub } })).status, 403, 'no public origin configured: refused');
  } finally { await local.close(); }
});

test('health stays demo-health/1 and carries the mode', async () => {
  const r = await get('/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.schema, 'demo-health/1');
  assert.equal(r.json.mode, 'se-mock');
  assert.equal(r.json.state, 'ready');
});

test('/api/info says hosted and simulated, with the banner text the UI shows on every view', async () => {
  const r = await get('/api/info');
  assert.equal(r.json.mode, 'se-mock');
  assert.equal(r.json.hosted, true);
  assert.equal(r.json.banner, SE_MOCK_BANNER);
  assert.match(r.json.banner, /^HOSTED SIMULATION/);
  assert.match(r.json.workspace, /^anon-[0-9a-f]{16}$/, 'no id: a private anonymous workspace, not the shared default');
  assert.notEqual((await get('/api/info')).json.workspace, r.json.workspace, 'each no-id call gets its own');
  assert.equal((await get('/api/info', 'visitor-a')).json.workspace, 'visitor-a', 'a valid id is kept');
});

test('a malformed workspace id is refused with 400, every time, before any route runs', async () => {
  for (const bad of ['../x', 'Default', 'a b', 'a'.repeat(33), '-x', 'a_b', '__proto__', '%2e%2e', 'a,b']) {
    const r = await get('/api/config', bad);
    assert.equal(r.status, 400, JSON.stringify(bad));
    assert.match(r.json.message, /X-Workspace-Id must be 1-32/);
  }
  assert.equal((await post('/api/run', { scenario: 'benign' }, '../../etc')).status, 400);
  assert.equal((await get('/api/config', '')).status, 400, 'an empty id is not the default');
});

test('two workspaces cannot see or change each other: config, fault, decision log and reset', async () => {
  const a = 'visitor-a'; const b = 'visitor-b';
  assert.equal((await put('/api/config', { gateway: OPEN_GATEWAY }, a)).status, 200);
  assert.equal((await put('/api/fault', { mode: 'error', delayMs: 0 }, a)).status, 200);
  const aRun = await post('/api/run', { scenario: 'benign' }, a);
  // A: its own sidecar fault (error) and its own fail-closed setting (off), so the sidecar error is let through.
  assert.equal(aRun.json.runs[0].outcome, 'allow');
  assert.equal(aRun.json.runs[0].reason, 'sidecar_error_fail_open');

  // B has the defaults: its config is untouched, its sidecar is healthy, its log is empty.
  const bCfg = (await get('/api/config', b)).json;
  assert.equal(bCfg.gateway.failClosed, true);
  assert.equal((await get('/api/fault', b)).json.fault.mode, 'none');
  assert.equal((await get('/api/decisions', b)).json.count, 0);
  const bRun = await post('/api/run', { scenario: 'benign' }, b);
  assert.equal(bRun.json.runs[0].outcome, 'allow');
  assert.equal(bRun.json.runs[0].stages[0].sidecar.ok, true, 'B reached a healthy sidecar state');

  // A still sees its own settings and its own log; B's reset does not touch A.
  assert.equal((await get('/api/fault', a)).json.fault.mode, 'error');
  assert.equal((await get('/api/config', a)).json.gateway.failClosed, false);
  assert.equal((await get('/api/decisions', a)).json.count, 1);
  assert.equal((await post('/api/reset', undefined, b)).status, 200);
  assert.equal((await get('/api/fault', a)).json.fault.mode, 'error', 'a reset in B leaves the fault in A');
  assert.equal((await get('/api/decisions', b)).json.count, 0);
  assert.equal((await get('/api/decisions', a)).json.count, 1);
});

test('two callers that send no X-Workspace-Id cannot read or change each other: each gets a private workspace, and the call still works', async () => {
  // A (no id) sets a sidecar fault. B (no id) must not see it: it is not the shared default.
  assert.equal((await put('/api/fault', { mode: 'error', delayMs: 0 })).status, 200, 'a call without an id still works');
  assert.equal((await get('/api/fault')).json.fault.mode, 'none', 'B does not see the fault A set without an id');
  const run = await post('/api/run', { scenario: 'benign' });
  assert.equal(run.status, 200);
  assert.equal(run.json.runs[0].outcome, 'allow');
  assert.equal(run.json.runs[0].stages[0].sidecar.ok, true, 'a new no-id caller reaches a healthy sidecar');
});

test('accepted residual risk (docs/safety.md): a write with NO Origin header is accepted, since non-browser clients send none', async () => {
  // No Origin and no Sec-Fetch-Site: the request is a script, not a browser page on another site, so the Origin check does not apply.
  const h = { 'x-workspace-id': 'no-origin-pin' };
  const fault = await request(port, 'PUT', '/api/fault', { body: { mode: 'none', delayMs: 0 }, headers: h });
  assert.equal(fault.status, 200, 'PUT without Origin is accepted');
  const run = await request(port, 'POST', '/api/run', { body: { scenario: 'benign' }, headers: h });
  assert.equal(run.status, 200, 'POST without Origin is accepted');
  assert.equal((await request(port, 'POST', '/api/reset', { headers: h })).status, 200, 'reset without Origin is accepted');
});

test('the embedded sidecar answers per workspace; a hostile sidecar header is refused', async () => {
  const sidecar = (path, method, body, headers) => request(sidecarPort, method, path, { body, headers });
  assert.equal((await sidecar('/demo/fault', 'GET', undefined, { 'x-ai-guard-workspace': 'visitor-a' })).json.fault.mode, 'error');
  assert.equal((await sidecar('/demo/fault', 'GET', undefined, { 'x-ai-guard-workspace': 'visitor-b' })).json.fault.mode, 'none');
  assert.equal((await sidecar('/demo/fault', 'GET', undefined, { 'x-ai-guard-workspace': 'visitor-c' })).json.fault.mode, 'none', 'a new workspace starts clean');
  assert.equal((await sidecar('/demo/fault', 'GET', undefined, { 'x-ai-guard-workspace': '../visitor-a' })).status, 400);
  assert.equal((await sidecar('/demo/fault', 'GET', undefined, { 'x-ai-guard-workspace': 'Visitor-A' })).status, 400);
});

test('a run in one workspace with an injected fault does not change the decision in another', async () => {
  await put('/api/fault', { mode: 'none', delayMs: 0 }, 'visitor-a');
  const c = await post('/api/run', { scenario: 'outage-502' }, 'visitor-c');
  assert.equal(c.json.allExpectationsMet, true);
  const d = await post('/api/run', { scenario: 'outage-502' }, 'visitor-d');
  assert.equal(d.json.allExpectationsMet, true, 'the scenario sets its own fault and restores the workspace afterwards');
});

test('the doctor fails on a live flag in se-mock, passes a clean se-mock, and fails an unknown MODE', () => {
  const find = (checks, id) => checks.find((c) => c.id === id);
  const bad = runChecks({ env: { MODE: 'se-mock', AI_GUARD_SIDECAR_URL: 'http://127.0.0.1:6549' } });
  assert.equal(find(bad, 'live-flags').level, 'fail');
  assert.equal(find(bad, 'sidecar-url').level, 'pass', 'the URL is not even checked: it is refused outright');
  const clean = runChecks({ env: { MODE: 'se-mock' } });
  assert.equal(find(clean, 'live-flags').level, 'pass');
  assert.equal(find(clean, 'mode').level, 'pass');
  assert.equal(runChecks({ env: { MODE: 'live' } }).find((c) => c.id === 'mode').level, 'fail');
  assert.equal(runChecks({ env: {} }).find((c) => c.id === 'live-flags'), undefined, 'the local demo has no live-flag check');
});
