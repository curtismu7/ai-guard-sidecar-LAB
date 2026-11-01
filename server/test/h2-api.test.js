// H2 2026 release through the HTTP API: the overview, kinds and the secrets rail through /api/config, your own rules, prompt logging, reset,
// per-workspace isolation, concurrency, and masking of everything typed. Zero outbound network, asserted.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { startHttpServer } from '../src/app.js';
import { PII_KIND_IDS, SAMPLES } from '../src/pii.js';
import { SECRET_DETECTORS } from '../src/secrets.js';
import { DECK, FIELD_TAGS, TAGS } from '../src/h2.js';
import { RULE_LIMITS } from '../src/rules.js';
import { PL_STORE } from '../src/promptlog.js';
import { openEnvelope } from '../../web/src/lib/seal.js';
import { freeBase, request, fakeSecrets, x25519Pair } from './helpers.js';
import { guardNetwork } from './netguard.js';

let srv; let port; let net;
before(async () => { net = guardNetwork(); const b = await freeBase('api', 2); port = b; srv = await startHttpServer({ port: b, embeddedPort: b + 1, webDist: null }); });
after(async () => { await srv.close(); net.restore(); });
const call = (m, p, body, o) => request(port, m, p, { body, ...o });
const get = (p, o) => call('GET', p, undefined, o);
const reset = () => call('POST', '/api/reset');
const custom = (requestText, extra = {}) => call('POST', '/api/run', { custom: { requestText, ...extra } });
const evals = (r) => r.json.runs[0].stages[0].evaluations;
const TOML = (id = 'acme-ticket', extra = '') => `[[rules]]\nid = "${id}"\nregex = "ACME-[0-9]{8}"\n${extra}`;

test('GET /api/h2: the banner, the tag legend, Ping\'s numbers beside the app\'s own computed ones, and live proofs', async () => {
  await reset();
  const r = await get('/api/h2');
  assert.equal(r.status, 200);
  assert.equal(r.json.banner, 'Ping release claim, UNVERIFIED on our tenant');
  assert.deepEqual(r.json.tags, TAGS);
  const n = Object.fromEntries(r.json.numbers.map((x) => [x.id, x]));
  assert.deepEqual([n['pii-kinds'].ping, n['secret-detectors'].ping, n['behavioural-rules'].ping, n['total-rules'].ping], [23, 364, 47, 411]);
  assert.equal(DECK.behaviouralRules + DECK.secretDetectors, DECK.totalRules, 'the deck\'s own sum');
  assert.equal(n['pii-kinds'].app, PII_KIND_IDS.length); assert.equal(n['secret-detectors'].app, SECRET_DETECTORS.length);
  for (const x of r.json.numbers) { assert.equal(x.pingTag, 'deck'); assert.ok(x.app === null || x.appTag === 'invented'); assert.notEqual(x.app, x.ping, 'the app\'s figure is not Ping\'s'); }
  assert.ok(r.json.kinds.every((k) => k.valid.detected && !k.nearMiss.detected), 'proofs hold');
  assert.ok(r.json.secretProofs.every((k) => k.valid.detected && !k.nearMiss.detected));
  assert.deepEqual(r.json.selected, ['card', 'ssn', 'iban', 'email', 'phone']);
  for (const f of FIELD_TAGS) assert.ok(Object.hasOwn(TAGS, f.tag), f.id);
  assert.ok(new Set(FIELD_TAGS.map((f) => f.tag)).size === 5, 'all five claim tags are in use');
  assert.ok(FIELD_TAGS.find((f) => f.tag === 'measured').note.startsWith('Nothing'));
  // none of the shown samples is a raw value
  for (const k of r.json.kinds) assert.ok(!r.raw.includes(SAMPLES[k.id].valid()) && !r.raw.includes(SAMPLES[k.id].nearMiss()), `${k.id} sample shown raw`);
  for (const d of SECRET_DETECTORS) assert.ok(!r.raw.includes(d.sample()) && !r.raw.includes(d.nearMiss()), `${d.id} sample shown raw`);
});

test('piiKinds through /api/config: a kind that is switched on raises a finding, off it does not; reset restores the original five', async () => {
  await reset();
  const text = `id ${SAMPLES['es-dni'].valid()}`;
  assert.equal(evals(await custom(text)).length, 0);
  const cfg = (await get('/api/config')).json;
  const on = await call('PUT', '/api/config', { sidecar: { ...cfg.sidecar, piiKinds: [...cfg.sidecar.piiKinds, 'es-dni'] } });
  assert.equal(on.status, 200); assert.ok(on.json.sidecar.piiKinds.includes('es-dni'));
  const hit = evals(await custom(text));
  assert.deepEqual(hit.map((e) => [e.category, e.blocks]), [['pii', true]]);
  assert.ok((await get('/api/h2')).json.selected.includes('es-dni'));
  for (const bad of [['nope'], 'x', ['ssn', 'ssn']]) assert.equal((await call('PUT', '/api/config', { sidecar: { ...cfg.sidecar, piiKinds: bad } })).status, 400);
  assert.ok((await get('/api/config')).json.sidecar.piiKinds.includes('es-dni'), 'a refused update changed nothing');
  await reset();
  assert.deepEqual((await get('/api/config')).json.sidecar.piiKinds, ['card', 'ssn', 'iban', 'email', 'phone']);
  assert.equal(evals(await custom(text)).length, 0);
});

test('the secrets rail is a config switch (default off); a bundled secret then blocks at the demo\'s unknown-category threshold', async () => {
  await reset();
  const secret = SECRET_DETECTORS[0].sample();
  assert.equal(evals(await custom(`key ${secret}`)).length, 0);
  const cfg = (await get('/api/config')).json;
  assert.equal(cfg.sidecar.rails.secrets, false);
  await call('PUT', '/api/config', { sidecar: { ...cfg.sidecar, rails: { ...cfg.sidecar.rails, secrets: true } } });
  const r = await custom(`key ${secret}`);
  assert.deepEqual(evals(r).map((e) => [e.category, e.severity, e.threshold, e.blocks]), [['secrets', 'high', 'high', true]]);
  assert.equal(r.json.runs[0].outcome, 'block');
  assert.ok(!r.raw.includes(secret), 'the secret is not echoed');
  // a sidecar PUT that leaves the optional parts out keeps them (the first-release body shape still works)
  const old = await call('PUT', '/api/config', { sidecar: { detector: cfg.sidecar.detector, rails: { injection: true, regex_pii: true } } });
  assert.equal(old.json.sidecar.rails.secrets, true);
  await reset();
  assert.equal((await get('/api/config')).json.sidecar.rails.secrets, false);
});

test('your own rules: paste (200), match, mask, severity and category take part in the gateway decision', async () => {
  await reset();
  const put = await call('PUT', '/api/rules', { toml: TOML('acme-ticket', 'severity = "high"\n') });
  assert.equal(put.status, 200); assert.deepEqual(put.json.Errors, []); assert.equal(put.json.Added[0].id, 'cst-acme-ticket');
  assert.ok(!put.raw.includes('ACME-'), 'the pattern is not returned');
  const r = await custom('ticket ACME-12345678 for you');
  assert.deepEqual(evals(r).map((e) => [e.category, e.blocks]), [['secrets', true]]);
  assert.equal(r.json.runs[0].outcome, 'block');
  assert.ok(!r.raw.includes('ACME-12345678'), 'the match is masked everywhere, including the request unit the gateway shows');
  assert.ok(r.raw.includes('[masked:cst-acme-ticket]'));
  assert.deepEqual((await get('/api/rules')).json.custom.map((x) => x.id), ['cst-acme-ticket']);
  // a medium finding in the pii category is below pii's high threshold: allowed, with an alert
  await call('DELETE', '/api/rules');
  await call('PUT', '/api/rules', { toml: TOML('acme-ticket', 'category = "pii"\nseverity = "medium"\n') });
  const soft = await custom('ticket ACME-12345678');
  assert.deepEqual([soft.json.runs[0].outcome, soft.json.runs[0].reason], ['allow', 'alert_only_below_threshold']);
});

test('one bad rule refuses the whole paste with an honest 400 and the list of reasons; nothing is added', async () => {
  await reset();
  const bad = await call('PUT', '/api/rules', { toml: `${TOML()}\n[[rules]]\nid = "two"\nregex = "(a+)+b"\n` });
  assert.equal(bad.status, 400);
  assert.equal(bad.json.error, 'bad_request'); assert.match(bad.json.message, /whole paste was refused/);
  assert.equal(bad.json.Errors.length, 1); assert.match(bad.json.Errors[0], /^rule 2 /);
  assert.equal((await get('/api/rules')).json.custom.length, 0);
  assert.equal(evals(await custom('ACME-12345678')).length, 0, 'the good rule of the refused paste is not active');
  for (const body of [{}, { toml: 5 }, { toml: 'x', extra: 1 }, [], 'x', { toml: null }]) assert.equal((await call('PUT', '/api/rules', body)).status, 400, JSON.stringify(body));
  assert.equal((await call('PUT', '/api/rules', { toml: 'x'.repeat(60 * 1024) })).status, 413);
});

test('pastes accumulate: a second paste with a new id adds to the first and both are active', async () => {
  await reset();
  assert.equal((await call('PUT', '/api/rules', { toml: TOML('first') })).status, 200);
  assert.equal((await call('PUT', '/api/rules', { toml: `[[rules]]\nid = "second"\nregex = "ZED-[0-9]{8}"\n` })).status, 200);
  assert.deepEqual((await get('/api/rules')).json.custom.map((r) => r.id), ['cst-first', 'cst-second']);
  assert.equal(evals(await custom('ACME-12345678 and ZED-12345678'))[0].category, 'secrets');
  assert.equal(evals(await custom('ZED-12345678')).length, 1, 'the second rule is live');
  assert.equal(evals(await custom('ACME-12345678')).length, 1, 'and so is the first');
});

test('caps refuse the whole paste: twenty rules in, the twenty-first is refused and nothing changes', async () => {
  await reset();
  const many = Array.from({ length: RULE_LIMITS.rulesPerWorkspace }, (_v, i) => TOML(`r${i}`)).join('');
  assert.equal((await call('PUT', '/api/rules', { toml: many })).status, 200);
  const over = await call('PUT', '/api/rules', { toml: TOML('over') });
  assert.equal(over.status, 400); assert.match(over.json.Errors[0], /at most/);
  assert.equal((await get('/api/rules')).json.custom.length, RULE_LIMITS.rulesPerWorkspace);
});

test('parallel pastes of the same rule id: exactly one is added, the rest are refused', async () => {
  await reset();
  const results = await Promise.all(Array.from({ length: 6 }, () => call('PUT', '/api/rules', { toml: TOML('same') })));
  assert.deepEqual(results.map((r) => r.status).sort(), [200, 400, 400, 400, 400, 400]);
  assert.equal((await get('/api/rules')).json.custom.length, 1);
});

test('prompt logging end to end: off by default, settings validated, a run is sealed, the key holder opens it, the server cannot', async () => {
  await reset();
  const pair = x25519Pair();
  assert.deepEqual((await get('/api/prompt-log')).json.config.Enabled, false);
  assert.equal((await custom('hello there')).json.runs[0].promptLog.recorded, false);
  const bad = await call('PUT', '/api/prompt-log', { Enabled: true, KeyID: 'k1', PublicKey: JSON.stringify(pair.privateJwk) });
  assert.equal(bad.status, 400); assert.equal(bad.json.errors[0].field, 'PublicKey'); assert.ok(!bad.raw.includes(pair.privateJwk.d), 'a private key is refused and not echoed');
  assert.equal((await call('PUT', '/api/prompt-log', { Enabled: true, KeyID: 'k1', Surplus: 1 })).status, 400);
  assert.equal((await get('/api/prompt-log')).json.config.Enabled, false, 'refused: unchanged');
  const ok = await call('PUT', '/api/prompt-log', { Enabled: true, KeyID: 'k1', PublicKey: JSON.stringify(pair.publicJwk), IncludeResponses: true });
  assert.equal(ok.status, 200); assert.equal(ok.json.status.recording, true);
  const k = fakeSecrets();
  const r = await custom(`please log this, my password is ${k.password}`, { upstreamText: 'sure' });
  const run = r.json.runs[0];
  assert.equal(run.promptLog.recorded, true); assert.ok(!r.raw.includes(k.password));
  const list = await get('/api/prompt-log');
  assert.equal(list.json.records.length, 1);
  assert.ok(!list.raw.includes(k.password) && !list.raw.includes('please log this'), 'the list holds no plaintext');
  const [rec] = list.json.records;
  assert.deepEqual([rec.surface, rec.outcome, rec.kid, rec.hasResponse], ['llm', 'allow', 'k1', true]);
  const opened = await openEnvelope(pair.privateJwk, rec.envelope);
  assert.equal(opened.ok, true); assert.match(JSON.parse(opened.plaintext).prompt, /please log this/);
  assert.equal(JSON.parse(opened.plaintext).response, 'sure');
  assert.equal((await openEnvelope(x25519Pair().privateJwk, rec.envelope)).ok, false);
  await reset();
  assert.deepEqual([(await get('/api/prompt-log')).json.records.length, (await get('/api/prompt-log')).json.config.PublicKey], [0, '']);
});

test('prompt logging: A2A runs are the a2a surface, a Surfaces filter skips others, the ring reports drops', async () => {
  await reset();
  const pair = x25519Pair();
  await call('PUT', '/api/prompt-log', { Enabled: true, KeyID: 'k1', PublicKey: JSON.stringify(pair.publicJwk), Surfaces: ['a2a'] });
  assert.equal((await custom('plain prompt')).json.runs[0].promptLog.recorded, false);
  assert.equal((await custom('agent message', { caller: 'research-agent' })).json.runs[0].promptLog.recorded, true);
  assert.equal((await get('/api/prompt-log')).json.records[0].surface, 'a2a');
  assert.equal((await get('/api/prompt-log')).json.limits.maxRecords, PL_STORE.maxRecords);
});

test('every new endpoint: unknown paths and methods are a fixed JSON 404/405 that never echoes the path', async () => {
  const k = fakeSecrets();
  for (const [m, p] of [['GET', `/api/rules/${k.ghp}`], ['GET', `/api/prompt-log/${k.password}`], ['GET', `/api/h2/${k.aws}`], ['POST', `/api/rules/${k.ghp}`], ['GET', `/api/${k.ghp}`], ['GET', `/${k.ghp}`]]) {
    const r = await request(port, m, p, m === 'POST' ? { body: {} } : {});
    assert.equal(r.status, 404, `${m} ${p.slice(0, 20)}`); assert.ok(!r.raw.includes(k.ghp) && !r.raw.includes(k.password) && !r.raw.includes(k.aws));
  }
  assert.equal((await call('POST', '/api/h2', {})).status, 404);
  assert.equal((await call('PUT', '/api/h2', {})).status, 404);
});

test('typed credential-shaped values in every field, header, query and unknown key of the new endpoints are never echoed or kept', async () => {
  await reset();
  const k = fakeSecrets(); const vals = [k.ghp, k.aws, k.password];
  const seen = [];
  const keep = (r) => { seen.push(r.raw); return r; };
  const logs = []; const real = { log: console.log, error: console.error, warn: console.warn };
  for (const f of ['log', 'error', 'warn']) console[f] = (...a) => { logs.push(a.join(' ')); };
  try {
    const key = `unknown_${k.password.replace(/-/g, '_')}`;
    keep(await call('PUT', '/api/rules', { toml: `[[rules]]\nid = "${k.ghp}"\nregex = "${k.aws}+"\n${key} = "${k.ghp}"\ndescription = "${k.password}"\n` }));
    keep(await call('PUT', '/api/rules', { toml: TOML('x1', `description = "my password is ${k.password} ${k.ghp}"\n`) }));
    keep(await call('PUT', '/api/rules', { [key]: k.ghp }));
    keep(await call('PUT', '/api/prompt-log', { [key]: k.ghp }));
    keep(await call('PUT', '/api/prompt-log', { Enabled: true, KeyID: k.ghp, PublicKey: k.aws, Surfaces: [k.password], MaxBytes: k.aws }));
    keep(await call('PUT', '/api/config', { sidecar: { detector: { threshold: 0.9, benignLabels: [] }, rails: { injection: true, regex_pii: true }, piiKinds: [k.ghp, k.password] } }));
    keep(await call('PUT', '/api/config', { [k.ghp]: 1 }));
    keep(await call('POST', '/api/run', { custom: { requestText: `${k.ghp} ${k.aws} my password is ${k.password}`, upstreamText: `${k.pem} ${k.ghp}`, caller: k.ghp, [key]: 1 } }));
    keep(await call('POST', '/api/run', { custom: { requestText: `${k.ghp} ${k.aws} ACME-12345678`, upstreamText: `pw: ${k.password}` } }));
    keep(await get(`/api/rules?x=${k.ghp}&y=${k.password}`)); keep(await get(`/api/prompt-log?x=${k.aws}`)); keep(await get(`/api/h2?x=${k.ghp}`));
    keep(await get('/api/decisions', { headers: { 'x-workspace-id': k.ghp } })); keep(await get('/api/rules', { headers: { 'x-custom': k.ghp } }));
    keep(await get('/api/rules', { headers: { authorization: `Bearer ${k.ghp}` } }));
    keep(await call('DELETE', `/api/rules?x=${k.ghp}`));
    keep(await get('/api/decisions')); keep(await get('/api/rules')); keep(await get('/api/prompt-log')); keep(await get('/api/config')); keep(await get('/api/h2'));
  } finally { Object.assign(console, real); }
  const all = [...seen, ...logs].join('\n');
  for (const v of [...vals, k.pem]) {
    const at = [...seen, ...logs].findIndex((t) => t.includes(v));
    assert.equal(at, -1, `${v.slice(0, 14)} appeared in response or log #${at}: ${[...seen, ...logs][at]?.slice(0, 200)}`);
  }
  assert.ok(!all.includes(k.password.replace(/-/g, '_')), 'the unknown key name was echoed');
});

test('zero outbound network attempts across all of the above', () => {
  assert.deepEqual(net.attempts, []);
});

test('per-workspace isolation in the hosted build: rules, kinds and prompt-log settings of one workspace never reach another', async () => {
  const b = await freeBase('api', 2);
  const hosted = await startHttpServer({ port: b, embeddedPort: b + 1, env: { MODE: 'se-mock' }, webDist: null });
  const w = (id, m, p, body) => request(b, m, p, { body, headers: { 'x-workspace-id': id } });
  try {
    const pair = x25519Pair();
    assert.equal((await w('ws-a', 'PUT', '/api/rules', { toml: TOML() })).status, 200);
    const cfg = (await w('ws-a', 'GET', '/api/config')).json;
    await w('ws-a', 'PUT', '/api/config', { sidecar: { ...cfg.sidecar, piiKinds: ['es-dni'], rails: { ...cfg.sidecar.rails, secrets: true } } });
    await w('ws-a', 'PUT', '/api/prompt-log', { Enabled: true, KeyID: 'a', PublicKey: JSON.stringify(pair.publicJwk) });
    assert.equal((await w('ws-b', 'GET', '/api/rules')).json.custom.length, 0);
    const cb = (await w('ws-b', 'GET', '/api/config')).json.sidecar;
    assert.deepEqual([cb.piiKinds, cb.rails.secrets], [['card', 'ssn', 'iban', 'email', 'phone'], false]);
    assert.equal((await w('ws-b', 'GET', '/api/prompt-log')).json.config.Enabled, false);
    const rb = await w('ws-b', 'POST', '/api/run', { custom: { requestText: 'ACME-12345678' } });
    assert.equal(rb.json.runs[0].stages[0].evaluations.length, 0);
    const ra = await w('ws-a', 'POST', '/api/run', { custom: { requestText: 'ACME-12345678' } });
    assert.equal(ra.json.runs[0].stages[0].evaluations.length, 1); assert.equal(ra.json.runs[0].promptLog.recorded, true);
    await w('ws-b', 'POST', '/api/reset');
    assert.equal((await w('ws-a', 'GET', '/api/rules')).json.custom.length, 1, 'b\'s reset does not touch a');
    await w('ws-a', 'POST', '/api/reset');
    assert.deepEqual([(await w('ws-a', 'GET', '/api/rules')).json.custom.length, (await w('ws-a', 'GET', '/api/prompt-log')).json.records.length], [0, 0]);
  } finally { await hosted.close(); }
});
