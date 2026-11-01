// Prompt logging, sealed to a key you hold: the server only seals; the round trip is opened with the BROWSER module (WebCrypto), the
// same code the page uses. Keys are built from raw bytes. Every setting of the config has a test that fails if the field is ignored.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { createPromptLog, PL_LIMITS, PL_STORE, PromptLogInvalid, capBytes } from '../src/promptlog.js';
import { parsePublicJwk, sealRecord } from '../src/seal.js';
import { openEnvelope } from '../../web/src/lib/seal.js';
import { fakeSecrets, x25519Pair } from './helpers.js';

const result = (over = {}) => ({ outcome: 'allow', blockedAt: null, reason: 'no_findings', ...over });
const cfgFor = (pair, over = {}) => ({ Enabled: true, PublicKey: JSON.stringify(pair.publicJwk), KeyID: 'key-1', ...over });
const rec = (pl, over = {}) => pl.record({ surface: 'llm', requestText: 'the prompt', upstreamText: 'the answer', caller: null, result: result(), categories: [], ...over });
const open = async (pair, record) => { const o = await openEnvelope(pair.privateJwk, record.envelope); return o.ok ? JSON.parse(o.plaintext) : o; };

test('round trip: sealed on the server, opened in the browser module with the private key; metadata stays readable', async () => {
  const pair = x25519Pair(); const pl = createPromptLog();
  pl.put(cfgFor(pair, { IncludeResponses: true }));
  const r = rec(pl, { caller: 'payments-agent', categories: ['pii'], result: result({ outcome: 'block', blockedAt: 'response', reason: 'threshold_met' }) });
  assert.equal(r.recorded, true);
  assert.deepEqual(await open(pair, r.record), { prompt: 'the prompt', response: 'the answer', truncated: false });
  assert.deepEqual([r.record.surface, r.record.caller, r.record.outcome, r.record.blockedAt, r.record.categories, r.record.kid], ['llm', 'payments-agent', 'block', 'response', ['pii'], 'key-1']);
  assert.ok(!JSON.stringify(pl.view()).includes('the prompt'), 'no plaintext anywhere in what the server returns');
});

test('a wrong key cannot open it; a tampered ciphertext, key id or record id cannot either (AES-GCM and the AAD)', async () => {
  const pair = x25519Pair(); const other = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair));
  const { record } = rec(pl);
  assert.equal((await openEnvelope(other.privateJwk, record.envelope)).ok, false);
  assert.equal((await openEnvelope(pair.privateJwk, record.envelope)).ok, true);
  const flip = (s) => `${s.slice(0, -2)}${s.slice(-2) === 'AA' ? 'BB' : 'AA'}`;
  for (const e of [{ ...record.envelope, ct: flip(record.envelope.ct) }, { ...record.envelope, kid: 'key-2' }, { ...record.envelope, rid: 'pl-99' }, { ...record.envelope, nonce: flip(record.envelope.nonce) }, { ...record.envelope, v: 'x' }]) {
    assert.equal((await openEnvelope(pair.privateJwk, e)).ok, false);
  }
});

test('two records of the same text differ (fresh ephemeral key and nonce each time)', () => {
  const pair = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair));
  const a = rec(pl).record.envelope; const b = rec(pl).record.envelope;
  assert.notEqual(a.ct, b.ct); assert.notEqual(a.epk, b.epk); assert.notEqual(a.nonce, b.nonce);
});

test('nothing is recorded without a public key, or when disabled; the reason is said', () => {
  const pl = createPromptLog(); const pair = x25519Pair();
  assert.deepEqual(rec(pl), { recorded: false, why: 'prompt logging is off' });
  pl.put({ Enabled: true });
  assert.match(rec(pl).why, /no public key/);
  pl.put(cfgFor(pair, { Enabled: false }));
  assert.match(rec(pl).why, /off/);
  assert.equal(pl.view().status.recording, false);
  pl.put(cfgFor(pair));
  assert.equal(pl.view().status.recording, true);
});

test('field Surfaces: only the ticked surfaces are recorded (none ticked = all)', () => {
  const pair = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair, { Surfaces: ['a2a'] }));
  assert.equal(rec(pl, { surface: 'llm' }).recorded, false);
  assert.equal(rec(pl, { surface: 'a2a' }).recorded, true);
  pl.put(cfgFor(pair, { Surfaces: [] }));
  assert.equal(rec(pl, { surface: 'llm' }).recorded, true);
});

test('field IncludeResponses: the response is sealed only when on, and never when the request was blocked (the upstream was not called)', async () => {
  const pair = x25519Pair(); const pl = createPromptLog();
  pl.put(cfgFor(pair)); assert.equal((await open(pair, rec(pl).record)).response, undefined);
  pl.put(cfgFor(pair, { IncludeResponses: true })); assert.equal((await open(pair, rec(pl).record)).response, 'the answer');
  assert.equal((await open(pair, rec(pl, { result: result({ outcome: 'block', blockedAt: 'request' }) }).record)).response, undefined);
});

test('field MaxBytes: the text is cut (prompt first, then the response) and the record says it was cut; whole characters only', async () => {
  const pair = x25519Pair(); const pl = createPromptLog();
  pl.put(cfgFor(pair, { MaxBytes: PL_LIMITS.minBytes, IncludeResponses: true }));
  const long = 'é'.repeat(300); // 2 bytes each
  const a = await open(pair, rec(pl, { requestText: long, upstreamText: 'tail' }).record);
  assert.equal(a.truncated, true); assert.ok(Buffer.byteLength(a.prompt) <= PL_LIMITS.minBytes); assert.ok(!a.prompt.includes('�')); assert.equal(a.response, undefined);
  const b = await open(pair, rec(pl, { requestText: 'p'.repeat(250), upstreamText: 'r'.repeat(100) }).record);
  assert.equal(b.truncated, true); assert.equal(b.prompt.length, 250); assert.equal(b.response.length, PL_LIMITS.minBytes - 250);
  pl.put(cfgFor(pair, { MaxBytes: 0 }));
  assert.equal((await open(pair, rec(pl, { requestText: 'x'.repeat(PL_LIMITS.defaultMaxBytes + 5) }).record)).prompt.length, PL_LIMITS.defaultMaxBytes);
  assert.deepEqual(capBytes('abc', 2), { text: 'ab', cut: true });
  for (const bad of [-1, 1, PL_LIMITS.minBytes - 1, PL_LIMITS.maxBytes + 1, 2.5, '300', null]) assert.throws(() => pl.put(cfgFor(pair, { MaxBytes: bad })), /refused/, String(bad));
});

test('field KeyID: records name the key they were sealed to; after a rotation old records still open with the old key', async () => {
  const k1 = x25519Pair(); const k2 = x25519Pair(); const pl = createPromptLog();
  pl.put(cfgFor(k1, { KeyID: 'key-1' })); const old = rec(pl).record;
  pl.put(cfgFor(k2, { KeyID: 'key-2' })); const fresh = rec(pl).record;
  assert.deepEqual([old.kid, fresh.kid, old.envelope.kid, fresh.envelope.kid], ['key-1', 'key-2', 'key-1', 'key-2']);
  assert.equal((await open(k1, old)).prompt, 'the prompt'); assert.equal((await open(k2, fresh)).prompt, 'the prompt');
  assert.equal((await openEnvelope(k2.privateJwk, old.envelope)).ok, false);
  for (const bad of ['', 'a b', 'x'.repeat(65), 'a|b', 5]) assert.throws(() => pl.put(cfgFor(k1, { KeyID: bad })), /refused/, String(bad));
  assert.throws(() => pl.put({ Enabled: true, PublicKey: JSON.stringify(k1.publicJwk) }), /refused/, 'a key needs a KeyID');
});

test('field Enabled and the settings as a whole: a refused update changes nothing; unknown fields and wrong types are refused', () => {
  const pair = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair, { MaxBytes: 512 }));
  const before = JSON.stringify(pl.view().config);
  for (const bad of [{ ...cfgFor(pair), Enabled: 'yes' }, { ...cfgFor(pair), extra: 1 }, { ...cfgFor(pair), Surfaces: ['nope'] }, { ...cfgFor(pair), IncludeResponses: 1 }, null, [], 'x', { ...cfgFor(pair), PublicKey: '{"kty":"RSA"}' }]) {
    assert.throws(() => pl.put(bad), /refused/);
    assert.equal(JSON.stringify(pl.view().config), before, 'unchanged');
  }
  try { pl.put({ Enabled: 'x', KeyID: '!' }); } catch (e) { assert.ok(e instanceof PromptLogInvalid); assert.deepEqual(e.errors.map((x) => x.field).sort(), ['Enabled', 'KeyID']); }
});

test('the server never takes a private key: a JWK with d is refused, so are bad and low-order public keys', () => {
  const pair = x25519Pair();
  assert.throws(() => parsePublicJwk(JSON.stringify(pair.privateJwk)), /PRIVATE/);
  assert.throws(() => parsePublicJwk({ ...pair.publicJwk, d: 'x' }), /PRIVATE/);
  assert.throws(() => parsePublicJwk({ kty: 'OKP', crv: 'Ed25519', x: pair.publicJwk.x }), /X25519/);
  assert.throws(() => parsePublicJwk({ ...pair.publicJwk, x: 'AAAA' }), /32 bytes/);
  assert.throws(() => parsePublicJwk({ ...pair.publicJwk, x: Buffer.alloc(32).toString('base64url') }), /usable/, 'the all-zero low-order point');
  assert.throws(() => parsePublicJwk('x'.repeat(2001)), /too long/);
  assert.throws(() => parsePublicJwk('{nope'), /not JSON/);
  const pl = createPromptLog();
  assert.throws(() => pl.put({ Enabled: true, KeyID: 'k', PublicKey: JSON.stringify(pair.privateJwk) }), /refused/);
  assert.throws(() => sealRecord({ publicKey: parsePublicJwk(pair.publicJwk), keyId: 'a|b', recordId: 'r', plaintext: 'x' }), /plain names/);
});

test('the server source holds no decrypt code and no private-key handling', () => {
  const dir = new URL('../src/', import.meta.url).pathname;
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    const src = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.ok(!/createDecipheriv|privateDecrypt|subtle\.decrypt|\.decrypt\(/.test(src), `${f} can decrypt`);
  }
});

test('the ring: at most the cap is kept, the oldest goes first, and the drop is counted, never silent', () => {
  const pair = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair));
  for (let i = 0; i < PL_STORE.maxRecords + 3; i += 1) rec(pl);
  const v = pl.view();
  assert.equal(v.records.length, PL_STORE.maxRecords); assert.equal(v.dropped, 3);
  assert.equal(v.records[0].id, `pl-${PL_STORE.maxRecords + 3}`, 'newest first'); assert.equal(v.records.at(-1).id, 'pl-4');
  pl.reset();
  assert.deepEqual([pl.view().records.length, pl.view().dropped, pl.view().config.Enabled, pl.view().config.PublicKey], [0, 0, false, '']);
});

test('what is sealed is the raw text, and only it: a typed credential never appears in the metadata', async () => {
  const pair = x25519Pair(); const pl = createPromptLog(); pl.put(cfgFor(pair)); const k = fakeSecrets();
  const { record } = rec(pl, { requestText: `my password is ${k.password} and ${k.ghp}` });
  assert.ok(!JSON.stringify({ ...record, envelope: undefined }).includes(k.password));
  assert.ok(!JSON.stringify(record).includes(k.ghp), 'not in the envelope either (only ciphertext)');
  assert.ok((await open(pair, record)).prompt.includes(k.password), 'but the key holder gets it back');
});
