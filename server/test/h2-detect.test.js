// H2 2026 release, detection side: personal-data kinds (selectable, with check digits), the bundled secret detectors, masking of
// anything typed. All values that look like credentials are assembled at run time. Ping's numbers (23 kinds, 364 detectors) are
// never asserted as the app's own: the app's counts come from its engine.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { LEGACY_KINDS, PII_KIND_IDS, SAMPLES, findPii, maskPii, piiCatalogue } from '../src/pii.js';
import { SECRET_DETECTORS, detectSecrets, filler } from '../src/secrets.js';
import { maskTyped } from '../src/mask.js';
import { fold, percentDecode } from '../src/fold.js';
import { redactText } from '../src/redaction.js';
import { DEFAULT_RAILS, detectUnit } from '../src/detectors.js';
import { safeSnippet, validateSidecarConfig, DEFAULT_SIDECAR_CONFIG } from '../src/sidecar.js';
import { fakeSecrets } from './helpers.js';

const D = { threshold: 0.9, benignLabels: ['benign', 'label_0', 'safe'] };
const CFG = (over = {}) => ({ detector: D, rails: { injection: true, regex_pii: true }, ...over });

test('every kind: its valid sample is found by that kind alone, its near miss is not (proofs computed from the check digit)', () => {
  assert.deepEqual(piiCatalogue().map((k) => k.id), PII_KIND_IDS);
  for (const id of PII_KIND_IDS) {
    assert.ok(SAMPLES[id], `no sample for ${id}`);
    assert.deepEqual(findPii(SAMPLES[id].valid(), [id]).map((p) => p.kind), [id], `${id} valid`);
    assert.deepEqual(findPii(SAMPLES[id].nearMiss(), [id]), [], `${id} near miss`);
  }
});

// The samples above are computed from the validators themselves, so a wrong formula would still agree with itself. These
// check the formulas against independent references and published example values.
test('check digits against independent references and published examples', () => {
  const aba = (d) => { const w = [3, 7, 1, 3, 7, 1, 3, 7, 1]; return [...d].reduce((a, c, i) => a + w[i] * +c, 0) % 10 === 0; };
  let seed = 7; let agree = 0;
  for (let i = 0; i < 400; i += 1) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    const d = `0${String(seed % 1000).padStart(3, '0')}${String(Math.floor(seed / 1000) % 100000).padStart(5, '0')}`.slice(0, 9);
    const checksum = aba(d); const prefix = +d.slice(0, 2);
    assert.equal(findPii(d, ['aba-routing']).length === 1, checksum && prefix >= 1 && prefix <= 12, d);
    if (checksum) agree += 1;
  }
  assert.ok(agree > 10, 'the reference found valid numbers to compare');
  assert.equal(findPii('12345678Z', ['es-dni']).length, 1, 'the widely documented DNI example');
  assert.equal(findPii('12345678A', ['es-dni']).length, 0);
  assert.equal(findPii('943 476 5919', ['health-id']).length, 1, 'the published NHS number example');
  assert.equal(findPii('943 476 5918', ['health-id']).length, 0);
  assert.equal(findPii('130-692-544', ['ca-sin']).length, 1, 'a commonly cited valid SIN (Luhn sum 40)');
  assert.equal(findPii('130-692-545', ['ca-sin']).length, 0);
  assert.equal(findPii('4111 1111 1111 1111', ['card']).length, 1);
  assert.equal(findPii('4111 1111 1111 1112', ['card']).length, 0);
  assert.equal(findPii('GB82 WEST 1234 5698 7654 32', ['iban']).length, 1);
  assert.equal(findPii('GB82 WEST 1234 5698 7654 33', ['iban']).length, 0);
});

test('the catalogue sits in the deck families and keeps the original five as the default selection', () => {
  const cat = piiCatalogue();
  for (const k of cat) assert.ok(['national', 'financial', 'health', 'contact'].includes(k.group), k.id);
  assert.deepEqual(cat.filter((k) => k.legacy).map((k) => k.id), LEGACY_KINDS);
  assert.deepEqual(DEFAULT_SIDECAR_CONFIG.piiKinds, LEGACY_KINDS);
  assert.ok(PII_KIND_IDS.length > LEGACY_KINDS.length && PII_KIND_IDS.length < 23, 'the app ships its own smaller set, not Ping\'s 23');
});

test('selection: a kind that is off raises no finding, a kind that is on does; the default is the original five', () => {
  const text = (id) => SAMPLES[id].valid();
  for (const id of PII_KIND_IDS) {
    const off = detectUnit({ text: text(id) }, CFG({ piiKinds: PII_KIND_IDS.filter((k) => k !== id) })).filter((d) => d.category === 'pii');
    const on = detectUnit({ text: text(id) }, CFG({ piiKinds: [id] })).filter((d) => d.category === 'pii');
    assert.ok(on.length === 1 && on[0].message.includes(id), `${id} on`);
    assert.ok(!off.some((d) => d.message.includes(id)), `${id} off`);
  }
  // no piiKinds in the config at all (the original shape): the original five only
  assert.equal(detectUnit({ text: SAMPLES['es-dni'].valid() }, CFG()).length, 0);
  assert.equal(detectUnit({ text: SAMPLES.ssn.valid() }, CFG()).length, 1);
  assert.equal(detectUnit({ text: SAMPLES.ssn.valid() }, CFG({ piiKinds: [] })).length, 0, 'an empty selection finds nothing');
});

test('the selection decides only what is FOUND: every kind is still masked in anything shown', () => {
  for (const id of PII_KIND_IDS) {
    const v = SAMPLES[id].valid();
    const shown = maskPii(`please use ${v} today`);
    assert.ok(!shown.includes(v.replace(/ /g, '')) && !shown.includes(v), `${id} leaked into ${shown}`);
  }
});

test('severity: a national id raises a high finding, a date of birth a medium one', () => {
  assert.equal(detectUnit({ text: SAMPLES['es-dni'].valid() }, CFG({ piiKinds: ['es-dni'] }))[0].severity, 'high');
  assert.equal(detectUnit({ text: SAMPLES.dob.valid() }, CFG({ piiKinds: ['dob'] }))[0].severity, 'medium');
});

test('values written to evade: fullwidth digits, interleaved zero-width and format characters, replacement characters', () => {
  const v = SAMPLES.ssn.valid();
  const full = [...v].map((c) => (/\d/.test(c) ? String.fromCharCode(c.charCodeAt(0) + 0xFEE0) : c)).join('');
  assert.equal(findPii(fold(full).norm, ['ssn']).length, 1, 'fullwidth');
  const inter = [...v].join('​️⁠�­');
  assert.equal(findPii(fold(inter).norm, ['ssn']).length, 1, 'interleaved');
  assert.ok(!maskPii(`x ${inter} y`).includes('6789​') && maskPii(`x ${inter} y`).includes('***-**-6789'), 'masked in the original');
  assert.ok(!maskTyped(full).includes('６'), 'fullwidth is masked');
});

test('fold: NFKC, drops default-ignorable, Cf, U+FFFD and lone surrogates, collapses whitespace, keeps an offset map', () => {
  const f = fold('a​b�c  \n d\uD800e');
  assert.equal(f.norm, 'abc de');
  assert.equal(f.starts.length, f.norm.length);
  assert.equal(fold('ＡＢＣ１２３').norm, 'ABC123');
});

test('percent-encoding is decoded up to three rounds, and no further', () => {
  assert.equal(percentDecode('%2534%2532'), '42');
  assert.equal(percentDecode('%25252534'), '%34', 'a fourth level is left alone');
  assert.equal(percentDecode('100%'), '100%');
  assert.equal(percentDecode('%zz%41'), '%zzA');
  const card = SAMPLES.card.valid().replace(/ /g, '');
  const enc = [...card].map((c) => `%${c.charCodeAt(0).toString(16)}`).join('');
  assert.match(maskTyped(`pay ${enc}`), /\*\*\*\* \*\*\*\* \*\*\*\* 1111/, 'a percent-encoded card is masked in its decoded form');
  const enc2 = [...card].map((c) => `%25${c.charCodeAt(0).toString(16)}`).join('');
  assert.match(maskTyped(`pay ${enc2}`), /\*\*\*\* \*\*\*\* \*\*\*\* 1111/, 'double-encoded too');
  const k = fakeSecrets();
  const encSecret = [...k.ghp].map((c) => `%${c.charCodeAt(0).toString(16)}`).join('');
  assert.equal(maskTyped(`t=${encSecret}`), 't=[masked:lab-github-token]', 'an encoded secret is masked in its decoded form');
  assert.equal(maskTyped('100%25 sure'), '100%25 sure', 'text with nothing to find is returned as typed');
});

test('bundled secret detectors: each sample is found by exactly its rule, each near miss is not, computed now', () => {
  const ids = SECRET_DETECTORS.map((d) => d.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const d of SECRET_DETECTORS) {
    assert.deepEqual([...new Set(detectSecrets(`here: ${d.sample()} done`).map((h) => h.rule))], [d.id], `${d.id} sample`);
    assert.deepEqual(detectSecrets(`here: ${d.nearMiss()} done`), [], `${d.id} near miss`);
  }
});

test('secret detectors: entropy floor, allowlist and value group are honoured (mutation-proven)', () => {
  const generic = SECRET_DETECTORS.find((d) => d.id === 'lab-generic-assignment');
  assert.equal(detectSecrets(`api_key = "${'a'.repeat(30)}"`).length, 0, 'low entropy value is not a secret');
  assert.equal(detectSecrets(`api_key = "your_api_key_goes_here"`).length, 0, 'allowlisted placeholder');
  const s = generic.sample(); const hit = detectSecrets(s)[0];
  assert.equal(s.slice(hit.start, hit.end), s.slice(s.indexOf('"') + 1, s.lastIndexOf('"')), 'only the value group is the span');
});

test('the secrets rail is off by default; on, a bundled secret raises a high finding in its own category; your rules need no rail', () => {
  assert.equal(DEFAULT_RAILS.secrets, false);
  const s = SECRET_DETECTORS[0].sample();
  assert.equal(detectUnit({ text: s }, CFG()).length, 0, 'rail absent');
  assert.equal(detectUnit({ text: s }, CFG({ rails: { injection: true, regex_pii: true, secrets: false } })).length, 0, 'rail off');
  const on = detectUnit({ text: s }, CFG({ rails: { injection: true, regex_pii: true, secrets: true } }));
  assert.deepEqual(on.map((d) => [d.category, d.severity]), [['secrets', 'high']]);
  assert.ok(on[0].message.includes('lab-aws-access-key-id') && !on[0].message.includes(s), 'names the rule, not the value');
});

test('config: piiKinds and the secrets rail are optional, validated, and left-out parts are not an error', () => {
  const base = { detector: D, rails: { injection: true, regex_pii: true } };
  assert.equal(validateSidecarConfig(base).piiKinds, undefined);
  assert.deepEqual(validateSidecarConfig({ ...base, piiKinds: ['phone', 'ssn'] }).piiKinds, ['ssn', 'phone'], 'canonical order');
  for (const bad of [['nope'], ['ssn', 'ssn'], 'ssn', [1], [{}], PII_KIND_IDS.concat('ssn'), ['__proto__']]) assert.throws(() => validateSidecarConfig({ ...base, piiKinds: bad }), /piiKinds/);
  assert.throws(() => validateSidecarConfig({ ...base, rails: { injection: true } }), /rails must have exactly/);
  assert.throws(() => validateSidecarConfig({ ...base, rails: { injection: true, regex_pii: true, secrets: 'yes' } }), /boolean/);
  assert.throws(() => validateSidecarConfig({ ...base, extra: 1 }), /config must have exactly/);
});

test('masking typed credentials: every shape from the review lessons', () => {
  const k = fakeSecrets();
  const shapes = [
    `my password is ${k.password}`, `pw: ${k.password}`, `the passcode = ${k.password}`,
    `https://bob:${k.password}@host.example/x`, `Authorization: token ${k.ghp}`, `Authorization: Bearer ${k.ghp}`,
    `{"api_key":"${k.password}"}`, `user=bob&password=${k.password}&x=1`, `x_token=${k.password};`, `${k.aws}`, `${k.ghp}`, `${k.pem}\nMIIEvAIBADANBgkq\n-----END RSA PRIVATE KEY-----`,
  ];
  for (const t of shapes) {
    const out = safeSnippet(t);
    for (const secret of [k.password, k.ghp, k.aws, 'MIIEvAIBADANBgkq']) assert.ok(!out.includes(secret), `${JSON.stringify(t.slice(0, 30))} leaked into ${out}`);
  }
  // zero-width characters interleaved inside a bundled-detector credential
  const woven = [...k.ghp].join('​');
  assert.ok(!maskTyped(woven).includes(k.ghp.slice(0, 12)), 'interleaved zero-width');
});

test('mask BEFORE truncating: a secret that straddles the cut is not half shown', () => {
  const k = fakeSecrets();
  const text = `${'a '.repeat(90)}${k.ghp} tail`; // the credential starts at 180, twenty characters before the 200-character cut
  const out = safeSnippet(text);
  assert.ok(out.length <= 800);
  assert.ok(!out.includes(k.ghp.slice(0, 12)), `a prefix survived: ${out.slice(-60)}`);
  assert.ok(out.includes('[masked:lab-github'), 'the credential was replaced by its marker before the cut (the marker itself may be cut)');
  assert.match(redactText(`note ${k.ghp}`), /note/);
});

test('hostile input stays bounded: long runs, many matches, near-pattern text', () => {
  const big = '0'.repeat(10000);
  for (const t of [big, '4'.repeat(10000), `${'a-'.repeat(5000)}`, ' '.repeat(10000), 'AKIA'.repeat(2500), '%'.repeat(10000), `${'ey'.repeat(2000)}J.`, '1 '.repeat(5000)]) {
    const t0 = Date.now(); safeSnippet(t); detectUnit({ text: t }, CFG({ piiKinds: PII_KIND_IDS, rails: { injection: true, regex_pii: true, secrets: true } }));
    assert.ok(Date.now() - t0 < 2000, 'bounded');
  }
});

test('filler is deterministic and the right length', () => {
  assert.equal(filler(30, 'x'), filler(30, 'x'));
  assert.equal(filler(30, 'x').length, 30);
});
