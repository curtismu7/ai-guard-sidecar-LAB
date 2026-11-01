// Your own gitleaks-format rules: the bounded TOML parser, the static regex check, the linear-time fallback, one bad rule refusing the
// whole paste, and every field of a rule changing behaviour (each proven by a mutant: ignore the field and a test here fails).
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { importToml, summarise, RULE_LIMITS } from '../src/rules.js';
import { parseToml, TOML_LIMITS } from '../src/toml.js';
import { checkRegex } from '../src/safeRegex.js';
import { detectUnit } from '../src/detectors.js';
import { maskTyped } from '../src/mask.js';
import { fakeSecrets } from './helpers.js';

const rule = (extra = '') => `[[rules]]\nid = "acme-ticket"\nregex = "ACME-[0-9]{8}"\n${extra}`;
const ok = (toml, existing = []) => { const r = importToml(toml, existing); assert.deepEqual(r.Errors, []); return r.Added; };
const refused = (toml, existing = []) => { const r = importToml(toml, existing); assert.ok(r.Errors.length, 'expected a refusal'); assert.deepEqual(r.Added, []); return r.Errors.join('\n'); };
const CFG = (rules) => ({ detector: { threshold: 0.9, benignLabels: ['benign', 'label_0', 'safe'] }, rails: { injection: false, regex_pii: false }, rules });
const finds = (rules, text) => detectUnit({ text }, CFG(rules));

test('a valid rule is accepted and matches; the summary never carries the pattern, keywords or allowlist text', () => {
  const [r] = ok(rule('keywords = ["acme"]\n[rules.allowlist]\nregexes = ["ACME-00000000"]\n'));
  assert.equal(r.id, 'cst-acme-ticket');
  assert.equal(r.spansOf('see ACME-12345678 now').length, 1);
  const s = JSON.stringify(summarise(r));
  assert.ok(!s.includes('ACME') && !s.includes('00000000') && !s.includes('regex'), s);
  assert.deepEqual(Object.keys(summarise(r)).sort(), ['allowlist', 'category', 'description', 'entropy', 'id', 'keywords', 'patternChars', 'secretGroup', 'severity']);
});

test('field: regex decides the match', () => {
  const [a] = ok(rule()); const [b] = ok('[[rules]]\nid = "acme-ticket"\nregex = "ZED-[0-9]{8}"\n');
  assert.equal(a.spansOf('ACME-12345678').length, 1); assert.equal(b.spansOf('ACME-12345678').length, 0);
});
test('field: id names the rule in the finding and in the mask marker, and is prefixed cst-', () => {
  const [r] = ok(rule());
  assert.equal(finds([r], 'ACME-12345678')[0].message, 'Your rule cst-acme-ticket matched');
  assert.equal(maskTyped('x ACME-12345678 y', [r]), 'x [masked:cst-acme-ticket] y');
});
test('field: keywords are a prefilter (case-insensitive); without the keyword the regex is not run', () => {
  const [r] = ok('[[rules]]\nid = "k"\nregex = "[0-9]{8}"\nkeywords = ["Acme"]\n');
  assert.equal(r.spansOf('acme 12345678').length, 1);
  assert.equal(r.spansOf('other 12345678').length, 0);
});
test('field: entropy ignores a low-entropy value', () => {
  const [r] = ok('[[rules]]\nid = "e"\nregex = "tok-[a-z0-9]{12}"\nentropy = 3.0\n');
  assert.equal(r.spansOf('tok-aaaaaaaaaaaa').length, 0);
  assert.equal(r.spansOf('tok-q7x2m9k4b1zp').length, 1);
});
test('field: secretGroup makes only that group the span', () => {
  const [r] = ok('[[rules]]\nid = "g"\nregex = "pass=([a-z0-9]{6,})"\nsecretGroup = 1\n');
  const text = 'pass=abc123xyz'; const [sp] = r.spansOf(text);
  assert.equal(text.slice(sp.start, sp.end), 'abc123xyz');
  const [w] = ok('[[rules]]\nid = "g"\nregex = "pass=([a-z0-9]{6,})"\n');
  assert.equal(text.slice(w.spansOf(text)[0].start, w.spansOf(text)[0].end), text);
});
test('field: allowlist regexes drop a matching value', () => {
  const [r] = ok(rule('[rules.allowlist]\nregexes = ["^ACME-0000"]\n'));
  assert.equal(r.spansOf('ACME-00001234').length, 0);
  assert.equal(r.spansOf('ACME-10001234').length, 1);
});
test('field: category and severity reach the finding; critical counts as high in the contract; defaults are secrets and high', () => {
  assert.deepEqual(finds(ok(rule()), 'ACME-12345678').map((d) => [d.category, d.severity]), [['secrets', 'high']]);
  assert.deepEqual(finds(ok(rule('category = "pii"\nseverity = "medium"\n')), 'ACME-12345678').map((d) => [d.category, d.severity]), [['pii', 'medium']]);
  assert.equal(finds(ok(rule('severity = "critical"\n')), 'ACME-12345678')[0].severity, 'high');
  assert.equal(finds(ok(rule('severity = "low"\n')), 'ACME-12345678')[0].severity, 'low');
});
test('field: description is shown back masked (a credential typed in it never survives)', () => {
  const k = fakeSecrets();
  const [r] = ok(rule(`description = "see ${k.ghp} please"\n`));
  assert.ok(!r.description.includes(k.ghp) && r.description.includes('see'), r.description);
});
test('every field has a validator: a wrong type or value refuses the whole paste', () => {
  for (const extra of ['entropy = "high"', 'entropy = 9', 'secretGroup = -1', 'secretGroup = 1.5', 'secretGroup = 3', 'category = "other"', 'severity = "urgent"', 'keywords = "acme"', 'keywords = [""]', `keywords = [${'"x",'.repeat(21)}]`, 'description = 5', 'bogus = 1', 'tags = []']) {
    assert.ok(refused(rule(`${extra}\n`)), extra);
  }
  assert.ok(refused('[[rules]]\nregex = "x"\n'), 'id required');
  assert.ok(refused('[[rules]]\nid = "x"\n'), 'regex required');
  for (const id of ['Bad Id!', '-x', 'x'.repeat(65), '']) assert.ok(refused(`[[rules]]\nid = "${id}"\nregex = "x"\n`), id);
  assert.ok(refused(rule('[rules.allowlist]\nregexes = [5]\n')));
  assert.ok(refused(rule('[rules.allowlist]\nwords = ["a"]\n')));
});

test('one bad rule refuses the whole paste: nothing is added and every refused rule is listed, one per line', () => {
  const toml = `${rule()}\n[[rules]]\nid = "two"\nregex = "(a+)+b"\n\n[[rules]]\nid = "three"\nregex = "ok[0-9]"\nseverity = "nope"\n`;
  const r = importToml(toml);
  assert.deepEqual(r.Added, []);
  assert.equal(r.Errors.length, 2);
  assert.match(r.Errors[0], /^rule 2 \(line \d+\)/); assert.match(r.Errors[1], /^rule 3 \(line \d+\)/);
});

test('duplicates and the cap refuse the whole request before anything is added', () => {
  const have = ok(rule());
  assert.match(refused(rule(), have), /already exists/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "a"\n[[rules]]\nid = "x"\nregex = "b"\n'), /already exists/);
  const many = Array.from({ length: RULE_LIMITS.rulesPerWorkspace }, (_v, i) => `[[rules]]\nid = "r${i}"\nregex = "q${i}"\n`).join('');
  assert.equal(ok(many).length, RULE_LIMITS.rulesPerWorkspace);
  assert.match(refused(`${many}[[rules]]\nid = "over"\nregex = "q"\n`), /at most|more than/);
  assert.match(refused(rule(), ok(many)), /at most/);
});

test('hostile TOML: size, lines, control characters, prototype keys, unsupported tables, odd values', () => {
  assert.match(refused(`#${'x'.repeat(TOML_LIMITS.bytes)}`), /over/);
  assert.match(refused('\n'.repeat(TOML_LIMITS.lines + 1)), /lines/);
  assert.match(refused(`[[rules]]\nid = "a\u0000b"\nregex = "x"\n`), /control/);
  assert.match(refused('[[rules]]\n__proto__ = 1\nid = "x"\nregex = "y"\n'), /unknown key/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "y"\n[constructor]\na = 1\n'), /not supported/);
  assert.match(refused('[__proto__]\n'), /not supported/);
  assert.ok(refused('[[rules]]\nid = "x"\nregex = ["a", ["b"]]\n'));
  assert.ok(refused('[[rules]]\nid = "x"\nid = "y"\nregex = "a"\n'));
  assert.ok(refused('[[rules]]\nid = "x\nregex = "a"\n'), 'unterminated string');
  assert.ok(refused('key = 5\n[[rules]]\nid = "x"\nregex = "a"\n'), 'unsupported top-level key');
  assert.ok(refused('nothing here'));
  assert.ok(refused(null) && refused(42));
  assert.equal(Object.getPrototypeOf(parseToml('[[rules]]\nid = "x"\n').rules[0].fields), null, 'fields hold no prototype');
  assert.equal({}.polluted, undefined);
  const deep = `[[rules]]\nid = "x"\nregex = "a"\nkeywords = [${'"k",'.repeat(60)}]\n`;
  assert.ok(refused(deep));
  assert.ok(importToml(`${'[[rules]]\n'.repeat(TOML_LIMITS.rules + 1)}`).Errors.length);
});

test('errors never echo what was typed: names, ids, values and the regex itself', () => {
  const k = fakeSecrets();
  const text = [`[[rules]]\nid = "${k.ghp}"\nregex = "(${k.password}+)+z"\nbogus_${k.password.replace(/-/g, '_')} = 1\n`, `[${k.ghp}]\nx = 1\n`, `${k.password} = 5\n`].join('\n');
  const out = refused(text);
  for (const s of [k.ghp, k.password, k.password.replace(/-/g, '_')]) assert.ok(!out.includes(s), `${s} echoed in: ${out}`);
});

test('static regex check refuses the shapes that backtrack: nesting, quantified alternation, backreferences, lookaround, long, many quantifiers', () => {
  for (const bad of ['(a+)+b', '(a*)*b', '(a|aa)+b', '(a|b)*c', '(?=a)b', '(?<!a)b', '(a)\\1', '\\k<x>', '(?<n>a)', 'a{1,1000}', 'a?a?a?a?a?a?a?aaaaaaa', '[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+[a-z]+x', 'a'.repeat(401), '', '(unbalanced', 'x)', '*a', '\\p{L}+']) {
    assert.ok(checkRegex(bad) !== null, `accepted ${bad.slice(0, 30)}`);
  }
  for (const good of ['ACME-[0-9]{8}', '(?i)tok[a-z0-9]{10,40}', '\\bsk_[A-Za-z0-9]{24}\\b', '(?:a|b)c', 'a+b']) assert.equal(checkRegex(good), null, good);
});

test('a pattern that matches the empty string, or does not compile, is refused', () => {
  assert.match(refused('[[rules]]\nid = "x"\nregex = "a*"\n'), /empty string/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "(a)?"\n'), /empty string/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "[z-a]"\n'), /compile/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "a"\n[rules.allowlist]\nregexes = ["b*"]\n'), /empty string/);
  assert.match(refused('[[rules]]\nid = "x"\nregex = "(a)"\nsecretGroup = 2\n'), /groups/);
});

test('V8 linear fallback: importing a rule arms it, so a backtracking pattern cannot hang the process (mutant: do not arm it)', () => {
  ok(rule()); // compiling a pasted rule arms the fallback (armLinearFallback is called inside compile; this test does not arm it itself)
  const t0 = Date.now();
  const bomb = new RegExp('(a+)+b');
  assert.equal(bomb.test(`${'a'.repeat(30)}!`), false);
  assert.ok(Date.now() - t0 < 1000, `took ${Date.now() - t0} ms: the fallback is not armed`);
});

test('matches per rule and per unit are capped, and a long input is handled in bounded time', () => {
  const [r] = ok('[[rules]]\nid = "many"\nregex = "x"\n');
  assert.equal(r.spansOf('x'.repeat(10000)).length, RULE_LIMITS.matchesPerRule);
  const t0 = Date.now();
  const [slow] = ok('[[rules]]\nid = "s"\nregex = "[a-z]+[a-z]+[a-z]+[a-z]+9"\n');
  slow.spansOf('a'.repeat(10000));
  assert.ok(Date.now() - t0 < 2000);
});

test('your rule masks text written with zero-width characters and fullwidth forms, and the percent-encoded form', () => {
  const [r] = ok(rule());
  const woven = [...'ACME-12345678'].join('​');
  assert.equal(maskTyped(`t ${woven} t`, [r]), 't [masked:cst-acme-ticket] t');
  const enc = [...'ACME-12345678'].map((c) => `%${c.charCodeAt(0).toString(16)}`).join('');
  assert.ok(!maskTyped(`t ${enc}`, [r]).toLowerCase().includes('%41%43'), 'percent-encoded form is masked in decoded form');
});
