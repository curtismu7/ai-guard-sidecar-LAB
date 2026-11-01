// Pasted rules: gitleaks rule format (a TOML subset) -> { Added[], Errors[] } (the shape of the console swagger's
// imodelAIGuardRuleImport {Toml, Added, Errors}, 2026-10-31, schema only). One bad rule refuses the WHOLE paste: nothing is
// added and Errors lists every refused rule, one per line (that behaviour is the swagger description's, a deck-adjacent claim).
// The TOML key names are a LAB READING of the gitleaks format: id, description, regex, keywords, entropy, secretGroup,
// category, severity and [rules.allowlist].regexes. Unknown keys refuse the paste.
// Every pasted regular expression is checked statically (safeRegex.js), must compile, must not match the empty string, and
// runs with V8's linear-time fallback armed (see armLinearFallback) on input of at most 10,000 characters.
import v8 from 'node:v8';
import { parseToml, TOML_LIMITS } from './toml.js';
import { checkRegex, splitInlineFlags } from './safeRegex.js';
import { fold, mapSpan } from './fold.js';
import { piiSpans } from './pii.js';
import { detectSecrets, shannon } from './secrets.js';
import { maskTyped } from './mask.js';
import { redactText } from './redaction.js';
import { revealText } from './sanitize.js';

export const RULE_LIMITS = { rulesPerWorkspace: 20, keywords: 20, keywordLength: 40, allowlist: 10, description: 200, id: 64, matchesPerRule: 20 };
export const CATEGORY_IDS = Object.freeze(['secrets', 'pii', 'prompt_injection', 'jailbreak', 'data_exfiltration', 'malicious_content']);
export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
const ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const KNOWN = ['id', 'description', 'regex', 'keywords', 'entropy', 'secretGroup', 'category', 'severity'];

// V8 runs a regular expression with backtracking, then, once it has backtracked too often, falls back to a linear-time engine
// (only for patterns without backreferences or lookaround, which safeRegex.js refuses). The flag is process-wide and is read when
// a regular expression is COMPILED, so it is armed before any pasted pattern is compiled. Mutation-tested in rules.test.js.
let armed = false;
export function armLinearFallback() {
  if (!armed) { v8.setFlagsFromString('--enable-experimental-regexp-engine-on-excessive-backtracks'); armed = true; }
}

const sensitive = (n) => piiSpans(n).length > 0 || detectSecrets(n).length > 0;
const isStrArray = (v, max) => Array.isArray(v) && v.length <= max && v.every((x) => typeof x === 'string');

// Field checks. Returns { problems, f, allow, n, line }. Errors never echo a pasted value.
function checkFields(raw, n) {
  const f = raw.fields; const problems = [...raw.errors];
  for (const k of Object.keys(f)) if (!KNOWN.includes(k)) problems.push(`unknown key (name hidden; supported: ${KNOWN.join(', ')})`);
  const idOk = typeof f.id === 'string' && ID.test(f.id.toLowerCase());
  if (!idOk) problems.push('id is required: lowercase letters, digits and dashes, up to 64');
  else if (sensitive(f.id)) problems.push('id looks like personal data or a secret: choose a plain name');
  if (typeof f.regex !== 'string') problems.push('regex is required (a string)');
  if (f.description !== undefined && (typeof f.description !== 'string' || f.description.length > RULE_LIMITS.description)) problems.push(`description must be text up to ${RULE_LIMITS.description} characters`);
  if (f.keywords !== undefined && (!isStrArray(f.keywords, RULE_LIMITS.keywords) || f.keywords.some((k) => !k || k.length > RULE_LIMITS.keywordLength))) problems.push(`keywords must be up to ${RULE_LIMITS.keywords} short strings`);
  if (f.entropy !== undefined && (typeof f.entropy !== 'number' || !(f.entropy >= 0 && f.entropy <= 8))) problems.push('entropy must be a number from 0 to 8');
  if (f.secretGroup !== undefined && (!Number.isInteger(f.secretGroup) || f.secretGroup < 0 || f.secretGroup > 9)) problems.push('secretGroup must be a whole number from 0 to 9');
  if (f.category !== undefined && !CATEGORY_IDS.includes(f.category)) problems.push(`category must be one of ${CATEGORY_IDS.join(', ')}`);
  if (f.severity !== undefined && !SEVERITIES.includes(f.severity)) problems.push('severity must be low, medium, high or critical');
  const a = raw.allowlist;
  if (a) {
    for (const k of Object.keys(a)) if (k !== 'regexes') problems.push('allowlist key (name hidden) is not supported (only regexes)');
    if (a.regexes !== undefined && !isStrArray(a.regexes, RULE_LIMITS.allowlist)) problems.push(`allowlist regexes must be up to ${RULE_LIMITS.allowlist} strings`);
  }
  return { n, line: raw.line, problems, f, allow: a?.regexes ?? [] };
}

// Compile one checked pattern. Never throws; returns { re } or { error } with a message that does not echo the pattern.
function compile(raw, what) {
  const why = checkRegex(raw);
  if (why) return { error: `${what} refused: ${why}` };
  const { source, flags } = splitInlineFlags(raw);
  armLinearFallback();
  let re;
  try { re = new RegExp(source, `${flags}g`); } catch { return { error: `${what} does not compile` }; }
  if (new RegExp(re.source, flags).test('')) return { error: `${what} matches the empty string` };
  return { re, groups: new RegExp(`${source}|`, flags).exec('').length - 1 };
}

// A compiled rule: spansOf(text) -> [{ start, end }] over the ORIGINAL text.
function build(b) {
  const f = b.f;
  const main = b.main.re; const allow = b.allowRes;
  const keywords = (f.keywords ?? []).map((k) => k.toLowerCase());
  const rule = {
    id: `cst-${f.id.toLowerCase()}`, description: revealText(redactText(maskTyped(f.description ?? '')), 200), category: f.category ?? 'secrets', severity: f.severity ?? 'high',
    keywords: keywords.length, entropy: f.entropy ?? 0, secretGroup: f.secretGroup ?? 0, allowlist: allow.length, patternChars: f.regex.length,
    spansOf(text) {
      const g = fold(text); const t = g.norm;
      if (keywords.length) { const low = t.toLowerCase(); if (!keywords.some((k) => low.includes(k))) return []; }
      const out = [];
      for (const m of t.matchAll(main)) {
        if (out.length >= RULE_LIMITS.matchesPerRule) break;
        const value = rule.secretGroup > 0 && m[rule.secretGroup] !== undefined ? m[rule.secretGroup] : m[0];
        if (rule.entropy && shannon(value) < rule.entropy) continue;
        if (allow.some((a) => a.test(value))) continue;
        const off = value === m[0] ? 0 : m[0].indexOf(value);
        const s = m.index + off;
        out.push(mapSpan(g, s, s + value.length));
      }
      return out;
    },
  };
  return rule;
}

// A copy of a rule that is safe to return: counts, never the pattern, keywords or allowlist text.
export const summarise = (r) => ({ id: r.id, description: r.description, category: r.category, severity: r.severity, keywords: r.keywords, entropy: r.entropy, secretGroup: r.secretGroup, allowlist: r.allowlist, patternChars: r.patternChars });

// existing: the workspace's current compiled rules. Returns { Added: [rule], Errors: [string] }; Added is empty whenever Errors is not.
export function importToml(toml, existing = []) {
  const out = { Added: [], Errors: [] };
  const parsed = parseToml(toml);
  out.Errors.push(...parsed.errors);
  if (!parsed.rules.length && !out.Errors.length) out.Errors.push('no [[rules]] found in the paste');
  const built = parsed.rules.map((r, i) => checkFields(r, i + 1));
  if (existing.length + built.length > RULE_LIMITS.rulesPerWorkspace) out.Errors.push(`a workspace holds at most ${RULE_LIMITS.rulesPerWorkspace} rules (${existing.length} now, ${built.length} pasted): nothing was added`);
  const seen = new Set(existing.map((r) => r.id));
  for (const b of built) {
    if (typeof b.f.id === 'string' && ID.test(b.f.id.toLowerCase())) {
      const id = `cst-${b.f.id.toLowerCase()}`;
      if (seen.has(id)) b.problems.push('a rule with this id already exists'); seen.add(id);
    }
    if (typeof b.f.regex === 'string') {
      b.main = compile(b.f.regex, 'regex');
      if (b.main.error) b.problems.push(b.main.error);
      else if (b.f.secretGroup !== undefined && b.f.secretGroup > b.main.groups) b.problems.push('secretGroup is higher than the number of groups in the regex');
    }
    b.allowRes = [];
    b.allow.forEach((r, k) => { const c = compile(r, `allowlist regex ${k + 1}`); if (c.error) b.problems.push(c.error); else b.allowRes.push(c.re); });
    if (b.problems.length) out.Errors.push(`rule ${b.n} (line ${b.line}): ${[...new Set(b.problems)].join('; ')}`);
  }
  if (out.Errors.length) return out; // the whole paste is refused: nothing is added
  out.Added = built.map(build);
  return out;
}

export { TOML_LIMITS };
