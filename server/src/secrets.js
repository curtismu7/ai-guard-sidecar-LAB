// A small set of secret and credential detectors written for this app (twelve): each has a keyword prefilter, an optional
// entropy floor, an allowlist and a value group, the same fields a pasted gitleaks-format rule can carry. These are the
// app's own illustrative examples. Ping's deck says the release ships 364 secret and credential detectors (slide 53); this
// file does not hold or copy that set or any third-party rule list. The prefixes and shapes are public conventions.
// Test credentials are built at run time (never a literal in the repository) and each has a near miss that must not match.
import { createHash } from 'node:crypto';
import { fold, mapSpan } from './fold.js';

export function shannon(s) {
  if (!s) return 0;
  const counts = new Map(); for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0; for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

const B62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
// Deterministic high-entropy filler for samples: same seed, same string.
export function filler(n, seed, alphabet = B62) {
  let out = ''; let i = 0;
  while (out.length < n) { const h = createHash('sha256').update(`${seed}:${i++}`).digest(); for (const b of h) { if (out.length < n) out += alphabet[b % alphabet.length]; } }
  return out;
}
const j = (...p) => p.join('');

export const SECRET_DETECTORS = [
  { id: 'lab-aws-access-key-id', description: 'AWS-style access key id (AKIA/ASIA prefix, 20 characters)', keywords: ['akia', 'asia'], pattern: '\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('AKI', 'A', filler(16, 'aws', UP)), nearMiss: () => j('AKI', 'A', filler(15, 'aws', UP)) },
  { id: 'lab-github-token', description: 'GitHub personal access token (ghp_ prefix, 36 characters)', keywords: ['ghp_'], pattern: '\\bghp_[A-Za-z0-9]{36}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('gh', 'p_', filler(36, 'gh')), nearMiss: () => j('gh', 'p_', filler(20, 'gh')) },
  { id: 'lab-slack-token', description: 'Slack token (xox prefix)', keywords: ['xox'], pattern: '\\bxox[abeprs]-[A-Za-z0-9-]{10,48}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('xo', 'xb-', filler(24, 'slack')), nearMiss: () => j('xo', 'xb-', filler(5, 'slack')) },
  { id: 'lab-payment-secret-key', description: 'Payment-provider live secret key (sk_live_ / rk_live_ prefix)', keywords: ['_live_'], pattern: '\\b[sr]k_live_[A-Za-z0-9]{24,99}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('sk', '_live_', filler(28, 'pay')), nearMiss: () => j('sk', '_test_', filler(28, 'pay')) },
  { id: 'lab-private-key-block', description: 'PEM private key block (header, body up to 4000 characters, footer or end of text)', keywords: ['private key'], pattern: '-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\\s\\S]{0,4000}?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('-----BEGIN ', 'RSA PRIVATE', ' KEY-----'), nearMiss: () => j('-----BEGIN ', 'PUBLIC', ' KEY-----') },
  { id: 'lab-jwt', description: 'JSON Web Token (three base64url parts, header and claims start eyJ)', keywords: ['eyj'], pattern: '\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('ey', 'J', filler(20, 'h'), '.ey', 'J', filler(20, 'c'), '.', filler(24, 's')), nearMiss: () => j('ey', 'J', filler(20, 'h'), '.', filler(20, 'c')) },
  { id: 'lab-google-api-key', description: 'Google-style API key (AIza prefix, 39 characters)', keywords: ['aiza'], pattern: '\\bAIza[0-9A-Za-z_-]{35}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('AI', 'za', filler(35, 'goog')), nearMiss: () => j('AI', 'za', filler(20, 'goog')) },
  { id: 'lab-npm-token', description: 'npm access token (npm_ prefix, 36 characters)', keywords: ['npm_'], pattern: '\\bnpm_[A-Za-z0-9]{36}\\b', flags: '', entropy: 0, allowlist: [], valueGroup: 0,
    sample: () => j('np', 'm_', filler(36, 'npm')), nearMiss: () => j('np', 'm_', filler(12, 'npm')) },
  { id: 'lab-url-password', description: 'Password inside a connection URL (scheme://user:password@host)', keywords: ['://'], pattern: '\\b[a-z][a-z0-9+.-]{1,15}://[^\\s:@/]{1,40}:([^\\s@/]{6,60})@[^\\s/]{1,80}', flags: '', entropy: 2.5, allowlist: ['^(?:password|changeme|example|x+|\\*+)$'], valueGroup: 1,
    sample: () => j('post', 'gres://app:', filler(18, 'url'), '@db.example:5432/orders'), nearMiss: () => 'postgres://app:changeme@db.example:5432/orders' },
  { id: 'lab-bearer-token', description: 'Bearer token in an Authorization header', keywords: ['bearer'], pattern: '\\bbearer\\s+([A-Za-z0-9._~+/=-]{20,200})', flags: 'i', entropy: 3.5, allowlist: [], valueGroup: 1,
    sample: () => j('Bear', 'er ', filler(32, 'bt')), nearMiss: () => j('Bear', 'er ', 'a'.repeat(32)) },
  { id: 'lab-generic-assignment', description: 'A secret-looking name assigned a high-entropy value (api_key=, secret:, token=, password=)', keywords: ['key', 'secret', 'token', 'passw', 'pwd'], pattern: '\\b(?:api[_-]?key|secret|token|passw(?:or)?d|pwd)\\s*[:=]\\s*["\']?([A-Za-z0-9/+=_-]{12,80})["\']?', flags: 'i', entropy: 3.2, allowlist: ['^(?:your|example|changeme|placeholder|xxx|\\$\\{)'], valueGroup: 1,
    sample: () => j('api_', 'key = "', filler(30, 'ga'), '"'), nearMiss: () => j('api_', 'key = "', 'your_api_key_goes_here', '"') },
  { id: 'lab-openai-style-key', description: 'sk- style API key (sk- then 20 or more characters including a digit)', keywords: ['sk-'], pattern: '\\bsk-(?=[A-Za-z0-9_-]*\\d)[A-Za-z0-9_-]{20,}', flags: '', entropy: 3, allowlist: [], valueGroup: 0,
    sample: () => j('sk', '-', filler(40, 'oa')), nearMiss: () => j('sk', '-', 'abc') },
];

const COMPILED = SECRET_DETECTORS.map((d) => ({ d, re: new RegExp(d.pattern, `${d.flags}dg`), allow: d.allowlist.map((a) => new RegExp(a, 'i')) }));

// Spans of the ORIGINAL text: [{ rule, start, end }]. Built-in patterns are fixed and linear, so they run in-process.
export function detectSecrets(raw) {
  const f = fold(raw); const text = f.norm; const low = text.toLowerCase();
  const out = [];
  for (const { d, re, allow } of COMPILED) {
    if (d.keywords.length && !d.keywords.some((k) => low.includes(k))) continue;
    for (const m of text.matchAll(re)) {
      const [s, e] = m.indices[d.valueGroup] || m.indices[0];
      const value = text.slice(s, e);
      if (d.entropy && shannon(value) < d.entropy) continue;
      if (allow.some((a) => a.test(value))) continue;
      out.push({ rule: d.id, ...mapSpan(f, s, e) });
    }
  }
  return out;
}
