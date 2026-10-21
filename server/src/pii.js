// PII rails: regex plus a check digit where one exists (Luhn for cards, mod 97 for IBAN-shaped values). No Presidio, no NLP.
// maskPii() is used everywhere a text leaves the detector, whether or not the PII rail is switched on: the decision
// log and API responses never carry a full SSN, card, IBAN, email or phone number.

import { INVISIBLE } from './sanitize.js';

export const luhn = (digits) => {
  let sum = 0; let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return digits.length > 0 && sum % 10 === 0;
};

export function ibanValid(raw) {
  const s = raw.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

const ssnValid = (s) => {
  const [a, g, n] = s.split(/[- ]/);
  return a !== '000' && a !== '666' && a[0] !== '9' && g !== '00' && n !== '0000';
};

// Order matters: a span claimed by an earlier kind is not offered to a later one (a card is not also a phone).
const KINDS = [
  { kind: 'card', severity: 'high', re: /(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])/g, ok: (m) => { const d = m.replace(/[ -]/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); },
    mask: (m) => { const d = m.replace(/[ -]/g, ''); return `**** **** **** ${d.slice(-4)}`; } },
  { kind: 'ssn', severity: 'high', re: /(?<![\w-])\d{3}([- ])\d{2}\1\d{4}(?![\w-])/g, ok: ssnValid, mask: (m) => `***-**-${m.slice(-4)}` },
  { kind: 'iban', severity: 'high', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, ok: ibanValid, mask: (m) => { const s = m.replace(/\s+/g, ''); return `${s.slice(0, 4)}****${s.slice(-2)}`; } },
  { kind: 'email', severity: 'medium', re: /\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b/g, ok: () => true, mask: (m) => { const [l, d] = m.split('@'); return `${l[0]}***@${d}`; } },
  { kind: 'phone', severity: 'medium', re: /(?<![\w-])(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}(?![\w-])/g, ok: () => true, mask: (m) => `***-***-${m.replace(/\D/g, '').slice(-4)}` },
];

// -> [{ kind, severity, start, end, mask }] sorted by start, non-overlapping
export function findPii(text) {
  const s = String(text ?? '');
  const spans = [];
  const overlaps = (a, b) => spans.some((x) => a < x.end && b > x.start);
  for (const k of KINDS) {
    for (const m of s.matchAll(k.re)) {
      const start = m.index; const end = start + m[0].length;
      if (overlaps(start, end) || !k.ok(m[0])) continue;
      spans.push({ kind: k.kind, severity: k.severity, start, end, mask: k.mask(m[0]) });
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

export function maskPii(text) {
  const s = String(text ?? '');
  // Find values on a copy with invisible characters removed (so "123-<ZWSP>45-6789" is found), then replace the
  // matching range of the ORIGINAL text, keeping every invisible character outside a value for revealText to show.
  const keep = []; let stripped = ''; let at0 = 0;
  for (const ch of s) {
    if (!INVISIBLE.test(ch)) { for (let k = 0; k < ch.length; k += 1) keep.push(at0 + k); stripped += ch; }
    at0 += ch.length;
  }
  let out = ''; let at = 0;
  for (const p of findPii(stripped)) {
    const start = keep[p.start]; const end = keep[p.end - 1] + 1;
    out += s.slice(at, start) + p.mask; at = end;
  }
  // Defence in depth for the logs: a run of nine or more digits that no rule recognised (a card that fails the Luhn
  // check, an SSN written without dashes) is still hidden, though it is not reported as a finding.
  return (out + s.slice(at)).replace(/\d{9,}/g, (d) => `${'*'.repeat(d.length - 4)}${d.slice(-4)}`);
}
