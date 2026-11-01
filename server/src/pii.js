// PII rails: regex plus a check digit where one exists (Luhn for cards, mod 97 for IBAN-shaped values). No Presidio, no NLP.
// maskPii() is used everywhere a text leaves the detector, whether or not the PII rail is switched on and whatever kinds are
// selected: the decision log and API responses never carry a full SSN, card, IBAN, email or phone number, nor any of the
// other kinds below.
//
// Kinds. The first five are the original rail (and the default selection). The other six are this app's own illustrative
// additions, written here from public formats: they are NOT Ping's list. Ping's deck says the release goes from 5 to 23
// kinds (slide 53); this file does not reproduce or guess that list. Each numeric kind has a real check digit, or a
// structural check where no check digit exists, and a valid sample and a near-miss sample computed at run time.

import { fold, mapSpan } from './fold.js';

export const luhn = (digits) => {
  let sum = 0; let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return digits.length > 0 && sum % 10 === 0;
};

const mod97 = (s) => {
  let rem = 0;
  for (const ch of s) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rem;
};

export function ibanValid(raw) {
  const s = raw.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  return mod97(s.slice(4) + s.slice(0, 4)) === 1;
}

const ssnValid = (s) => {
  const [a, g, n] = s.split(/[- ]/);
  return a !== '000' && a !== '666' && a[0] !== '9' && g !== '00' && n !== '0000';
};

// US routing number: 3-7-1 weighted sum, and a Federal Reserve prefix range.
export const abaValid = (d) => /^\d{9}$/.test(d)
  && (3 * (+d[0] + +d[3] + +d[6]) + 7 * (+d[1] + +d[4] + +d[7]) + (+d[2] + +d[5] + +d[8])) % 10 === 0
  && (() => { const p = +d.slice(0, 2); return (p >= 1 && p <= 12) || (p >= 21 && p <= 32) || (p >= 61 && p <= 72) || p === 80; })();
const abaCheckDigit = (eight) => { for (let c = 0; c < 10; c += 1) if (abaValid(`${eight}${c}`)) return c; return -1; };

// NHS-number-shaped (mod 11, weights 10..2). Calling it a "health id" is this app's reading of a published format.
const mod11Check = (nine) => { let s = 0; for (let i = 0; i < 9; i += 1) s += (10 - i) * +nine[i]; const c = 11 - (s % 11); return c === 11 ? 0 : c; };
export const healthIdValid = (d) => /^\d{10}$/.test(d) && mod11Check(d.slice(0, 9)) !== 10 && mod11Check(d.slice(0, 9)) === +d[9];

const DNI_LETTERS = 'TRWAGMYFPDXBNJZSQVHLCKE';
const dniLetter = (n8) => DNI_LETTERS[Number(n8) % 23];
const calendarValid = (y, m, d) => { const dt = new Date(Date.UTC(y, m - 1, d)); return y >= 1900 && y <= 2100 && dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d; };

const digitsOf = (s) => s.replace(/\D/g, '');
const hide = (kind) => () => `[${kind} masked]`;

// Order matters: a span claimed by an earlier kind is not offered to a later one (a card is not also a phone).
// `group` is the deck's family (national identifiers, financial, health, contact); `validation` says what is checked.
const KINDS = [
  { kind: 'card', label: 'Payment card number', group: 'financial', validation: 'length 13 to 19 and the Luhn check digit', severity: 'high', re: /(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])/g, ok: (m) => { const d = m.replace(/[ -]/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); },
    mask: (m) => { const d = m.replace(/[ -]/g, ''); return `**** **** **** ${d.slice(-4)}`; } },
  { kind: 'ssn', label: 'SSN-shaped national id', group: 'national', validation: 'structure (area, group and serial rules; no check digit exists)', severity: 'high', re: /(?<![\w-])\d{3}([- ])\d{2}\1\d{4}(?![\w-])/g, ok: ssnValid, mask: (m) => `***-**-${m.slice(-4)}` },
  { kind: 'iban', label: 'IBAN', group: 'financial', validation: 'ISO 7064 mod 97', severity: 'high', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, ok: ibanValid, mask: (m) => { const s = m.replace(/\s+/g, ''); return `${s.slice(0, 4)}****${s.slice(-2)}`; } },
  { kind: 'aba-routing', label: 'US routing number', group: 'financial', validation: '3-7-1 weighted check digit and the Federal Reserve prefix range', severity: 'high', re: /(?<![\w-])\d{9}(?![\w-])/g, ok: abaValid, mask: hide('aba-routing') },
  { kind: 'ca-sin', label: 'Canadian SIN-shaped national id', group: 'national', validation: 'Luhn check digit and a first-digit rule', severity: 'high', re: /(?<![\w-])\d{3}([ ._-])\d{3}\1\d{3}(?![\w-])/g, ok: (m) => { const d = digitsOf(m); return luhn(d) && d[0] !== '0' && d[0] !== '8'; }, mask: hide('ca-sin') },
  { kind: 'es-dni', label: 'Spanish DNI-shaped national id', group: 'national', validation: 'mod 23 check letter', severity: 'high', re: /(?<![\w-])(\d{8})([A-HJ-NP-TV-Z])(?![\w-])/g, ok: (m) => dniLetter(m.slice(0, 8)) === m[8], mask: hide('es-dni') },
  { kind: 'uk-nino', label: 'UK NINO-shaped national id', group: 'national', validation: 'structure (letter classes and excluded prefixes; no check digit)', severity: 'high', re: /(?<![\w-])[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D](?![\w-])/g, ok: (m) => !['BG', 'GB', 'NK', 'KN', 'TN', 'NT', 'ZZ'].includes(m.slice(0, 2)), mask: hide('uk-nino') },
  { kind: 'health-id', label: 'Health id (NHS-number-shaped)', group: 'health', validation: 'mod 11 check digit', severity: 'high', re: /(?<![\w-])\d{3}( ?)\d{3}\1\d{4}(?![\w-])/g, ok: (m) => healthIdValid(digitsOf(m)), mask: hide('health-id') },
  { kind: 'dob', label: 'Date of birth after a label', group: 'health', validation: 'a real calendar date after dob / date of birth / born', severity: 'medium', re: /\b(?:dob|d\.o\.b\.?|date of birth|born(?: on)?)\s{0,3}[:-]?\s{0,3}(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{4})(?![\w-])/gi,
    ok: (m) => { const v = /(\d{4}-\d{2}-\d{2}|\d{1,2}[/.]\d{1,2}[/.]\d{4})$/.exec(m)[1]; const [y, mo, d] = v.includes('-') ? v.split('-').map(Number) : v.split(/[/.]/).map(Number).reverse(); return calendarValid(y, mo, d); }, mask: hide('dob') },
  { kind: 'email', label: 'E-mail address', group: 'contact', validation: 'structure (local part, dotted domain)', severity: 'medium', re: /\b[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}\b/g, ok: () => true, mask: (m) => { const [l, d] = m.split('@'); return `${l[0]}***@${d}`; } },
  { kind: 'phone', label: 'Telephone number', group: 'contact', validation: 'structure (NANP shape, 10 digits)', severity: 'medium', re: /(?<![\w-])(?:\+?1[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}(?![\w-])/g, ok: () => true, mask: (m) => `***-***-${m.replace(/\D/g, '').slice(-4)}` },
];

export const LEGACY_KINDS = Object.freeze(['card', 'ssn', 'iban', 'email', 'phone']);
export const PII_KIND_IDS = Object.freeze(KINDS.map((k) => k.kind));
export const PII_GROUPS = Object.freeze(['national', 'financial', 'health', 'contact']);
export const piiCatalogue = () => KINDS.map(({ kind, label, group, validation, severity }) => ({ id: kind, label, group, validation, severity, legacy: LEGACY_KINDS.includes(kind) }));

// -> [{ kind, severity, start, end, mask }] sorted by start, non-overlapping. `kinds`: a Set or array of kind ids; omitted = every kind.
export function findPii(text, kinds = null) {
  const s = String(text ?? '');
  const allowed = kinds === null ? null : new Set(kinds);
  const spans = [];
  const overlaps = (a, b) => spans.some((x) => a < x.end && b > x.start);
  for (const k of KINDS) {
    if (allowed && !allowed.has(k.kind)) continue;
    for (const m of s.matchAll(k.re)) {
      const start = m.index; const end = start + m[0].length;
      if (overlaps(start, end) || !k.ok(m[0])) continue;
      spans.push({ kind: k.kind, severity: k.severity, start, end, mask: k.mask(m[0]) });
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

// Spans of the ORIGINAL text for every kind (the selection is about what raises a finding, never about what may be shown).
export function piiSpans(text) {
  const f = fold(text);
  return findPii(f.norm).map((p) => ({ ...mapSpan(f, p.start, p.end), mask: p.mask, kind: p.kind }));
}

export function maskPii(text) {
  const s = String(text ?? '');
  let out = ''; let at = 0;
  for (const p of piiSpans(s)) {
    if (p.start < at) continue;
    out += s.slice(at, p.start) + p.mask; at = p.end;
  }
  // Defence in depth for the logs: a run of nine or more digits that no rule recognised (a card that fails the Luhn
  // check, an SSN written without dashes) is still hidden, though it is not reported as a finding.
  return (out + s.slice(at)).replace(/\d{9,}/g, (d) => `${'*'.repeat(d.length - 4)}${d.slice(-4)}`);
}

// ---- samples: a valid value and a near miss, computed from the check digit at run time (no literal sits in the repo) ----
const luhnComplete = (partial) => { for (let c = 0; c < 10; c += 1) if (luhn(`${partial}${c}`)) return `${partial}${c}`; return partial; };
const ibanCheck = (bban) => String(98 - mod97(`${bban}GB00`)).padStart(2, '0');
const groups4 = (s) => s.replace(/(.{4})(?=.)/g, '$1 ');
const bump = (d) => (d + 1) % 10;
const pad = (n, w) => String(n).padStart(w, '0');
export const SAMPLES = {
  card: { valid: () => groups4(luhnComplete('411111111111111')), nearMiss: () => { const d = luhnComplete('411111111111111'); return groups4(`${d.slice(0, 15)}${bump(+d[15])}`); } },
  ssn: { valid: () => `${pad(123, 3)}-${pad(45, 2)}-${pad(6789, 4)}`, nearMiss: () => `${pad(666, 3)}-${pad(45, 2)}-${pad(6789, 4)}` },
  iban: { valid: () => { const b = 'WEST12345698765432'; return groups4(`GB${ibanCheck(b)}${b}`); }, nearMiss: () => { const b = 'WEST12345698765432'; return groups4(`GB${ibanCheck(b)}${b.slice(0, 17)}${bump(+b[17])}`); } },
  'aba-routing': { valid: () => `02100002${abaCheckDigit('02100002')}`, nearMiss: () => `02100002${bump(abaCheckDigit('02100002'))}` },
  'ca-sin': { valid: () => { const d = luhnComplete('46454286'); return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6)}`; }, nearMiss: () => { const d = luhnComplete('46454286'); return `${d.slice(0, 3)}-${d.slice(3, 6)}-${d.slice(6, 8)}${bump(+d[8])}`; } },
  'es-dni': { valid: () => `12345678${dniLetter('12345678')}`, nearMiss: () => `12345678${dniLetter('12345679')}` },
  'uk-nino': { valid: () => 'AB 12 34 56 C', nearMiss: () => 'BG 12 34 56 C' },
  'health-id': { valid: () => { const n = '943476591'; return `${n.slice(0, 3)} ${n.slice(3, 6)} ${n.slice(6)}${mod11Check(n)}`; }, nearMiss: () => { const n = '943476591'; return `${n.slice(0, 3)} ${n.slice(3, 6)} ${n.slice(6)}${bump(mod11Check(n))}`; } },
  dob: { valid: () => 'DOB: 1984-03-27', nearMiss: () => 'DOB: 1984-02-30' },
  email: { valid: () => 'sam.jones@mail.example', nearMiss: () => 'sam.jones@localhost' },
  phone: { valid: () => '415-555-0132', nearMiss: () => '415-555-01' },
};
