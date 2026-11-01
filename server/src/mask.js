// Masking of anything a visitor typed, before it is stored, logged or returned. Everything the built-in detectors recognise
// (every personal-data kind and every bundled secret detector) and everything the visitor's own pasted rules recognise
// becomes a marker; redactText (redaction.js) then removes the keyword-and-value forms. Heuristic: it catches the shapes
// below, not every way a value can be written. Order matters: mask the WHOLE text first, truncate after (safeSnippet).
import { piiSpans } from './pii.js';
import { detectSecrets } from './secrets.js';
import { percentDecode } from './fold.js';

// Replace each span ({ start, end, mask }) with its marker; overlapping spans collapse into the first.
export function maskSpans(text, spans) {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  if (!sorted.length) return text;
  let out = ''; let at = 0;
  for (const s of sorted) { if (s.start < at) { at = Math.max(at, s.end); continue; } out += `${text.slice(at, s.start)}${s.mask}`; at = s.end; }
  return out + text.slice(at);
}

// A run of nine or more digits that no rule recognised is still hidden (defence in depth for the logs).
const hideDigits = (t) => t.replace(/\d{9,}/g, (d) => `${'*'.repeat(d.length - 4)}${d.slice(-4)}`);

// rules: compiled custom rules (rules.js); each has spansOf(text) -> [{ start, end }] over the ORIGINAL text it is given.
export function maskTyped(input, rules = []) {
  const s = String(input ?? '');
  const once = (t) => hideDigits(maskSpans(t, [
    ...piiSpans(t),
    ...detectSecrets(t).map((x) => ({ ...x, mask: `[masked:${x.rule}]` })),
    ...rules.flatMap((r) => r.spansOf(t).map((x) => ({ ...x, mask: `[masked:${r.id}]` }))),
  ]));
  const masked = once(s);
  // A value written with percent-encoding (up to three rounds) is masked in its decoded form.
  const decoded = percentDecode(s);
  if (decoded !== s) { const md = once(decoded); if (md !== hideDigits(decoded)) return md; }
  return masked;
}
