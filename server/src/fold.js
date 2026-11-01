// One normalised copy of a text for detection and masking, with an offset map back to the original, so a value found in
// the copy is replaced at the right place in the original. Applied after NFKC: zero-width, bidi, tag, variation and other
// default-ignorable characters, every format character (Cf), U+FFFD, lone surrogates and the Braille blank are dropped;
// every whitespace run becomes one space; compatibility forms (fullwidth digits and letters) become their plain form.
// It is a heuristic, not a guarantee: a visitor can still split a value with a character this does not know.
const DROP = /^[\p{Default_Ignorable_Code_Point}\p{Cf}�⠀\uD800-\uDFFF]$/u;
const SPACE = /\s/u;

export function fold(input) {
  const text = String(input ?? '');
  let norm = ''; const starts = []; const ends = []; let space = false; let i = 0;
  for (const cp of text) {
    const start = i; i += cp.length;
    const c = cp.normalize('NFKC');
    for (const ch of c) {
      if (DROP.test(ch)) continue;
      if (SPACE.test(ch)) { if (!space) { norm += ' '; starts.push(start); ends.push(i); space = true; } continue; }
      space = false;
      for (let k = 0; k < ch.length; k += 1) { norm += ch[k]; starts.push(start); ends.push(i); }
    }
  }
  return { norm, starts, ends };
}

// A span [s, e) of the folded copy back to the original text.
export const mapSpan = (f, s, e) => ({ start: f.starts[s], end: f.ends[e - 1] });

// Percent-decoding, up to three rounds, so "%34%32" typed as an evasion is read as "42". An undecodable string stays as is.
export function percentDecode(input, rounds = 3) {
  let s = String(input ?? '');
  for (let r = 0; r < rounds; r += 1) {
    if (!/%[0-9a-fA-F]{2}/.test(s)) break;
    let next;
    try { next = decodeURIComponent(s); } catch { next = s.replace(/%([0-9a-fA-F]{2})/g, (_m, h) => String.fromCharCode(parseInt(h, 16))); }
    if (next === s) break;
    s = next;
  }
  return s;
}
