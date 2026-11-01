// Prompt-logging settings (modelPromptLogConfig: Enabled, PublicKey, KeyID, Surfaces, IncludeResponses, MaxBytes; console swagger names,
// 2026-10-31, schema only). Off until asked, and nothing is recorded without a public key (the swagger says so). The behaviour below
// (what is capped, which surface a record belongs to, the envelope) is this app's reading or invention, tagged so in the UI.
import { SealError, parsePublicJwk, sealRecord } from './seal.js';
import { maskTyped } from './mask.js';

// The surfaces the console swagger names (llm, mcp, a2a, coding_agent). This app's mock gateway only produces llm and a2a.
export const SURFACES = Object.freeze(['llm', 'mcp', 'a2a', 'coding_agent']);

export const PL_LIMITS = { defaultMaxBytes: 16384, minBytes: 256, maxBytes: 65536 };
export const defaultPromptLog = () => ({ Enabled: false, PublicKey: '', KeyID: '', Surfaces: [], IncludeResponses: false, MaxBytes: 0 });
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Returns { ok, errors, config, publicKey }. A missing field is its default; a wrong-typed one is an error. Errors never echo the input.
export function validatePromptLog(c) {
  const errors = []; const config = defaultPromptLog(); let publicKey = null;
  if (c === undefined) return { ok: true, errors, config, publicKey };
  if (!isObj(c)) return { ok: false, errors: [{ field: 'promptLog', message: 'must be an object' }], config, publicKey };
  const has = (k) => Object.hasOwn(c, k);
  if (has('Enabled')) { if (typeof c.Enabled === 'boolean') config.Enabled = c.Enabled; else errors.push({ field: 'Enabled', message: 'must be true or false' }); }
  if (has('IncludeResponses')) { if (typeof c.IncludeResponses === 'boolean') config.IncludeResponses = c.IncludeResponses; else errors.push({ field: 'IncludeResponses', message: 'must be true or false' }); }
  if (has('Surfaces')) {
    if (Array.isArray(c.Surfaces) && c.Surfaces.length <= SURFACES.length && c.Surfaces.every((s) => typeof s === 'string' && SURFACES.includes(s))) config.Surfaces = [...new Set(c.Surfaces)];
    else errors.push({ field: 'Surfaces', message: `must list surfaces from ${SURFACES.join(', ')}` });
  }
  if (has('MaxBytes')) {
    if (Number.isInteger(c.MaxBytes) && (c.MaxBytes === 0 || (c.MaxBytes >= PL_LIMITS.minBytes && c.MaxBytes <= PL_LIMITS.maxBytes))) config.MaxBytes = c.MaxBytes;
    else errors.push({ field: 'MaxBytes', message: `must be 0 (the default) or ${PL_LIMITS.minBytes} to ${PL_LIMITS.maxBytes}` });
  }
  if (has('KeyID')) { if (typeof c.KeyID === 'string' && (c.KeyID === '' || (KEY_ID.test(c.KeyID) && maskTyped(c.KeyID) === c.KeyID))) config.KeyID = c.KeyID; else errors.push({ field: 'KeyID', message: 'must be a plain name: letters, digits, dot, dash or underscore, up to 64, and not something that looks like personal data or a secret' }); }
  if (has('PublicKey') && c.PublicKey !== '' && c.PublicKey !== null) {
    try { const k = parsePublicJwk(c.PublicKey); publicKey = k; config.PublicKey = JSON.stringify(k.jwk); } catch (e) { errors.push({ field: 'PublicKey', message: e instanceof SealError ? e.message : 'not a usable key' }); }
  }
  if (publicKey && !config.KeyID) errors.push({ field: 'KeyID', message: 'is required with a PublicKey (it names the key a record was sealed to)' });
  return { ok: errors.length === 0, errors, config, publicKey: errors.length ? null : publicKey };
}

// Why a record is NOT written, or null when it is.
export function skipReason(config, publicKey, surface) {
  if (!config.Enabled) return 'prompt logging is off';
  if (!publicKey || !config.PublicKey) return 'no public key: nothing is recorded without one';
  if (config.Surfaces.length && !config.Surfaces.includes(surface)) return 'this surface is not selected';
  return null;
}

// Cut a string to at most `max` UTF-8 bytes without splitting a character.
export function capBytes(s, max) {
  const buf = Buffer.from(String(s), 'utf8');
  if (buf.length <= max) return { text: String(s), cut: false };
  let end = max; while (end > 0 && (buf[end] & 0xc0) === 0x80) end--;
  return { text: buf.subarray(0, end).toString('utf8'), cut: true };
}

// What is sealed: the prompt (and the response when IncludeResponses), capped to MaxBytes in total (the prompt first).
export function plaintextFor(config, prompt, response) {
  const max = config.MaxBytes || PL_LIMITS.defaultMaxBytes;
  const p = capBytes(prompt, max);
  let truncated = p.cut; let r = null;
  if (config.IncludeResponses && typeof response === 'string' && response) {
    const left = max - Buffer.byteLength(p.text, 'utf8');
    if (left <= 0) truncated = true; // no room left: the response is dropped, and the record says it was cut
    else { const c = capBytes(response, left); r = c.text; truncated = truncated || c.cut; }
  }
  const body = { prompt: p.text, ...(r === null ? {} : { response: r }), truncated };
  return { json: JSON.stringify(body), truncated, hasResponse: r !== null };
}

// ---- the store: one per workspace (the service creates it) -------------------------------------------------------------------------------
export const PL_STORE = { maxRecords: 100 };
const FIELDS = ['Enabled', 'PublicKey', 'KeyID', 'Surfaces', 'IncludeResponses', 'MaxBytes'];

export class PromptLogInvalid extends Error { constructor(errors) { super('the prompt-log settings were refused: nothing changed'); this.errors = errors; } }

// Settings and sealed records. Records are a ring: when full the oldest is dropped and `dropped` counts it (nothing is silent).
export function createPromptLog({ now = () => new Date() } = {}) {
  let config = defaultPromptLog(); let publicKey = null; let records = []; let seq = 0; let dropped = 0;
  const status = () => {
    const why = skipReason(config, publicKey, config.Surfaces[0] ?? 'llm');
    return { recording: why === null, why: why ?? 'recording: each run is sealed to the key above' };
  };
  return {
    view: () => ({ config: structuredClone(config), status: status(), records: records.slice().reverse(), dropped, limits: { ...PL_LIMITS, maxRecords: PL_STORE.maxRecords, surfaces: SURFACES } }),
    // The whole settings object is validated first; a refused one changes nothing.
    put(body) {
      if (!isObj(body) || Object.keys(body).some((k) => !FIELDS.includes(k))) throw new PromptLogInvalid([{ field: 'body', message: `must be an object with only: ${FIELDS.join(', ')}` }]);
      const v = validatePromptLog(body);
      if (!v.ok) throw new PromptLogInvalid(v.errors);
      config = v.config; publicKey = v.publicKey;
    },
    // Seals one run. Returns { recorded: true, record } or { recorded: false, why }. Never throws.
    record({ surface, requestText, upstreamText, caller, result, categories }) {
      const why = skipReason(config, publicKey, surface);
      if (why) return { recorded: false, why };
      try {
        seq += 1;
        const rid = `pl-${seq}`;
        const withResponse = result.blockedAt !== 'request'; // a request that was blocked never reached the upstream
        const pt = plaintextFor(config, requestText, withResponse ? upstreamText : undefined);
        const envelope = sealRecord({ publicKey, keyId: config.KeyID, recordId: rid, plaintext: pt.json });
        const rec = {
          id: rid, at: now().toISOString(), surface, caller: caller ?? null, outcome: result.outcome, blockedAt: result.blockedAt, reason: result.reason,
          categories, kid: config.KeyID, truncated: pt.truncated, hasResponse: pt.hasResponse, envelope,
        };
        records.push(rec);
        if (records.length > PL_STORE.maxRecords) { records = records.slice(records.length - PL_STORE.maxRecords); dropped += 1; }
        return { recorded: true, record: rec };
      } catch { return { recorded: false, why: 'sealing failed' }; }
    },
    reset() { config = defaultPromptLog(); publicKey = null; records = []; dropped = 0; },
  };
}
