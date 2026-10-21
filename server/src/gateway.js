// The MOCK GATEWAY. It stands in for the real agent gateway so the sidecar contract can be taught offline.
// Behaviour implemented here is AS UNDERSTOOD FROM THE DEMO ENVIRONMENT, UNVERIFIED against product documentation:
//   - the gateway POSTs the text units of a request or response to the sidecar's /inspect;
//   - an empty findings list means allow;
//   - a finding at or above its category's block threshold makes the gateway block;
//   - if the sidecar fails (502, timeout, unreachable), a "Sidecar Fail Closed" toggle decides block or allow.
// Block thresholds and defaults below are demo choices, not product defaults.
import { revealText } from './sanitize.js';
import { severityRank } from './detectors.js';
import { assertSidecarUrl } from './safety.js';
import { safeSnippet } from './sidecar.js';

export const THRESHOLD_LEVELS = ['low', 'medium', 'high', 'none'];
export const CATEGORIES = ['prompt_injection', 'jailbreak', 'pii'];
export const DEFAULT_GATEWAY_CONFIG = Object.freeze({
  failClosed: true,
  timeoutMs: 1000,
  blockThresholds: { prompt_injection: 'medium', jailbreak: 'none', pii: 'high' },
});
export const TIMEOUT_RANGE = [100, 5000];
// A category the demo does not know blocks at this level (a conservative demo choice).
export const UNKNOWN_CATEGORY_THRESHOLD = 'high';
export const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_FINDINGS = 100;

export class Invalid extends Error {}

export function validateThresholds(t, what = 'blockThresholds') {
  if (!t || typeof t !== 'object' || Array.isArray(t)) throw new Invalid(`${what} must be an object`);
  const keys = Object.keys(t);
  if (keys.length !== CATEGORIES.length || !CATEGORIES.every((c) => c in t)) throw new Invalid(`${what} must set exactly: ${CATEGORIES.join(', ')}`);
  for (const c of CATEGORIES) if (!THRESHOLD_LEVELS.includes(t[c])) throw new Invalid(`${what}.${c} must be one of ${THRESHOLD_LEVELS.join(', ')}`);
  return Object.fromEntries(CATEGORIES.map((c) => [c, t[c]]));
}

export function validateTimeout(ms) {
  if (!Number.isInteger(ms) || ms < TIMEOUT_RANGE[0] || ms > TIMEOUT_RANGE[1]) throw new Invalid(`timeoutMs must be an integer from ${TIMEOUT_RANGE[0]} to ${TIMEOUT_RANGE[1]}`);
  return ms;
}

export function validateGatewayConfig(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Invalid('gateway must be an object');
  const keys = Object.keys(v).sort().join();
  if (keys !== 'blockThresholds,failClosed,timeoutMs') throw new Invalid('gateway must have exactly: failClosed, timeoutMs, blockThresholds');
  if (typeof v.failClosed !== 'boolean') throw new Invalid('failClosed must be a boolean');
  return { failClosed: v.failClosed, timeoutMs: validateTimeout(v.timeoutMs), blockThresholds: validateThresholds(v.blockThresholds) };
}

// Does one finding reach its category's block threshold? Compared by severity rank: at or above blocks.
// An unknown severity counts as high (fail safe); 'none' means the category is alert-only.
export function findingBlocks(finding, thresholds) {
  const level = thresholds[finding.category] ?? UNKNOWN_CATEGORY_THRESHOLD;
  if (level === 'none') return false;
  const rank = severityRank(finding.severity) || severityRank('high');
  return rank >= severityRank(level);
}

// The sidecar is untrusted input to the gateway: shape-check it, bound it, make every string inert and PII-safe.
export function sanitizeFindings(raw) {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.findings) || raw.findings.length > MAX_FINDINGS) throw new Error('bad shape');
  return raw.findings.map((f) => {
    const idx = f?.location?.index;
    if (!f || typeof f !== 'object' || typeof f.category !== 'string' || typeof f.severity !== 'string' || !Number.isInteger(idx) || idx < 0) throw new Error('bad finding');
    const strs = (a) => (Array.isArray(a) ? a.slice(0, 5).filter((s) => typeof s === 'string').map((s) => safeSnippet(s, 300)) : []);
    return {
      category: revealText(f.category, 64),
      severity: ['low', 'medium', 'high'].includes(f.severity) ? f.severity : 'unknown',
      index: idx, messages: strs(f.messages), contents: strs(f.contents),
    };
  });
}

async function readBounded(res) {
  const reader = res.body.getReader();
  const chunks = []; let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error('too large'); }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

// POST units to {base}/inspect. Never throws: -> { ok, status, latencyMs, findings? , error? }
// The exact /inspect request body the gateway sends (also used by the UI viewer, with the text made safe first).
export const inspectBody = (units) => ({ tenant: 'demo-tenant', user: 'demo-user', app_name: 'mock-gateway', units });

export async function callSidecar(base, units, timeoutMs, fetchImpl = globalThis.fetch) {
  const started = Date.now();
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  timer.unref?.(); // never the only thing keeping the process alive (a stuck call must not outlive its caller)
  const done = (r) => ({ latencyMs: Date.now() - started, ...r });
  try {
    const res = await fetchImpl(`${base}/inspect`, {
      method: 'POST', redirect: 'error', signal: ctl.signal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(inspectBody(units)),
    });
    if (res.status !== 200) { await res.body?.cancel?.().catch(() => {}); return done({ ok: false, status: res.status, error: `sidecar_http_${res.status}` }); }
    let findings;
    try { findings = sanitizeFindings(JSON.parse(await readBounded(res))); } catch { return done({ ok: false, status: 200, error: 'sidecar_bad_response' }); }
    return done({ ok: true, status: 200, findings });
  } catch (e) {
    return done({ ok: false, status: null, error: ctl.signal.aborted ? 'sidecar_timeout' : 'sidecar_unreachable' });
  } finally {
    clearTimeout(timer);
  }
}

// Decide one inspection. `call` is the callSidecar result.
export function decide(call, policy) {
  if (!call.ok) {
    return policy.failClosed
      ? { decision: 'block', reason: 'sidecar_error_fail_closed', alert: false, evaluations: [] }
      : { decision: 'allow', reason: 'sidecar_error_fail_open', alert: true, evaluations: [] };
  }
  const evaluations = call.findings.map((f) => ({ ...f, threshold: policy.blockThresholds[f.category] ?? UNKNOWN_CATEGORY_THRESHOLD, blocks: findingBlocks(f, policy.blockThresholds) }));
  if (evaluations.some((e) => e.blocks)) return { decision: 'block', reason: 'threshold_met', alert: false, evaluations };
  // Findings that do not block: either below a real threshold, or the category is not enforced at all (threshold none).
  if (evaluations.length) return { decision: 'allow', reason: evaluations.every((e) => e.threshold === 'none') ? 'alert_only_not_enforcing' : 'alert_only_below_threshold', alert: true, evaluations };
  return { decision: 'allow', reason: 'no_findings', alert: false, evaluations };
}

export function createGateway({ sidecarUrl, fetchImpl = globalThis.fetch } = {}) {
  const base = assertSidecarUrl(sidecarUrl);

  async function inspectStage(stage, unit, policy) {
    const call = await callSidecar(base, [unit], policy.timeoutMs, fetchImpl);
    const d = decide(call, policy);
    // What the teaching viewer shows: the request body as sent, and the answer in contract shape. Both are display
    // copies: text is masked and made inert, the sidecar answer was sanitised by callSidecar.
    const exchange = {
      request: inspectBody([{ role: revealText(unit.role, 64), direction: unit.direction, text: safeSnippet(unit.text, 300) }]),
      response: call.ok
        ? { status: 200, body: { findings: call.findings.map((f) => ({ category: f.category, severity: f.severity, location: { index: f.index }, messages: f.messages, contents: f.contents })) } }
        : { status: call.status, error: call.error },
    };
    return {
      stage,
      unit: { role: revealText(unit.role, 64), direction: unit.direction, chars: unit.text.length, text: safeSnippet(unit.text, 300) },
      sidecar: { ok: call.ok, status: call.status, latencyMs: call.latencyMs, error: call.error ?? null },
      exchange,
      ...d,
    };
  }

  // request -> (inspect) -> upstream stub -> (inspect response) -> client. A block at request skips the upstream.
  async function run({ requestText, requestRole = 'user_prompt', upstreamText = '', policy }) {
    const stages = [];
    const req = await inspectStage('request', { role: requestRole, direction: 'request', text: requestText }, policy);
    stages.push(req);
    if (req.decision === 'block') {
      stages.push({ stage: 'upstream', skipped: true }, { stage: 'response', skipped: true });
      return { outcome: 'block', blockedAt: 'request', reason: req.reason, stages };
    }
    stages.push({ stage: 'upstream', skipped: false, chars: upstreamText.length });
    const resp = await inspectStage('response', { role: 'assistant_response', direction: 'response', text: upstreamText }, policy);
    stages.push(resp);
    if (resp.decision === 'block') return { outcome: 'block', blockedAt: 'response', reason: resp.reason, stages };
    return { outcome: 'allow', blockedAt: null, reason: resp.reason !== 'no_findings' ? resp.reason : req.reason, stages };
  }

  // Admin calls to the sidecar's /demo endpoints, over the same loopback HTTP.
  async function admin(method, path, body) {
    const res = await fetchImpl(`${base}${path}`, {
      method, redirect: 'error', signal: AbortSignal.timeout(2000),
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await readBounded(res);
    let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, json };
  }

  return { base, run, admin };
}
