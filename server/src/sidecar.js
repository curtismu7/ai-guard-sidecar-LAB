// The guardrail sidecar: POST /inspect (the contract as understood from the AI-DEMO2 demo_mcp_promptguard README,
// UNVERIFIED against product documentation), GET /health, GET/PUT /demo/config, GET/PUT /demo/fault.
// Runs standalone (sidecar-main.js) or embedded in the main server. Always loopback.
import express from 'express';
import { DEFAULT_RAILS, ENGINE, RAILS, detectUnit } from './detectors.js';
import { maskPii } from './pii.js';
import { redactText } from './redaction.js';
import { revealText } from './sanitize.js';
import { credentialGuard, hostGuard, isLoopbackHost, originGuard, portInRange } from './safety.js';

export const LIMITS = { bodyBytes: 64 * 1024, units: 32, textChars: 10000, roleChars: 64, configBytes: 2048, delayMaxMs: 10000, snippetChars: 200 };
export const DEFAULT_SIDECAR_CONFIG = Object.freeze({
  detector: { threshold: 0.9, benignLabels: ['benign', 'label_0', 'safe'] },
  rails: { ...DEFAULT_RAILS },
});
export const DEFAULT_FAULT = Object.freeze({ mode: 'none', delayMs: 0 });
export const FAULT_MODES = ['none', 'error', 'timeout', 'slow'];

const clone = (v) => structuredClone(v);
export class Invalid extends Error {}
const exactKeys = (obj, keys, what) => {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Invalid(`${what} must be an object`);
  const extra = Object.keys(obj).filter((k) => !keys.includes(k));
  const missing = keys.filter((k) => !(k in obj));
  if (extra.length || missing.length) throw new Invalid(`${what} must have exactly: ${keys.join(', ')}`);
};

export function validateSidecarConfig(v) {
  exactKeys(v, ['detector', 'rails'], 'config');
  exactKeys(v.detector, ['threshold', 'benignLabels'], 'detector');
  const { threshold, benignLabels } = v.detector;
  if (typeof threshold !== 'number' || !Number.isFinite(threshold) || threshold < 0 || threshold > 1) throw new Invalid('threshold must be a number from 0 to 1');
  if (!Array.isArray(benignLabels) || benignLabels.length > 10 || !benignLabels.every((l) => typeof l === 'string' && /^[\w .-]{1,40}$/.test(l))) {
    throw new Invalid('benignLabels must be at most 10 labels of 1-40 letters, digits, space, dot, dash or underscore');
  }
  exactKeys(v.rails, RAILS.map((r) => r.id), 'rails');
  if (!Object.values(v.rails).every((b) => typeof b === 'boolean')) throw new Invalid('each rail must be a boolean');
  return { detector: { threshold, benignLabels: [...new Set(benignLabels.map((l) => l.toLowerCase()))] }, rails: { ...v.rails } };
}

export function validateFault(v) {
  exactKeys(v, ['mode', 'delayMs'], 'fault');
  if (!FAULT_MODES.includes(v.mode)) throw new Invalid(`mode must be one of ${FAULT_MODES.join(', ')}`);
  if (!Number.isInteger(v.delayMs) || v.delayMs < 0 || v.delayMs > LIMITS.delayMaxMs) throw new Invalid(`delayMs must be an integer from 0 to ${LIMITS.delayMaxMs}`);
  if (v.mode === 'slow' && v.delayMs === 0) throw new Invalid('slow needs a delayMs above 0');
  return { mode: v.mode, delayMs: v.mode === 'slow' ? v.delayMs : 0 };
}

export function createSidecarState() {
  return {
    config: clone(DEFAULT_SIDECAR_CONFIG),
    fault: clone(DEFAULT_FAULT),
    reset() { this.config = clone(DEFAULT_SIDECAR_CONFIG); this.fault = clone(DEFAULT_FAULT); },
  };
}

// What may leave the detector: PII masked, secret-looking strings redacted, hidden characters made visible, bounded.
export const safeSnippet = (text, max = LIMITS.snippetChars) => revealText(redactText(maskPii(String(text ?? ''))).slice(0, max), max * 4);

// Validate and run one /inspect request body. Returns { findings }. Throws Invalid (400) or a size error (413).
export function inspect(body, config) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Invalid('body must be a JSON object');
  const { units } = body;
  if (units !== undefined && !Array.isArray(units)) throw new Invalid('units must be an array');
  const list = units ?? [];
  if (list.length > LIMITS.units) throw Object.assign(new Invalid(`at most ${LIMITS.units} units`), { status: 413 });
  const findings = [];
  list.forEach((unit, index) => {
    if (!unit || typeof unit !== 'object' || Array.isArray(unit)) throw new Invalid(`units[${index}] must be an object`);
    const { role, direction = 'request', text = '' } = unit;
    if (role !== undefined && (typeof role !== 'string' || role.length > LIMITS.roleChars)) throw new Invalid(`units[${index}].role must be a short string`);
    if (direction !== 'request' && direction !== 'response') throw new Invalid(`units[${index}].direction must be request or response`);
    if (typeof text !== 'string') throw new Invalid(`units[${index}].text must be a string`);
    if (text.length > LIMITS.textChars) throw Object.assign(new Invalid(`units[${index}].text is over ${LIMITS.textChars} characters`), { status: 413 });
    if (!text.trim()) return;
    for (const d of detectUnit({ role, direction, text }, config)) {
      findings.push({ category: d.category, severity: d.severity, location: { index }, messages: [d.message], contents: [safeSnippet(text)] });
    }
  });
  return { findings };
}

export function createSidecarApp(state = createSidecarState(), { log = () => {} } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  app.use(originGuard);
  app.use((_req, res, next) => { res.set({ 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }); next(); });
  app.use(credentialGuard);

  app.get('/health', (_req, res) => res.json({ ok: true }));
  app.all('/health', (_req, res) => res.set('Allow', 'GET').status(405).json({ error: 'method_not_allowed' }));

  const json = (limit) => express.json({ limit, strict: true });
  const sendConfig = (res) => res.json({ engine: ENGINE, standIn: true, config: state.config, fault: state.fault, rails: RAILS });

  app.get('/demo/config', (_req, res) => sendConfig(res));
  app.put('/demo/config', json(LIMITS.configBytes), (req, res) => {
    state.config = validateSidecarConfig(req.body);
    sendConfig(res);
  });
  app.get('/demo/fault', (_req, res) => res.json({ fault: state.fault, modes: FAULT_MODES }));
  app.put('/demo/fault', json(LIMITS.configBytes), (req, res) => {
    state.fault = validateFault(req.body);
    res.json({ fault: state.fault, modes: FAULT_MODES });
  });

  app.post('/inspect', json(LIMITS.bodyBytes), (req, res) => {
    const respond = () => {
      let result;
      try { result = inspect(req.body, state.config); } catch (e) {
        if (e instanceof Invalid) return res.status(e.status || 400).json({ error: e.status === 413 ? 'payload_too_large' : 'bad_request', message: e.message });
        log('inspect_failed');
        return res.status(502).json({ error: 'inspect_failed' });
      }
      // Verdict only: no prompt text ever reaches the log.
      log(`${(req.body.units || []).length} unit(s) -> ${result.findings.map((f) => `${f.category}/${f.severity}`).join(', ') || 'allow'}`);
      res.set('X-Guard-Engine', ENGINE).json(result);
    };
    const { mode, delayMs } = state.fault;
    if (mode === 'error') { log('injected fault: 502'); return res.status(502).json({ error: 'inspect_failed', message: 'injected fault' }); }
    if (mode === 'timeout' || mode === 'slow') {
      // timeout: hold the connection until the caller gives up. slow: answer after delayMs. Timers are cleared on close.
      const timer = setTimeout(respond, mode === 'timeout' ? LIMITS.delayMaxMs * 3 : delayMs);
      timer.unref();
      res.on('close', () => clearTimeout(timer));
      return undefined;
    }
    return respond();
  });

  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use((err, _req, res, _next) => {
    if (err instanceof Invalid) return res.status(400).json({ error: 'bad_request', message: err.message });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large', message: 'request body is too large' });
    if (err.type === 'entity.parse.failed' || err instanceof URIError || err.status === 400) return res.status(400).json({ error: 'bad_request', message: 'request body is not valid JSON' });
    log('server_error');
    return res.status(500).json({ error: 'server_error' });
  });
  return app;
}

// The sidecar never binds anything but loopback.
export async function startSidecar({ port, host = '127.0.0.1', state = createSidecarState(), log } = {}) {
  if (!isLoopbackHost(host)) throw new Error(`refusing to bind the sidecar to ${host}: loopback only`);
  if (!portInRange(port)) throw new Error(`sidecar port ${port} is outside 6500-6549`);
  return new Promise((resolve, reject) => {
    const server = createSidecarApp(state, { log }).listen(port, host);
    server.once('error', reject);
    server.once('listening', () => resolve({
      port: server.address().port, state, url: `http://127.0.0.1:${server.address().port}`,
      close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
    }));
  });
}
