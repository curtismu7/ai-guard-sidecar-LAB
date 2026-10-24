// Orchestrates the demo: gateway config, caller profiles, scenario runs (serialised, capped queue), the decision log,
// the fault injector and reset. All text that is stored or returned has been masked and made inert upstream of here.
import { createDecisionLog } from './decisions.js';
import { CALLERS, listScenarios, scenarioById } from './scenarios.js';
import { DEFAULT_GATEWAY_CONFIG, Invalid, createGateway, validateGatewayConfig, validateTimeout } from './gateway.js';
import { DEFAULT_SIDECAR_CONFIG } from './sidecar.js';
import { STAND_IN_LIMITS, detectInjection } from './detectors.js';
import { safeSnippet } from './sidecar.js';

export const MAX_QUEUE = 4;
export const CUSTOM_MAX_CHARS = 4000;
export { Invalid };

export class QueueFull extends Error {}
export class SidecarDown extends Error {}

export function createService({ sidecarUrl, fetchImpl, decisions = createDecisionLog(), workspace } = {}) {
  const gateway = createGateway({ sidecarUrl, fetchImpl, workspace });
  let config = structuredClone(DEFAULT_GATEWAY_CONFIG);

  // One run at a time (faults and config are shared state); at most MAX_QUEUE waiting or running.
  let chain = Promise.resolve(); let pending = 0;
  const enqueue = (fn) => {
    if (pending >= MAX_QUEUE) throw new QueueFull('run queue is full');
    pending += 1;
    const p = chain.then(fn, fn);
    chain = p.catch(() => {}).finally(() => { pending -= 1; });
    return p;
  };

  const adminOk = async (method, path, body) => {
    let r;
    try { r = await gateway.admin(method, path, body); } catch { throw new SidecarDown('the sidecar is not reachable'); }
    if (r.status !== 200 || !r.json) throw new SidecarDown(`the sidecar answered ${r.status} on ${path}`);
    return r.json;
  };

  const policyFor = (run) => {
    const caller = run.caller ? CALLERS[run.caller] : null;
    return {
      failClosed: run.failClosed ?? config.failClosed,
      timeoutMs: run.timeoutMs ?? config.timeoutMs,
      blockThresholds: caller ? caller.blockThresholds : config.blockThresholds,
    };
  };

  async function executeRun(run, meta) {
    const policy = policyFor(run);
    let restore = null;
    if (run.fault) {
      restore = (await adminOk('GET', '/demo/fault')).fault;
      await adminOk('PUT', '/demo/fault', run.fault);
    }
    let result;
    try {
      result = await gateway.run({ requestText: run.requestText, requestRole: run.requestRole, upstreamText: run.upstreamText, policy });
    } finally {
      if (restore) await adminOk('PUT', '/demo/fault', restore).catch(() => {});
    }
    const expectationMet = run.expect ? ['outcome', 'blockedAt', 'reason'].every((k) => result[k] === run.expect[k]) : null;
    const entry = decisions.add({
      source: meta.source, scenario: meta.scenario ?? null, label: run.label, caller: run.caller ?? null,
      policy: { ...policy, blockThresholds: { ...policy.blockThresholds } },
      injectedFault: run.fault?.mode ?? null,
      ...result, expected: run.expect ?? null, expectationMet,
    });
    return entry;
  }

  const api = {
    gateway, decisions,
    getConfig: () => structuredClone(config),

    async getFullConfig() {
      let sidecar = null; let fault = null; let sidecarError = null;
      try { const j = await adminOk('GET', '/demo/config'); sidecar = j.config; fault = j.fault; } catch (e) { sidecarError = e.message; }
      return { gateway: structuredClone(config), sidecar, fault, sidecarError, defaults: { gateway: DEFAULT_GATEWAY_CONFIG, sidecar: DEFAULT_SIDECAR_CONFIG }, callers: CALLERS };
    },

    // body: { gateway?: {...}, sidecar?: {...} } each part complete and validated before anything changes.
    putConfig(body) {
      if (!body || typeof body !== 'object' || Array.isArray(body) || !Object.keys(body).length || Object.keys(body).some((k) => k !== 'gateway' && k !== 'sidecar')) {
        throw new Invalid('body must contain gateway and/or sidecar');
      }
      const g = body.gateway === undefined ? null : validateGatewayConfig(body.gateway);
      return enqueue(async () => {
      if (body.sidecar !== undefined) {
        const r = await gateway.admin('PUT', '/demo/config', body.sidecar).catch(() => { throw new SidecarDown('the sidecar is not reachable'); });
        if (r.status === 400) throw new Invalid(String(r.json?.message ?? 'invalid sidecar config').slice(0, 200));
        if (r.status !== 200) throw new SidecarDown(`the sidecar answered ${r.status}`);
      }
      if (g) config = g;
      return api.getFullConfig();
      });
    },

    putFault(fault) {
      return enqueue(async () => {
      const r = await gateway.admin('PUT', '/demo/fault', fault).catch(() => { throw new SidecarDown('the sidecar is not reachable'); });
      if (r.status === 400) throw new Invalid(String(r.json?.message ?? 'invalid fault').slice(0, 200));
      if (r.status !== 200) throw new SidecarDown(`the sidecar answered ${r.status}`);
      return r.json;
      });
    },
    getFault: () => adminOk('GET', '/demo/fault'),

    listScenarios,

    runScenario(id) {
      const s = scenarioById(id);
      if (!s) return null;
      return enqueue(async () => {
        const runs = [];
        for (const run of s.runs) runs.push(await executeRun(run, { source: 'scenario', scenario: s.id }));
        return { scenario: s.id, title: s.title, teaches: s.teaches, knownLimit: s.knownLimit ?? null, runs, allExpectationsMet: runs.every((r) => r.expectationMet) };
      });
    },

    // custom: { requestText, upstreamText?, caller?, failClosed? }
    runCustom(c) {
      if (!c || typeof c !== 'object' || Array.isArray(c)) throw new Invalid('custom must be an object');
      const extra = Object.keys(c).filter((k) => !['requestText', 'upstreamText', 'caller', 'failClosed', 'timeoutMs'].includes(k));
      if (extra.length) throw new Invalid(`unknown field: ${safeSnippet(extra[0], 40)}`);
      if (typeof c.requestText !== 'string' || !c.requestText.trim() || c.requestText.length > CUSTOM_MAX_CHARS) throw new Invalid(`requestText must be 1-${CUSTOM_MAX_CHARS} characters`);
      if (c.upstreamText !== undefined && (typeof c.upstreamText !== 'string' || c.upstreamText.length > CUSTOM_MAX_CHARS)) throw new Invalid(`upstreamText must be at most ${CUSTOM_MAX_CHARS} characters`);
      if (c.caller !== undefined && !(typeof c.caller === 'string' && Object.hasOwn(CALLERS, c.caller))) throw new Invalid(`caller must be one of ${Object.keys(CALLERS).join(', ')}`);
      if (c.failClosed !== undefined && typeof c.failClosed !== 'boolean') throw new Invalid('failClosed must be a boolean');
      if (c.timeoutMs !== undefined) validateTimeout(c.timeoutMs);
      const run = { label: 'Custom text', requestText: c.requestText, upstreamText: c.upstreamText ?? '', caller: c.caller, failClosed: c.failClosed, timeoutMs: c.timeoutMs, requestRole: c.caller ? 'a2a_message' : 'user_prompt' };
      return enqueue(async () => ({ scenario: null, title: 'Custom text', runs: [await executeRun(run, { source: 'custom' })] }));
    },

    // The stand-in's documented limits, computed by the live detector with the current sidecar settings.
    async standIn() {
      const cfg = (await adminOk('GET', '/demo/config')).config;
      return {
        engine: 'stand-in-heuristics', realClassifier: false,
        notice: 'A deterministic keyword stand-in. It says nothing about the detection quality, defaults or licensing of any real product.',
        limits: STAND_IN_LIMITS.map((l) => ({ id: l.id, kind: l.kind, text: l.text, why: l.why, flagged: detectInjection(l.text, cfg.detector).blocked })),
      };
    },

    decisionList: () => decisions.list(),

    reset() {
      return enqueue(async () => {
        config = structuredClone(DEFAULT_GATEWAY_CONFIG);
        decisions.clear();
        await adminOk('PUT', '/demo/config', DEFAULT_SIDECAR_CONFIG);
        await adminOk('PUT', '/demo/fault', { mode: 'none', delayMs: 0 });
      });
    },
  };
  return api;
}
