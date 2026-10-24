// GET /api/health, contract demo-health/1 (the demo shelf's docs/health-contract.md).
// Public, GET only, no counts or detail. The state comes from the doctor checks plus a loopback probe of the sidecar,
// refreshed in the background every 60 s; a request never runs them.
import fs from 'node:fs';
import express from 'express';
import { allPassed, runChecks as defaultChecks } from './doctor.js';
import { modeFrom } from './config.js';

const { version } = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const DEMO = { id: 'ai-guard-sidecar', name: 'AI Guard Sidecar', version };
// The doctor fails an invalid MODE, so the reply only reports 'invalid' for a server that should not be serving.
const modeOf = (env) => { try { return modeFrom(env); } catch { return 'invalid'; } };

export function createHealth({ runChecks = defaultChecks, probe = async () => true, now = () => new Date(), intervalMs = 60_000, env = process.env } = {}) {
  let last = { state: 'unknown', at: null };
  async function refresh() {
    try {
      const ok = allPassed(runChecks({ env })) && await probe();
      last = { state: ok ? 'ready' : 'broken', at: now().toISOString() };
    } catch { last = { state: 'unknown', at: now().toISOString() }; }
  }
  const first = refresh();
  const timer = setInterval(refresh, intervalMs);
  timer.unref();

  const router = express.Router();
  router.get('/', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ schema: 'demo-health/1', at: last.at || now().toISOString(), state: last.state, runtime: 'offline', mode: modeOf(env), demo: DEMO });
  });
  router.all('/', (_req, res) => res.set('Allow', 'GET').status(405).json({ error: 'method_not_allowed' }));
  return { router, refresh, ready: first, stop: () => clearInterval(timer) };
}
