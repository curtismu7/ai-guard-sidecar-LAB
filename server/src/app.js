// The main server: the mock gateway API under /api. createApp() is what the tests use.
// Every string in a response was masked (PII) and made inert (hidden characters visible) before it was stored.
import express from 'express';
import { createHealth } from './health.js';
import { Invalid, QueueFull, SidecarDown, createService } from './service.js';
import { assertBindAllowed, assertSidecarUrl, bindHost, credentialGuard, embeddedSidecarPort, hostGuard, originGuard, portInRange, serverPort } from './safety.js';
import { startSidecar } from './sidecar.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, message, status = 400) => res.status(status).json({ error: status === 404 ? 'not_found' : 'bad_request', message });
const API_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

export function createApp({ service, health = createHealth() } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  app.use(originGuard);
  app.use((_req, res, next) => { res.set(API_HEADERS); next(); });

  const api = express.Router();
  api.use(credentialGuard);
  api.use('/health', health.router);
  api.use(express.json({ limit: '16kb', strict: true }));

  api.get('/scenarios', (_req, res) => res.json({
    provenance: 'The sidecar contract and gateway behaviour are as understood from the demo environment (reverse-engineered), UNVERIFIED against product documentation.',
    scenarios: service.listScenarios(),
  }));
  api.get('/stand-in', wrap(async (_req, res) => res.json(await service.standIn())));

  // Body: { scenario: "<id>" } or { custom: { requestText, upstreamText?, caller?, failClosed?, timeoutMs? } }
  api.post('/run', wrap(async (req, res) => {
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 1 || !('scenario' in b || 'custom' in b)) return bad(res, 'body must be exactly one of {scenario} or {custom}');
    if ('scenario' in b) {
      if (typeof b.scenario !== 'string') return bad(res, 'scenario must be a string');
      const result = await service.runScenario(b.scenario);
      if (!result) return bad(res, 'no such scenario', 404);
      return res.json(result);
    }
    return res.json(await service.runCustom(b.custom));
  }));

  api.get('/decisions', (_req, res) => { const decisions = service.decisionList(); res.json({ count: decisions.length, decisions }); });
  api.get('/config', wrap(async (_req, res) => res.json(await service.getFullConfig())));
  api.put('/config', wrap(async (req, res) => res.json(await service.putConfig(req.body))));
  api.get('/fault', wrap(async (_req, res) => res.json(await service.getFault())));
  api.put('/fault', wrap(async (req, res) => res.json(await service.putFault(req.body))));
  api.post('/reset', wrap(async (req, res) => {
    if (req.body && Object.keys(req.body).length) return bad(res, 'POST /api/reset takes no parameters');
    await service.reset();
    res.json({ ok: true });
  }));

  api.use((_req, res) => bad(res, 'no such endpoint', 404));
  api.use((err, _req, res, _next) => {
    if (err instanceof Invalid) return bad(res, err.message);
    if (err instanceof QueueFull) return res.set('Retry-After', '2').status(429).json({ error: 'run_queue_full', message: 'runs are queued; try again shortly' });
    if (err instanceof SidecarDown) return res.status(503).json({ error: 'sidecar_unavailable', message: err.message });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large', message: 'request body is too large' });
    if (err.type === 'entity.parse.failed') return bad(res, 'request body is not valid JSON');
    if (err instanceof URIError || err.status === 400) return bad(res, 'malformed request');
    console.error('[ai-guard-sidecar] api error:', err.message);
    return res.status(500).json({ error: 'server_error' });
  });
  app.use('/api', api);
  app.use((_req, res) => bad(res, 'no such endpoint', 404));
  app.use((err, _req, res, _next) => (err instanceof URIError || err.status === 400 ? bad(res, 'malformed request') : res.status(500).json({ error: 'server_error' })));
  return app;
}

// Boot the main server on `port`. Unless `sidecarUrl` points at an external sidecar, an embedded stand-in sidecar is
// started on `embeddedPort` (loopback) and the gateway calls it over HTTP like any other.
export async function startHttpServer({ port = serverPort(), host = bindHost(), env = process.env, embeddedPort = embeddedSidecarPort(env), sidecarUrl = env.AI_GUARD_SIDECAR_URL, service: given } = {}) {
  assertBindAllowed(host, env);
  if (!portInRange(port)) throw new Error(`port ${port} is outside 6500-6549`);
  if (sidecarUrl) assertSidecarUrl(sidecarUrl);
  const embedded = sidecarUrl ? null : await startSidecar({ port: embeddedPort });
  const service = given || createService({ sidecarUrl: sidecarUrl || embedded.url });
  const probe = async () => { try { return (await service.gateway.admin('GET', '/health')).status === 200; } catch { return false; } };
  const health = createHealth({ env, probe });
  await health.ready;
  return new Promise((resolve, reject) => {
    const httpServer = createApp({ service, health }).listen(port, host);
    const cleanup = async () => { health.stop(); await embedded?.close(); };
    httpServer.once('error', async (e) => { await cleanup(); reject(e); });
    httpServer.once('listening', () => {
      const { port: bound } = httpServer.address();
      resolve({
        port: bound, address: httpServer.address().address, service, embedded, url: `http://127.0.0.1:${bound}/`, sidecarUrl: service.gateway.base,
        close: async () => { await new Promise((r) => { httpServer.closeAllConnections?.(); httpServer.close(r); }); await cleanup(); },
      });
    });
  });
}
