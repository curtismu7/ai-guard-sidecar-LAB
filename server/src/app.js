// The main server: the mock gateway API under /api. createApp() is what the tests use.
// Every string in a response was masked (PII) and made inert (hidden characters visible) before it was stored.
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { createHealth } from './health.js';
import { Invalid, QueueFull, Refused, SidecarDown, createService } from './service.js';
import { assertBindAllowed, assertSidecarUrl, bindHost, credentialGuard, embeddedSidecarPort, hostGuard, makeOriginGuard, portInRange, serverPort } from './safety.js';
import { loadCustomer, DEFAULT_CUSTOMER } from './customer.js';
import { startSidecar, createSidecarState } from './sidecar.js';
import { SE_MOCK_BANNER, modeFrom, publicOriginFrom, refusedFlagsSet } from './config.js';
import { DEFAULT_WORKSPACE, WORKSPACE_HEADER, WORKSPACE_RE, createWorkspaces } from './workspaces.js';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
// 'anon-' + 16 hex characters: a valid workspace id (WORKSPACE_RE), unguessable, never reused.
const anonymousWorkspace = () => `anon-${randomBytes(8).toString('hex')}`;
const bad = (res, message, status = 400, extra = {}) => res.status(status).json({ error: status === 404 ? 'not_found' : 'bad_request', message, ...extra });
const API_HEADERS = { 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };

export const DEFAULT_WEB_DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../web/dist');
// The built UI: same-origin scripts, styles, images and fetches only. (style-src allows inline styles: React Flow sets them.)
export const UI_CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

// webDist: directory with the built UI (web/dist). null disables static serving; a missing directory leaves / a JSON 404.
// mode 'local' (default): one service, the header is ignored. mode 'se-mock': `workspaces` (a registry from
// createWorkspaces) gives each X-Workspace-Id its own runtime, and a malformed id is refused with 400.
export function createApp({ service, realService = null, workspaces = null, mode = 'local', health = createHealth(), webDist = DEFAULT_WEB_DIST, publicOrigin = null, customer = loadCustomer() } = {}) {
  const seMock = mode === 'se-mock';
  // Local mode: Mock is the embedded stand-in sidecar; Real is the external sidecar, present only when AI_GUARD_SIDECAR_URL is set.
  // The default is Real when it exists (as before), else Mock. The hosted build is Mock only and cannot be switched.
  const modeState = { source: realService ? 'real' : 'mock' };
  const registry = workspaces ?? { get: () => ({ service: modeState.source === 'real' ? realService : service }) };
  const app = express();
  app.disable('x-powered-by');
  app.use(hostGuard);
  app.use(makeOriginGuard({ publicOrigin }));
  app.use((_req, res, next) => { res.set(API_HEADERS); next(); });
  // The workspace this request works in. Static files do not need one, so the lookup is lazy for them.
  app.use((req, res, next) => {
    const id = req.headers[WORKSPACE_HEADER];
    if (seMock && id !== undefined && (typeof id !== 'string' || !WORKSPACE_RE.test(id))) return bad(res, 'X-Workspace-Id must be 1-32 characters of a-z, 0-9 and hyphen');
    // se-mock: a call with no id gets a private anonymous workspace for that request, never the shared default.
    req.workspaceId = seMock ? (id ?? anonymousWorkspace()) : DEFAULT_WORKSPACE;
    Object.defineProperty(req, 'rt', { get: () => registry.get(req.workspaceId), configurable: true });
    return next();
  });
  if (webDist && fs.existsSync(path.join(webDist, 'index.html'))) {
    app.use(express.static(webDist, {
      index: 'index.html', dotfiles: 'ignore',
      setHeaders: (res) => res.set({ ...API_HEADERS, 'Content-Security-Policy': UI_CSP }),
    }));
  }

  const api = express.Router();
  api.use(credentialGuard);
  api.use('/health', health.router);
  // A rule paste is larger than the other bodies, so its route has its own parser, ahead of the 16 KB one.
  api.put('/rules', express.json({ limit: '48kb', strict: true }), wrap(async (req, res) => {
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 1 || !('toml' in b)) return bad(res, 'body must be exactly {toml}');
    return res.json(await req.rt.service.putRules(b.toml));
  }));
  api.use(express.json({ limit: '16kb', strict: true }));

  // What the UI shows about the deployment. The banner is set only in se-mock (hosted and simulated).
  const infoBody = (req) => ({ mode: seMock ? 'se-mock' : 'local', hosted: seMock, simulated: true, workspace: req.workspaceId, banner: seMock ? SE_MOCK_BANNER : null, source: seMock ? 'mock' : modeState.source, realAvailable: !seMock && !!realService });
  api.get('/info', (req, res) => res.json(infoBody(req)));
  // The Mock/Real toggle. Body is exactly {source: "mock" | "real"}. The hosted build is fail-closed Mock; Real needs a configured sidecar.
  api.post('/mode', (req, res) => {
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 1 || !['mock', 'real'].includes(b.source)) return bad(res, 'body must be exactly {source: "mock" or "real"}');
    if (seMock) return bad(res, 'The hosted build is Mock only and cannot be switched.', 403);
    if (b.source === 'real' && !realService) return bad(res, 'Real needs AI_GUARD_SIDECAR_URL: start the server with it set to an AI Guard sidecar, then switch.', 409);
    modeState.source = b.source;
    return res.json(infoBody(req));
  });

  api.get('/scenarios', (req, res) => res.json({
    provenance: 'The sidecar contract and gateway behaviour are as understood from the demo environment (reverse-engineered), UNVERIFIED against product documentation.',
    scenarios: req.rt.service.listScenarios(),
  }));
  api.get('/h2', wrap(async (req, res) => res.json(await req.rt.service.h2())));
  api.get('/rules', wrap(async (req, res) => res.json(await req.rt.service.getRules())));
  api.delete('/rules', wrap(async (req, res) => res.json(await req.rt.service.clearRules())));
  api.get('/prompt-log', (req, res) => res.json(req.rt.service.promptLogView()));
  api.put('/prompt-log', wrap(async (req, res) => res.json(await req.rt.service.putPromptLog(req.body))));
  api.get('/stand-in', wrap(async (req, res) => res.json(await req.rt.service.standIn())));

  // Body: { scenario: "<id>" } or { custom: { requestText, upstreamText?, caller?, failClosed?, timeoutMs? } }
  api.post('/run', wrap(async (req, res) => {
    const b = req.body;
    if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 1 || !('scenario' in b || 'custom' in b)) return bad(res, 'body must be exactly one of {scenario} or {custom}');
    if ('scenario' in b) {
      if (typeof b.scenario !== 'string') return bad(res, 'scenario must be a string');
      const result = await req.rt.service.runScenario(b.scenario);
      if (!result) return bad(res, 'no such scenario', 404);
      return res.json(result);
    }
    return res.json(await req.rt.service.runCustom(b.custom));
  }));

  api.get('/decisions', (req, res) => { const decisions = req.rt.service.decisionList(); res.json({ count: decisions.length, decisions }); });
  api.get('/config', wrap(async (req, res) => res.json({ ...(await req.rt.service.getFullConfig()), customer: { ...DEFAULT_CUSTOMER, ...customer } })));
  api.put('/config', wrap(async (req, res) => res.json(await req.rt.service.putConfig(req.body))));
  api.get('/fault', wrap(async (req, res) => res.json(await req.rt.service.getFault())));
  api.put('/fault', wrap(async (req, res) => res.json(await req.rt.service.putFault(req.body))));
  api.post('/reset', wrap(async (req, res) => {
    if (req.body && Object.keys(req.body).length) return bad(res, 'POST /api/reset takes no parameters');
    await req.rt.service.reset();
    res.json({ ok: true });
  }));

  api.use((_req, res) => bad(res, 'no such endpoint', 404));
  api.use((err, _req, res, _next) => {
    if (err instanceof Refused) return bad(res, err.message, 400, { [err.key]: err.details });
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
export async function startHttpServer({ port = serverPort(), host = bindHost(), env = process.env, embeddedPort = embeddedSidecarPort(env), sidecarUrl = env.AI_GUARD_SIDECAR_URL, service: given, webDist } = {}) {
  const mode = modeFrom(env);
  assertBindAllowed(host, env);
  if (!portInRange(port)) throw new Error(`port ${port} is outside 6500-6549`);
  if (mode === 'se-mock') {
    const publicOrigin = publicOriginFrom(env);
    const refused = refusedFlagsSet(env);
    if (refused.length) throw new Error(`refusing to start in MODE=se-mock: ${refused.join(', ')} set (live features are refused by the mock-only build)`);
    if (given) throw new Error('MODE=se-mock builds its own services, one per workspace; a service cannot be supplied');
    return startSeMockServer({ port, host, env, embeddedPort, webDist, publicOrigin });
  }
  if (sidecarUrl) assertSidecarUrl(sidecarUrl);
  const embedded = await startSidecar({ port: embeddedPort }); // always: the Mock side
  const mockService = given || createService({ sidecarUrl: embedded.url });
  const realService = sidecarUrl ? createService({ sidecarUrl }) : null;
  const service = realService ?? mockService;
  const probe = async () => { try { return (await service.gateway.admin('GET', '/health')).status === 200; } catch { return false; } };
  const health = createHealth({ env, probe });
  await health.ready;
  return listen({ port, host, app: createApp({ service: mockService, realService, health, mode, ...(webDist === undefined ? {} : { webDist }) }), service, embedded, health, sidecarUrl: service.gateway.base });
}

// MODE=se-mock: the embedded sidecar keeps one state per workspace, and every workspace gets its own service (config,
// fault settings through the sidecar, decision log, run queue). The sidecar URL is never configurable here.
async function startSeMockServer({ port, host, env, embeddedPort, webDist, publicOrigin }) {
  let registry = null;
  const embedded = await startSidecar({ port: embeddedPort, stateFor: (id) => registry.get(id).sidecar });
  registry = createWorkspaces({ create: (id) => ({ sidecar: createSidecarState(), service: createService({ sidecarUrl: embedded.url, workspace: id }) }) });
  const service = registry.get(DEFAULT_WORKSPACE).service;
  const probe = async () => { try { return (await service.gateway.admin('GET', '/health')).status === 200; } catch { return false; } };
  const health = createHealth({ env, probe });
  await health.ready;
  return listen({ port, host, app: createApp({ workspaces: registry, mode: 'se-mock', health, publicOrigin, ...(webDist === undefined ? {} : { webDist }) }), service, embedded, health, sidecarUrl: embedded.url });
}

function listen({ port, host, app, service, embedded, health, sidecarUrl }) {
  return new Promise((resolve, reject) => {
    const httpServer = app.listen(port, host);
    const cleanup = async () => { health.stop(); await embedded?.close(); };
    httpServer.once('error', async (e) => { await cleanup(); reject(e); });
    httpServer.once('listening', () => {
      const { port: bound } = httpServer.address();
      resolve({
        port: bound, address: httpServer.address().address, service, embedded, url: `http://127.0.0.1:${bound}/`, sidecarUrl,
        close: async () => { await new Promise((r) => { httpServer.closeAllConnections?.(); httpServer.close(r); }); await cleanup(); },
      });
    });
  });
}
