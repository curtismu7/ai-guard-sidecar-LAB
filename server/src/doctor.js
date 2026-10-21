// Preflight checks shared by `npm run doctor` and GET /api/health. Synchronous, no network, never prints a setting's value.
// Each check: { id, level: 'pass' | 'info' | 'fail', detail }.
import { PORT_MAX, PORT_MIN, assertBindAllowed, assertSidecarUrl, bindHost, embeddedSidecarPort, portInRange, serverPort, sidecarPort } from './safety.js';

export function runChecks({ env = process.env } = {}) {
  const checks = [];
  const add = (id, level, detail) => checks.push({ id, level, detail });

  const major = Number(process.versions.node.split('.')[0]);
  add('node', major >= 20 ? 'pass' : 'fail', `v${process.versions.node} (need >= 20)`);

  try { add('bind', 'pass', `${assertBindAllowed(bindHost(env), env)}${env.AI_GUARD_BIND ? ' (AI_GUARD_BIND opt-in)' : ' (loopback)'}; the standalone sidecar is always loopback`); }
  catch (e) { add('bind', 'fail', e.message); }

  const ports = { server: serverPort(env), sidecar: sidecarPort(env), embedded: embeddedSidecarPort(env) };
  const bad = Object.entries(ports).filter(([, p]) => !portInRange(p));
  add('port-range', bad.length ? 'fail' : 'pass', bad.length
    ? `outside ${PORT_MIN}-${PORT_MAX}: ${bad.map(([k, p]) => `${k} ${p}`).join(', ')}`
    : `server ${ports.server}, standalone sidecar ${ports.sidecar}, embedded sidecar ${ports.embedded} (all within ${PORT_MIN}-${PORT_MAX})`);

  if (env.AI_GUARD_SIDECAR_URL) {
    try { assertSidecarUrl(env.AI_GUARD_SIDECAR_URL); add('sidecar-url', 'pass', 'external sidecar URL is http, loopback and in range'); }
    catch (e) { add('sidecar-url', 'fail', e.message); }
  } else add('sidecar-url', 'pass', 'default: an embedded stand-in sidecar on loopback, called over HTTP');

  add('detector', 'info', 'STAND-IN heuristics, not a real classifier; no model, no download');
  add('outbound', 'pass', 'no outbound settings: the gateway calls a loopback sidecar only; credentials are never accepted or sent');
  return checks;
}

export const allPassed = (checks) => checks.every((c) => c.level !== 'fail');
