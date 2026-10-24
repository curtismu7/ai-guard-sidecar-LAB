// Deployment mode (rule 18). MODE=local (default) is the standalone demo. MODE=se-mock is the mock-only SE k8s build:
// the same code, with live features refused at startup and per-visitor workspaces. Unknown values are an error, never
// a silent fallback.
export const MODES = Object.freeze(['local', 'se-mock']);

// Settings that point the app at something outside the demo. Refused (not ignored) in se-mock.
export const REFUSED_IN_SE_MOCK = Object.freeze(['AI_GUARD_SIDECAR_URL', 'AI_GUARD_SIDECAR_PORT']);

export const SE_MOCK_BANNER = 'HOSTED SIMULATION: every decision here is synthetic. The detector is a deterministic keyword stand-in, not a real classifier. No tenant, no network, no credentials. This is a shared hosted demo: your workspace is private to this browser tab and held in memory only.';

export function modeFrom(env = process.env) {
  const m = env.MODE === undefined || env.MODE === '' ? 'local' : env.MODE;
  if (!MODES.includes(m)) throw new Error(`MODE=${String(m).slice(0, 20)} is not available: use ${MODES.join(' or ')}`);
  return m;
}

export const isSeMock = (env = process.env) => modeFrom(env) === 'se-mock';

// The https origin the hosted UI is served from (se-mock only). The ingress rewrites Host to loopback but passes the
// browser's Origin through, so writes from this one origin are allowed. No port, no path, no other origin.
const PUBLIC_ORIGIN_RE = /^https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*$/;
export function publicOriginFrom(env = process.env) {
  const v = env.AI_GUARD_PUBLIC_ORIGIN;
  if (v === undefined || v === '') return null;
  if (!PUBLIC_ORIGIN_RE.test(v)) throw new Error('AI_GUARD_PUBLIC_ORIGIN must be https://<host> with no port or path');
  return v;
}

export function refusedFlagsSet(env = process.env) {
  return REFUSED_IN_SE_MOCK.filter((k) => env[k] !== undefined && env[k] !== '');
}
