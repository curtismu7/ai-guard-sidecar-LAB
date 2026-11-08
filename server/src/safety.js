// Safety rules. Pure functions, no I/O.
//  1. The main server binds loopback only, unless AI_GUARD_BIND opts in (the container does). The standalone sidecar
//     always binds 127.0.0.1 and has no opt-in.
//  2. Every port this app uses is in 6500-6549.
//  3. Only loopback hosts are Host-header-accepted, plus the names in LAB_ALLOWED_HOSTS (the lab-proxy's name for this app);
//     no credential header is accepted.
//  4. The gateway only ever calls a sidecar URL that is http, loopback and inside the port range.

export const PORT_MIN = 6500;
export const PORT_MAX = 6549;
export const SERVER_PORT = 6500;
export const SIDECAR_PORT = 6501;
export const EMBEDDED_SIDECAR_PORT = 6502;

const OCTET = '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)';
const LOOPBACK_V4 = new RegExp(`^127\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);
export function isLoopbackHost(host) {
  const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || LOOPBACK_V4.test(h);
}

export const portInRange = (p) => Number.isInteger(p) && p >= PORT_MIN && p <= PORT_MAX;
export const bindHost = (env = process.env) => env.AI_GUARD_BIND || '127.0.0.1';
export const serverPort = (env = process.env) => (env.AI_GUARD_PORT === undefined ? SERVER_PORT : Number(env.AI_GUARD_PORT));
export const sidecarPort = (env = process.env) => (env.AI_GUARD_SIDECAR_PORT === undefined ? SIDECAR_PORT : Number(env.AI_GUARD_SIDECAR_PORT));
export const embeddedSidecarPort = (env = process.env) => (env.AI_GUARD_EMBEDDED_PORT === undefined ? EMBEDDED_SIDECAR_PORT : Number(env.AI_GUARD_EMBEDDED_PORT));

export function assertBindAllowed(host, env = process.env) {
  if (isLoopbackHost(host) || env.AI_GUARD_BIND) return host;
  throw new Error(`refusing to bind ${host}: loopback only. Set AI_GUARD_BIND to opt in (the container does).`);
}

// The sidecar URL the gateway may call. Returns the normalised origin string; throws otherwise.
export function assertSidecarUrl(value) {
  let u;
  try { u = new URL(String(value)); } catch { throw new Error('sidecar URL is not a valid URL'); }
  if (u.protocol !== 'http:') throw new Error('sidecar URL must be http (loopback, no TLS needed)');
  if (!isLoopbackHost(u.hostname)) throw new Error('sidecar URL must be a loopback host');
  if (u.username || u.password) throw new Error('sidecar URL must not carry credentials');
  if (!portInRange(Number(u.port))) throw new Error(`sidecar URL port must be in ${PORT_MIN}-${PORT_MAX}`);
  return u.origin;
}

// Strict Host parsing: "localhost", "127.x.y.z" (each octet 0-255) or "[::1]", optionally ":port". Anything else -> null.
const HOST_RE = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])(?::(\d{1,5}))?$/i;
export function parseHost(hostHeader) {
  const m = HOST_RE.exec(String(hostHeader ?? '').trim());
  if (!m || !isLoopbackHost(m[1])) return null;
  if (m[2] !== undefined && Number(m[2]) > 65535) return null;
  return { hostname: m[1].toLowerCase().replace(/^\[|\]$/g, ''), port: m[2] === undefined ? null : Number(m[2]), host: `${m[1]}${m[2] === undefined ? '' : `:${m[2]}`}`.toLowerCase() };
}

// Rejects a missing, malformed or non-loopback Host header (DNS rebinding): 421 Misdirected Request. `extra` is the set of host
// names (no port, lower case) the lab-proxy sends in Host, from LAB_ALLOWED_HOSTS; loopback always works.
const hostName = (hostHeader) => String(hostHeader ?? '').trim().toLowerCase().replace(/:\d{1,5}$/, '');
export const makeHostGuard = (extra = new Set()) => function hostGuard(req, res, next) {
  if (!req.headers.host || !(parseHost(req.headers.host) || extra.has(hostName(req.headers.host)))) {
    return res.status(421).json({ error: 'bad_host', message: 'this server answers loopback Host headers only' });
  }
  return next();
};
export const hostGuard = makeHostGuard();

// CSRF defence for anything that is not a plain read. A page on another site can send a "simple" POST to 127.0.0.1
// without CORS permission, so the server refuses it itself:
//  - Sec-Fetch-Site: cross-site is refused;
//  - an Origin header must be an http loopback origin identical to the Host the request was sent to;
//  - a request with a body must be application/json.
const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// `publicOrigin` (se-mock only, optional) is the one extra origin allowed: the hosted UI's own https origin, which the
// ingress passes through while it rewrites Host to loopback. Nothing else is relaxed.
export function makeOriginGuard({ publicOrigin = null, allowedHosts = new Set() } = {}) {
  return function originGuard(req, res, next) {
    if (READ_METHODS.has(req.method)) return next();
    const refuse = (status, error, message) => res.status(status).json({ error, message });
    if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') return refuse(403, 'cross_site_refused', 'cross-site requests are refused');
    const origin = req.headers.origin;
    if (origin !== undefined && !(publicOrigin && origin === publicOrigin)) {
    let u = null;
    try { u = new URL(origin); } catch { /* refused below */ }
    const host = parseHost(req.headers.host);
    // Behind the lab-proxy the browser's origin is https://local.ping-devops.com:8443 while Host is this app's own name. The proxy
    // sets X-Forwarded-Host/-Proto; they are believed only when Host is one of the allowed names, so a request that did not come
    // through the proxy cannot use them.
    const xfh = String(req.headers['x-forwarded-host'] || '').toLowerCase();
    const xfp = String(req.headers['x-forwarded-proto'] || 'https').toLowerCase();
    const proxied = allowedHosts.has(hostName(req.headers.host)) && xfh !== '' && (xfp === 'https' || xfp === 'http') && origin === `${xfp}://${xfh}`;
    const same = proxied || u && u.protocol === 'http:' && u.origin !== 'null' && isLoopbackHost(u.hostname) && host
      && u.host.toLowerCase() === host.host && !u.username && !u.password && u.pathname === '/' && origin === u.origin;
    if (!same) return refuse(403, 'bad_origin', 'this server accepts same-origin loopback requests only');
  }
  const hasBody = Number(req.headers['content-length'] || 0) > 0 || req.headers['transfer-encoding'] !== undefined;
  if (hasBody && !/^application\/json\s*(;|$)/i.test(req.headers['content-type'] || '')) return refuse(415, 'unsupported_media_type', 'a request body must be application/json');
  return next();
  };
}
export const originGuard = makeOriginGuard();

// No credential is ever accepted or used. A request that carries one is refused, not ignored.
// (Cookies are not checked: they are scoped by host not port. They are never read.)
const CREDENTIAL_HEADERS = ['authorization', 'proxy-authorization', 'x-api-key'];
export function credentialGuard(req, res, next) {
  if (CREDENTIAL_HEADERS.some((h) => req.headers[h] !== undefined)) {
    return res.status(400).json({ error: 'credentials_not_accepted', message: 'this server accepts and uses no credentials' });
  }
  return next();
}
