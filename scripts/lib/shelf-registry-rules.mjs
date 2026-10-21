// A copy of the validation rules in demo-shelf's server/src/registry.js (validateDemos, checkPath, checkOrigin and their constants),
// reduced to returning a list of problems. Copied, not imported: this repo never reads the shelf repo at runtime.
// Copy includes the `where` / `hostedUrl` fields. If the shelf's rules change, update this copy.
import path from 'node:path';

const ID = /^[a-z0-9][a-z0-9-]{1,40}$/;
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const SHELL_CHARS = /[;&|$`<>\\"'*?(){}!#\n\r\t\0]/;
const WHERE = ['installed', 'hosted', 'both'];
const FIELDS = ['id', 'name', 'catalogId', 'kind', 'description', 'url', 'where', 'hostedUrl', 'healthPath', 'composeFile', 'composeOverlays', 'notes'];

function checkPath(label, p, errors) {
  if (typeof p !== 'string' || !path.isAbsolute(p)) return errors.push(`${label} must be an absolute path`);
  if (SHELL_CHARS.test(p)) return errors.push(`${label} contains shell characters`);
  if (p.split('/').includes('..')) return errors.push(`${label} must not contain ".."`);
  if (!/\.ya?ml$/.test(p)) errors.push(`${label} must be a .yml or .yaml file`);
}

function checkOrigin(label, value, errors) {
  try {
    const u = new URL(value);
    const host = u.hostname.toLowerCase();
    if (u.protocol !== 'http:' && u.protocol !== 'https:') errors.push(`${label} must be http or https`);
    else if (u.username || u.password) errors.push(`${label} must not carry credentials`);
    else if (u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) errors.push(`${label} must be an origin only (no path, query or fragment)`);
    else if (!LOOPBACK.has(host)) errors.push(`${label}: host "${host}" is not loopback`);
  } catch { errors.push(`${label} is not a valid URL`); }
}

export function shelfProblems(demos) {
  const errors = [];
  if (!Array.isArray(demos)) return ['"demos" must be an array'];
  const seen = new Set();
  demos.forEach((d, i) => {
    const at = `demos[${i}]${d && typeof d.id === 'string' ? ` (${d.id})` : ''}`;
    if (!d || typeof d !== 'object' || Array.isArray(d)) return errors.push(`${at} must be an object`);
    if (typeof d.id !== 'string' || !ID.test(d.id)) errors.push(`${at}: id must match ${ID}`);
    else if (seen.has(d.id)) errors.push(`${at}: duplicate id`);
    else seen.add(d.id);
    for (const f of ['name', 'description']) {
      if (typeof d[f] !== 'string' || !d[f].trim() || d[f].length > 300) errors.push(`${at}: ${f} must be a non-empty string up to 300 characters`);
    }
    for (const f of ['catalogId', 'kind']) {
      if (d[f] !== undefined && (typeof d[f] !== 'string' || d[f].length > 40)) errors.push(`${at}: ${f} must be a short string`);
    }
    const where = d.where === undefined ? 'installed' : d.where;
    if (!WHERE.includes(where)) errors.push(`${at}: where must be one of ${WHERE.join(', ')}`);
    if (where !== 'hosted' || d.url !== undefined) checkOrigin(`${at}: url`, d.url, errors);
    if (where === 'hosted' || where === 'both' || d.hostedUrl !== undefined) {
      if (d.hostedUrl === undefined) errors.push(`${at}: hostedUrl is required when where is "${where}"`);
      else checkOrigin(`${at}: hostedUrl`, d.hostedUrl, errors);
    }
    const hp = d.healthPath === undefined ? '/api/health' : d.healthPath;
    if (typeof hp !== 'string' || !/^\/[A-Za-z0-9._~\-/]*$/.test(hp) || hp.startsWith('//') || hp.includes('..')) errors.push(`${at}: healthPath must be a plain path starting with "/"`);
    if (d.composeFile !== undefined) checkPath(`${at}: composeFile`, d.composeFile, errors);
    if (d.composeOverlays !== undefined) {
      if (!Array.isArray(d.composeOverlays)) errors.push(`${at}: composeOverlays must be an array of absolute paths`);
      else d.composeOverlays.forEach((o, j) => checkPath(`${at}: composeOverlays[${j}]`, o, errors));
      if (d.composeFile === undefined && d.composeOverlays?.length) errors.push(`${at}: composeOverlays needs composeFile`);
    }
    for (const k of Object.keys(d)) if (!FIELDS.includes(k)) errors.push(`${at}: unknown field ${k} (the shelf drops it)`);
  });
  return errors;
}
