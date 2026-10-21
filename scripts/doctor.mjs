// Preflight: the same checks GET /api/health reports from, plus whether the ports are free.
// Prints only pass/fail lines, never the value of a setting. Exit 1 on any failure. Needs no network.
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
try { process.loadEnvFile(path.join(root, '.env')); } catch { /* optional */ }

const { runChecks } = await import(pathToFileURL(path.join(root, 'server/src/doctor.js')));
const { serverPort, sidecarPort, embeddedSidecarPort } = await import(pathToFileURL(path.join(root, 'server/src/safety.js')));
let failed = 0;
const report = (level, name, detail) => {
  if (level === 'fail') failed++;
  console.log(`${level.toUpperCase().padEnd(4)}  ${name}: ${detail}`);
};

for (const c of runChecks()) report(c.level, c.id, c.detail);

const free = (port) => new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', (e) => resolve(e.code));
  s.listen(port, '127.0.0.1', () => s.close(() => resolve(null)));
});
const wanted = [['server', serverPort()], ['standalone-sidecar', sidecarPort()]];
if (!process.env.AI_GUARD_SIDECAR_URL) wanted.push(['embedded-sidecar', embeddedSidecarPort()]);
for (const [name, port] of wanted) {
  const err = await free(port);
  report(err ? 'fail' : 'pass', `port-${name}`, err ? `${port} is not free (${err}). Set AI_GUARD_PORT, AI_GUARD_SIDECAR_PORT or AI_GUARD_EMBEDDED_PORT in .env to a free port in 6500-6549` : `${port} is free`);
}

process.exit(failed ? 1 : 0);
