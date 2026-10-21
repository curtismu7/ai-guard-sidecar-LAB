import { fileURLToPath } from 'node:url';
import { startHttpServer } from './app.js';
import { allPassed, runChecks } from './doctor.js';

// Local runs read the repo-root .env (real env vars win).
try { process.loadEnvFile(fileURLToPath(new URL('../../.env', import.meta.url))); } catch { /* no .env */ }

const checks = runChecks();
if (!allPassed(checks)) {
  for (const c of checks.filter((x) => x.level === 'fail')) console.error(`[ai-guard-sidecar] refusing to start: ${c.id}: ${c.detail}`);
  process.exit(1);
}
const { url, sidecarUrl, embedded } = await startHttpServer();
console.log(`[ai-guard-sidecar] mock gateway + API at ${url} (loopback unless AI_GUARD_BIND is set)`);
console.log(`[ai-guard-sidecar] ${embedded ? 'embedded' : 'external'} STAND-IN sidecar at ${sidecarUrl} (not a real classifier)`);
console.log(`[ai-guard-sidecar] API: GET ${url}api/health | GET ${url}api/scenarios | POST ${url}api/run | GET ${url}api/decisions`);
