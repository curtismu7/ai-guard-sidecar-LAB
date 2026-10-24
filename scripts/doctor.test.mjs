// `npm run doctor` port checks follow the mode: MODE=se-mock never runs the standalone sidecar, so it does not check its port.
// Reads the doctor's printed lines only (no node:test output is parsed). Loopback only.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const doctor = (env) => spawnSync(process.execPath, [path.join(root, 'scripts/doctor.mjs')], {
  cwd: root, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8',
});
const checked = (out) => out.split('\n').filter((l) => /^(PASS|FAIL|INFO)/.test(l)).map((l) => l.split(':')[0].trim().split(/\s+/).pop());

test('MODE=se-mock: the doctor checks the server and embedded sidecar ports, never the standalone sidecar', () => {
  const r = doctor({ MODE: 'se-mock', AI_GUARD_PORT: '6541', AI_GUARD_EMBEDDED_PORT: '6542' });
  assert.ok(checked(r.stdout).includes('port-server'), r.stdout);
  assert.ok(checked(r.stdout).includes('port-embedded-sidecar'), r.stdout);
  assert.ok(!checked(r.stdout).includes('port-standalone-sidecar'), r.stdout);
});

test('MODE unset (local): the standalone sidecar port is still checked', () => {
  const r = doctor({ AI_GUARD_PORT: '6543', AI_GUARD_EMBEDDED_PORT: '6544' });
  assert.ok(checked(r.stdout).includes('port-standalone-sidecar'), r.stdout);
});
