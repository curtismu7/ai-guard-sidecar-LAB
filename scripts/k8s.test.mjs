// Rule 18 (mock-only SE build): the manifests keep their safety properties. Text checks on the YAML-ish files, no yaml
// dependency, no cluster. Keys are matched as whole words so a comment cannot satisfy a check.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = new URL('..', import.meta.url);
const read = (f) => fs.readFileSync(new URL(f, root), 'utf8');
const uncommented = (t) => t.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
const dep = uncommented(read('k8s/deployment.yaml'));
const run = (env, cwd = fileURLToPath(root)) => spawnSync('bash', ['k8s/deploy.sh', '--dry-run'], { cwd, env: { PATH: process.env.PATH, ...env }, encoding: 'utf8' });
const ok = { OWNER_APPROVED: '1', NAMESPACE: 'demo-ns', IMAGE: 'registry.example/team/ai-guard-sidecar:abc1234', SE_HOST: 'guard.demo.example' };
const without = (k) => { const e = { ...ok }; delete e[k]; return e; };

test('the deployment is mock-only, non-root, read-only, limited and probed on /api/health', () => {
  for (const re of [/- \{ name: MODE, value: se-mock \}/, /runAsNonRoot: true/, /readOnlyRootFilesystem: true/, /allowPrivilegeEscalation: false/,
    /capabilities: \{ drop: \["ALL"\] \}/, /limits: \{ cpu: 500m, memory: 256Mi \}/, /automountServiceAccountToken: false/, /seccompProfile: \{ type: RuntimeDefault \}/,
    /containerPort: 6500/, /AI_GUARD_BIND, value: 0\.0\.0\.0/]) assert.match(dep, re, String(re));
  assert.equal((dep.match(/path: \/api\/health/g) || []).length, 2, 'readiness and liveness');
  assert.match(dep, /replicas: 1\b/);
  assert.doesNotMatch(dep, /image: \S*:(latest|HEAD)\b/);
  assert.doesNotMatch(dep, /MODE, value: (local|live|prod|mock)\b/i);
});

test('no privileged container, no hostPath, no secret, no service-account token', () => {
  assert.doesNotMatch(dep, /privileged:\s*true/);
  assert.doesNotMatch(dep, /hostPath|hostNetwork|hostPID|hostIPC/);
  assert.doesNotMatch(dep, /secretKeyRef|secretRef|kind: Secret|password|apiKey|(^|\s)token:/i);
  assert.doesNotMatch(dep, /runAsUser: 0\b/);
});

test('no secret, tenant id, credential or real host sits in the manifests or the script', () => {
  for (const f of ['k8s/deployment.yaml', 'k8s/service.yaml', 'k8s/ingress.yaml', 'k8s/deploy.sh']) {
    assert.doesNotMatch(read(f), /secretKeyRef|kind: Secret|password|(^|\s)token:|apiKey|ping-devops|ghcr\.io\/[a-z]/i, f);
  }
  assert.match(read('k8s/ingress.yaml'), /host: __SE_HOST__/, 'the host is supplied, never defaulted');
  assert.match(read('k8s/ingress.yaml'), /upstream-vhost: "127\.0\.0\.1:6500"/, 'loopback Host for the pod');
});

test('the image is a placeholder and the only tokens are __IMAGE__ and __SE_HOST__: no namespace field, no ${...} forms', () => {
  assert.match(dep, /image: __IMAGE__/);
  for (const f of ['k8s/deployment.yaml', 'k8s/service.yaml', 'k8s/ingress.yaml']) {
    const t = read(f);
    assert.doesNotMatch(t, /^\s*namespace:/m, f);
    assert.doesNotMatch(t, /\$\{[^}]*\}/, f);
    for (const tok of t.match(/__[A-Z0-9_]+__/g) || []) assert.ok(['__IMAGE__', '__SE_HOST__'].includes(tok), `${f}: ${tok}`);
  }
  assert.doesNotMatch(read('k8s/deploy.sh'), /envsubst/);
});

test('the Dockerfile is one image for both forms: MODE defaults to local, the same two stages, non-root', () => {
  const d = read('Dockerfile');
  assert.match(d, /ENV[^\n]*MODE=local/);
  assert.equal((d.match(/^FROM /gm) || []).length, 2);
  assert.match(d, /USER node/);
});

test('deploy.sh refuses without approval and renders with valid values (no kubectl needed)', () => {
  assert.equal(run({}).status, 2, 'no approval');
  assert.equal(run({ ...ok, OWNER_APPROVED: '0' }).status, 2);
  const r = run(ok);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /image: registry\.example\/team\/ai-guard-sidecar:abc1234/);
  assert.match(r.stdout, /host: guard\.demo\.example/);
  assert.doesNotMatch(r.stdout, /__[A-Z0-9_]+__|\$\{/);
});

test('deploy.sh refuses a missing value, an immutable-tag violation, a bad host or a bad namespace', () => {
  for (const k of ['NAMESPACE', 'IMAGE', 'SE_HOST']) assert.notEqual(run(without(k)).status, 0, `missing ${k}`);
  for (const IMAGE of ['registry.example/x:latest', 'registry.example/x:HEAD', 'registry.example/x', 'registry.example/x:', 'registry.example:5000/x', 'registry.example:5000/team/x', 'registry.example:5000/team/x@', 'reg;rm/x:1', 'reg|x/y:1', 'reg/x:1\nfoo']) assert.equal(run({ ...ok, IMAGE }).status, 2, JSON.stringify(IMAGE));
  for (const SE_HOST of ['Bad Host', 'a|b.example', 'a/b.example', 'a&b.example', 'a\\b.example', 'a.example\nb.example', '']) assert.notEqual(run({ ...ok, SE_HOST }).status, 0, JSON.stringify(SE_HOST));
  for (const NAMESPACE of ['', 'Demo', '-ns', 'ns-', 'a_b', 'a.b', 'a|b', 'ns\nx', 'a'.repeat(64)]) assert.notEqual(run({ ...ok, NAMESPACE }).status, 0, JSON.stringify(NAMESPACE));
});

test('deploy.sh --dry-run fails when a rendered manifest keeps a stray __TOKEN__ (temp copy, tracked files untouched)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'k8s-copy-'));
  try {
    fs.cpSync(new URL('k8s', root), tmp, { recursive: true });
    fs.appendFileSync(path.join(tmp, 'service.yaml'), '# stray __EXTRA_TOKEN__\n');
    const r = spawnSync('bash', [path.join(tmp, 'deploy.sh'), '--dry-run'], { env: { PATH: process.env.PATH, ...ok }, encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /__EXTRA_TOKEN__/);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
