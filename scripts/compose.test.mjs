import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';

// Every published port must be bound to loopback on the host. A small line parser (no YAML dependency):
// the list items under each `ports:` key.
export function publishedPorts(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)ports:\s*$/.exec(lines[i]);
    if (!m) continue;
    for (let j = i + 1; j < lines.length; j++) {
      const item = /^\s*-\s*["']?([^"'\s#]+)["']?/.exec(lines[j]);
      if (!item || lines[j].search(/\S/) <= m[1].length) break;
      out.push(item[1]);
    }
  }
  return out;
}

const compose = fs.readFileSync(new URL('../docker-compose.yml', import.meta.url), 'utf8');
const code = compose.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
const dockerfile = fs.readFileSync(new URL('../Dockerfile', import.meta.url), 'utf8').split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');

test('docker-compose.yml publishes only on 127.0.0.1, in 6500-6549', () => {
  const ports = publishedPorts(compose);
  assert.ok(ports.length > 0, 'the parser found the published port');
  for (const p of ports) {
    assert.match(p, /^127\.0\.0\.1:/, `${p} must start with 127.0.0.1:`);
    for (const n of p.replace(/^127\.0\.0\.1:/, '').match(/\d+/g).map(Number)) assert.ok(n >= 6500 && n <= 6549, `${p}: port ${n} outside 6500-6549`);
  }
});

test('only the main server port is published; the embedded sidecar is not', () => {
  assert.deepEqual(publishedPorts(compose), ['127.0.0.1:${HOST_PORT:-6500}:6500']);
});

test('the parser flags an unbound or wildcard publish', () => {
  for (const bad of ['- "6500:6500"', '- "0.0.0.0:6500:6500"', '- 6500']) {
    const ports = publishedPorts(`services:\n  a:\n    ports:\n      ${bad}\n`);
    assert.equal(ports.length, 1);
    assert.doesNotMatch(ports[0], /^127\.0\.0\.1:/);
  }
});

test('compose gives the container no host access: no mounts, docker socket, host network or privilege', () => {
  assert.doesNotMatch(code, /^\s*volumes:/m);
  assert.doesNotMatch(code, /docker\.sock/);
  assert.doesNotMatch(code, /network_mode|privileged|pid:\s*host/);
  assert.match(code, /no-new-privileges:true/);
  assert.match(code, /read_only:\s*true/);
  assert.match(code, /cap_drop:\s*\[ALL\]/);
});

test('the Dockerfile runs as non-root and exposes only 6500', () => {
  assert.match(dockerfile, /^USER node$/m);
  assert.match(dockerfile, /^EXPOSE 6500$/m);
  assert.doesNotMatch(dockerfile, /EXPOSE (?!6500$)/m);
});

test('the healthcheck uses /api/health, in compose and in the Dockerfile', () => {
  assert.match(code, /\/api\/health/);
  assert.match(dockerfile, /^HEALTHCHECK .*\/api\/health/m);
});

test('the pre-commit hook runs gitleaks', () => {
  assert.match(fs.readFileSync(new URL('../.githooks/pre-commit', import.meta.url), 'utf8'), /gitleaks protect --staged/);
});

test('compose passes a usable SHELF_URL so the header Shelf button shows in Docker', () => {
  assert.match(code, /SHELF_URL:\s*\$\{SHELF_URL:-http:\/\/127\.0\.0\.1:4400\}/);
});
