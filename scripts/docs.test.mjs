import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const docs = ['README.md', 'docs/safety.md', 'docs/architecture.md', 'docs/k8s.md'];
const read = (f) => fs.readFileSync(path.join(root, f), 'utf8');

test('relative links in README and docs resolve to files that exist', () => {
  for (const d of docs) {
    for (const m of read(d).matchAll(/\]\((?!https?:|#|mailto:)([^)#\s]+)/g)) {
      assert.ok(fs.existsSync(path.resolve(path.dirname(path.join(root, d)), m[1])), `${d} links to missing ${m[1]}`);
    }
  }
});

test('every npm script and source file the docs name exists', () => {
  const pkg = JSON.parse(read('package.json'));
  for (const d of docs) {
    for (const m of read(d).matchAll(/npm run ([\w-]+)(?! -w)/g)) assert.ok(pkg.scripts[m[1]], `${d}: npm run ${m[1]} does not exist`);
    for (const m of read(d).matchAll(/`((?:server|scripts)\/[\w./-]+\.(?:js|mjs))`/g)) assert.ok(fs.existsSync(path.join(root, m[1])), `${d} names missing file ${m[1]}`);
  }
});

test('the docs carry the provenance statement and the stand-in warning', () => {
  for (const d of ['README.md', 'docs/safety.md']) {
    assert.match(read(d), /UNVERIFIED against product documentation/, d);
    assert.match(read(d), /stand-in/i, d);
  }
  assert.match(read('docs/architecture.md'), /UNVERIFIED against product documentation/);
  assert.match(read('docs/safety.md'), /no claim/i);
});

test('every scenario id named in the README exists, and every scenario is named', async () => {
  const { SCENARIOS } = await import('../server/src/scenarios.js');
  const readme = read('README.md');
  for (const s of SCENARIOS) assert.ok(readme.includes(`\`${s.id}\``), `README does not mention scenario ${s.id}`);
});

test('every port in the docs is inside 6500-6549 (apart from the named real-sidecar ports we avoid)', () => {
  for (const d of docs) {
    for (const m of read(d).matchAll(/127\.0\.0\.1:(\d{4,5})/g)) {
      const n = Number(m[1]);
      assert.ok(n >= 6500 && n <= 6549, `${d}: ${m[0]}`);
    }
  }
});

test('the size limits the docs state are the ones in the code', async () => {
  const { LIMITS } = await import('../server/src/sidecar.js');
  const { MAX_QUEUE, CUSTOM_MAX_CHARS } = await import('../server/src/service.js');
  const { MAX_DECISIONS } = await import('../server/src/decisions.js');
  const { MAX_RESPONSE_BYTES } = await import('../server/src/gateway.js');
  const row = read('docs/safety.md').split('\n').find((l) => l.startsWith('| Bounded input'));
  assert.ok(row.includes(`custom text ${CUSTOM_MAX_CHARS.toLocaleString('en-US')} characters`), row);
  assert.ok(row.includes(`sidecar body ${LIMITS.bodyBytes / 1024} KB, ${LIMITS.units} units, ${LIMITS.textChars.toLocaleString('en-US')} characters per unit`), row);
  assert.ok(row.includes(`over ${MAX_RESPONSE_BYTES / 1024} KB`), row);
  const queue = read('docs/safety.md').split('\n').find((l) => l.startsWith('| Capped queue'));
  assert.ok(queue.includes(`at most ${MAX_QUEUE} running`) && queue.includes(`keeps ${MAX_DECISIONS} entries`), queue);
  assert.ok(row.includes('API body 16 KB'));
});

test('the docs do not describe finished work as a later step', () => {
  for (const d of docs) assert.doesNotMatch(read(d), /a later step|when the UI exists|CI still scans/, d);
});

test('CLAUDE.md and the talk track exist and name the app port', () => {
  for (const f of ['CLAUDE.md', 'docs/talk-track.md']) {
    assert.ok(fs.existsSync(path.join(root, f)), `${f} is missing`);
    assert.match(read(f), /6500/, `${f} does not mention port 6500`);
  }
});
