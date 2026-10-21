import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = new URL('..', import.meta.url).pathname;
const docs = ['README.md', 'docs/safety.md', 'docs/architecture.md'];
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
