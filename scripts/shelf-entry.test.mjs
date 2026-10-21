import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { shelfProblems } from './lib/shelf-registry-rules.mjs';

const read = (f) => fs.readFileSync(new URL(f, import.meta.url), 'utf8');
const entry = JSON.parse(read('../docs/shelf-entry.json'));

test('docs/shelf-entry.json passes the shelf registry rules (copied into scripts/lib/shelf-registry-rules.mjs)', () => {
  assert.deepEqual(shelfProblems(entry.demos), []);
});

test('the entry matches this app: id, catalog D12, port 6500, /api/health, compose file name', () => {
  const [d] = entry.demos;
  assert.equal(d.id, 'ai-guard-sidecar');
  assert.equal(d.catalogId, 'D12');
  assert.equal(d.url, 'http://localhost:6500');
  assert.equal(d.healthPath, '/api/health');
  assert.match(d.composeFile, /\/docker-compose\.yml$/);
  const pkg = JSON.parse(read('../package.json'));
  assert.ok(pkg.scripts.start && pkg.scripts.doctor);
  assert.match(read('../docker-compose.yml'), /127\.0\.0\.1:\$\{HOST_PORT:-6500\}:6500/);
});

test('the copied rules reject a bad entry', () => {
  const bad = [{ ...entry.demos[0], url: 'http://evil.example:6500', healthPath: '//x', composeFile: 'relative.yml' }];
  assert.ok(shelfProblems(bad).length >= 3);
  assert.ok(shelfProblems([{ ...entry.demos[0], where: 'both' }]).length >= 1, 'where=both needs hostedUrl');
});
