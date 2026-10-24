import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DEFAULT_WORKSPACE, MAX_WORKSPACES, WORKSPACE_TTL_MS, createWorkspaces } from '../src/workspaces.js';

const clock = () => { let t = 0; return { now: () => t, set: (v) => { t = v; } }; };
const reg = (opts = {}) => createWorkspaces({ create: (id) => ({ id }), ...opts });

test('ids are validated: 1-32 of a-z, 0-9 and hyphen, first character alphanumeric', () => {
  const r = reg();
  for (const bad of ['', 'A', 'Default', '../x', 'a b', 'a'.repeat(33), '-a', 'a_b', 'a.b', '__proto__', 'a/b', 'ä', 'a\nb']) {
    assert.throws(() => r.get(bad), /invalid workspace id/, JSON.stringify(bad));
  }
  assert.equal(r.get('a'.repeat(32)).id, 'a'.repeat(32));
  assert.equal(r.get('w-1').id, 'w-1');
});

test('the same id gets the same runtime; the default workspace is used when no id is given', () => {
  const r = reg();
  assert.equal(r.get('x'), r.get('x'));
  assert.notEqual(r.get('x'), r.get('y'));
  assert.equal(r.get(), r.get(DEFAULT_WORKSPACE));
  assert.equal(r.get().id, DEFAULT_WORKSPACE);
});

test('the cap drops the least recently used non-default workspace first', () => {
  const r = reg({ max: 3 });
  r.get(DEFAULT_WORKSPACE); r.get('a'); r.get('b'); // full: default, a, b
  r.get('b'); // touch b: a is now the least recently used non-default
  r.get('c');
  assert.deepEqual(r.ids(), [DEFAULT_WORKSPACE, 'b', 'c']);
  assert.equal(r.size, 3);
});

test('the default workspace is never dropped by the cap', () => {
  const r = reg({ max: 2 });
  r.get(DEFAULT_WORKSPACE);
  r.get('x');
  r.get('y');
  assert.deepEqual(r.ids(), [DEFAULT_WORKSPACE, 'y']);
});

test('an idle workspace expires after its TTL, the default never does, and a get after expiry is a fresh runtime', () => {
  const c = clock();
  const r = reg({ now: c.now, ttlMs: 1000 });
  const first = r.get('a');
  c.set(500); r.get('b');
  c.set(1400); r.get('c'); // a idle 1400 ms (expired), b idle 900 ms (kept); the get is what triggers expiry
  assert.deepEqual(r.ids(), ['b', 'c']);
  assert.notEqual(r.get('a'), first, 'an expired id gets a fresh runtime');
  c.set(10 * WORKSPACE_TTL_MS);
  r.get('d');
  assert.deepEqual(r.ids(), ['d']);
  assert.equal(r.get().id, DEFAULT_WORKSPACE);
  c.set(20 * WORKSPACE_TTL_MS);
  r.get('e');
  assert.deepEqual(r.ids(), [DEFAULT_WORKSPACE, 'e'], 'the default survives expiry, d does not');
});

test('defaults: at most 50 workspaces, a 30 minute TTL, and a registry needs room for two', () => {
  assert.equal(MAX_WORKSPACES, 50);
  assert.equal(WORKSPACE_TTL_MS, 30 * 60 * 1000);
  assert.throws(() => reg({ max: 1 }), /at least 2/);
});
