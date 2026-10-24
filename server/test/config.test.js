import assert from 'node:assert/strict';
import { test } from 'node:test';
import { REFUSED_IN_SE_MOCK, modeFrom, refusedFlagsSet } from '../src/config.js';

test('MODE defaults to local; se-mock is the only other mode; anything else is an error, never a fallback', () => {
  assert.equal(modeFrom({}), 'local');
  assert.equal(modeFrom({ MODE: '' }), 'local');
  assert.equal(modeFrom({ MODE: 'local' }), 'local');
  assert.equal(modeFrom({ MODE: 'se-mock' }), 'se-mock');
  for (const bad of ['live', 'prod', 'SE-MOCK', 'mock', ' se-mock', 'se-mock\n']) assert.throws(() => modeFrom({ MODE: bad }), /not available/, JSON.stringify(bad));
});

test('the live settings refused in se-mock are named, and empty values do not count as set', () => {
  assert.deepEqual(REFUSED_IN_SE_MOCK, ['AI_GUARD_SIDECAR_URL', 'AI_GUARD_SIDECAR_PORT']);
  assert.deepEqual(refusedFlagsSet({ AI_GUARD_SIDECAR_URL: 'http://127.0.0.1:6549' }), ['AI_GUARD_SIDECAR_URL']);
  assert.deepEqual(refusedFlagsSet({ AI_GUARD_SIDECAR_URL: '', AI_GUARD_SIDECAR_PORT: '6501' }), ['AI_GUARD_SIDECAR_PORT']);
  assert.deepEqual(refusedFlagsSet({}), []);
});
