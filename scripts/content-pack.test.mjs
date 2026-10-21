import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { PACK_PATH, buildPack, serialize } from './build-content-pack.mjs';
import { validatePack } from './validate-content-pack.mjs';

test('content-pack.json is exactly what the generator produces (run: npm run content-pack)', () => {
  assert.equal(fs.readFileSync(PACK_PATH, 'utf8'), serialize(buildPack()), 'content-pack.json is stale; regenerate it and commit the result');
});

test('the generator is deterministic', () => assert.equal(serialize(buildPack()), serialize(buildPack())));

test('content-pack.json validates against docs/content-pack.schema.json', () => {
  assert.deepEqual(validatePack(JSON.parse(fs.readFileSync(PACK_PATH, 'utf8'))), []);
});

test('the validator rejects a broken pack', () => {
  const pack = buildPack();
  pack.cards[0].terms = ['no-such-term'];
  delete pack.title;
  assert.ok(validatePack(pack).length >= 2);
});

test('the pack covers the app and keeps the UNVERIFIED and STAND-IN statements', () => {
  const pack = buildPack();
  for (const id of ['ai-guard-sidecar', 'inspect-contract', 'findings', 'block-threshold', 'fail-closed', 'stand-in-detector', 'pii-rail', 'response-scanning', 'per-key-guardrail', 'unverified', 'inert-text']) assert.ok(pack.glossary.some((g) => g.id === id), id);
  assert.deepEqual(pack.sources, []);
  assert.equal(pack.demo.baseUrl, 'http://localhost:6500');
  assert.equal(pack.demo.catalog, 'D12');
  const text = JSON.stringify(pack);
  assert.match(text, /UNVERIFIED against product documentation/);
  assert.match(pack.glossary.find((g) => g.id === 'stand-in-detector').definition, /no claim about real product detection quality, defaults or licensing/);
  assert.match(pack.glossary.find((g) => g.id === 'inspect-contract').definition, /UNVERIFIED/);
});

test('every story says exactly what the UI story strip says', () => {
  const jsx = fs.readFileSync(new URL('../web/src/components/Story.jsx', import.meta.url), 'utf8');
  for (const s of buildPack().stories) assert.ok(jsx.includes(`"${s.say}"`), `Story.jsx does not carry the text of ${s.id}`);
});

test('a commit is recorded only when passed', () => {
  assert.equal(buildPack().source, undefined);
  assert.equal(buildPack({ commit: 'abc1234' }).source.commit, 'abc1234');
});
