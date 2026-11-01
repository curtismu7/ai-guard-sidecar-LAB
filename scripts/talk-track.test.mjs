import assert from 'node:assert/strict';
import fs from 'node:fs';
import { test } from 'node:test';
import { BASE_PATH, MARKER, TRACK_PATH, buildTalkTrack, h2Section } from './build-talk-track.mjs';
import { DECK, WHY_IT_MATTERS, h2Static } from '../server/src/h2.js';
import { PII_KIND_IDS } from '../server/src/pii.js';
import { SECRET_DETECTORS } from '../server/src/secrets.js';

const read = (rel) => fs.readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');

test('docs/talk-track.md is exactly what the generator produces (run: node scripts/build-talk-track.mjs)', () => {
  assert.equal(fs.readFileSync(TRACK_PATH, 'utf8'), buildTalkTrack(), 'docs/talk-track.md is stale; regenerate it and commit the result');
});

test('the generator is deterministic, and the base carries the marker exactly once', () => {
  assert.equal(buildTalkTrack(), buildTalkTrack());
  assert.equal(fs.readFileSync(BASE_PATH, 'utf8').split(MARKER).length, 2);
  assert.ok(!fs.readFileSync(TRACK_PATH, 'utf8').includes(MARKER), 'the marker is replaced in the output');
});

test('the H2 section carries the banner, every why-it-matters line marked as a Ping claim, and the numbers from the engine', () => {
  const t = fs.readFileSync(TRACK_PATH, 'utf8');
  assert.match(t, /Ping release claim, UNVERIFIED on our tenant/);
  for (const w of WHY_IT_MATTERS) for (const line of [w.challenge, w.technical, w.business]) assert.ok(t.includes(line), `missing: ${line.slice(0, 40)}`);
  assert.match(t, /### Why it matters \(Ping claims, UNVERIFIED on our tenant\)/);
  assert.ok(t.includes(`${PII_KIND_IDS.length} personal-data kinds`) && t.includes(`${SECRET_DETECTORS.length} bundled secret detectors`));
  for (const id of PII_KIND_IDS) assert.ok(t.includes(id), id);
  for (const d of SECRET_DETECTORS) assert.ok(t.includes(d.id), d.id);
});

test('Ping\'s numbers appear only labelled as Ping\'s: never in the app\'s column', () => {
  const rows = h2Section().split('\n').filter((l) => /^\| (Personal-data|Secret and|Behavioural|Maintained)/.test(l));
  assert.equal(rows.length, 4);
  for (const row of rows) {
    const [, , ping, app] = row.split('|').map((c) => c.trim());
    assert.match(ping, /\(deck claim\)/);
    assert.ok(!app.includes('(deck claim)'), row);
  }
  const h = h2Static();
  assert.ok(![DECK.kinds, DECK.secretDetectors, DECK.behaviouralRules].includes(PII_KIND_IDS.length) && SECRET_DETECTORS.length !== DECK.secretDetectors);
  assert.equal(h.deck.totalRules, h.deck.behaviouralRules + h.deck.secretDetectors);
});

test('every control the talk track tells the presenter to press exists in the UI source', () => {
  const web = ['H2Tab', 'Kinds', 'Rules', 'PromptLog'].map((n) => read(`web/src/components/${n}.jsx`)).join('\n');
  for (const label of ['Original five', 'Load two example rules', 'Load an example with one bad rule', 'Add these rules', 'Generate a key pair in this browser', 'Save the settings', 'Open in this page', 'Forget all keys', 'Run my text', 'Run this app\'s', 'Try it through the gateway', 'Prompt logging, sealed to a key only you hold', 'Personal-data kinds', 'Ping\'s numbers, and this app\'s own']) {
    assert.ok(web.includes(label), `the UI has no "${label}"`);
  }
  assert.ok(read('web/src/App.jsx').includes('H2 2026 release'));
  const t = fs.readFileSync(TRACK_PATH, 'utf8');
  for (const label of ['Original five', 'Load two example rules', 'Generate a key pair in this browser', 'Open in this page']) assert.ok(t.includes(label), `the talk track does not name ${label}`);
});
