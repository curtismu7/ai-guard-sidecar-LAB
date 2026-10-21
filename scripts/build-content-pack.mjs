#!/usr/bin/env node
/**
 * Generates content-pack.json (repo root). Format: docs/content-pack.schema.json (a copy of the Learning Hub / ID-JAG kit schema).
 * Glossary from content/terms.json, stories from content/stories.json (same text as web/src/components/Story.jsx; a test checks that),
 * cards for the UI. Deterministic: lists sorted by id, 2-space JSON, no timestamps. The git commit is recorded only when
 * passed (--commit=<sha>), so a plain run is reproducible.
 *
 * Sources: none. No public documentation URL is cited in this repo that was verified, so the pack lists none.
 *
 *   node scripts/build-content-pack.mjs [--commit=<sha>]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PACK_PATH = path.join(ROOT, 'content-pack.json');
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// The UI is one page with no deep links, so every card opens the app root.
const CARDS = [
  { id: 'scenarios', label: 'Run the scripted scenarios', description: 'Benign prompt, direct injection, PII in a request, PII leaking in a response, and an A2A message through two keys. Watch the gateway allow or block.', group: 'try-it', href: '/', terms: ['ai-guard-sidecar', 'findings', 'block-threshold', 'pii-rail', 'response-scanning', 'per-key-guardrail'], story: 'S03' },
  { id: 'outage', label: 'Break the sidecar: fail closed vs fail open', description: 'Inject a 502, a timeout or a slow answer and compare what the gateway does in each mode.', group: 'try-it', href: '/', terms: ['fail-closed'], story: 'S04' },
  { id: 'stand-in-limits', label: 'What the stand-in misses', description: 'A paraphrased attack the stand-in allows and a harmless sentence it blocks. Detection quality belongs to the model.', group: 'concept', href: '/', terms: ['stand-in-detector', 'unverified'], story: 'S02' },
  { id: 'contract', label: 'The /inspect contract', description: 'Units in, findings out, as understood from the demo environment and unverified against product documentation.', group: 'concept', href: '/', terms: ['inspect-contract', 'findings', 'unverified', 'inert-text'], story: 'S01' },
];

export function buildPack({ commit } = {}) {
  const pkg = readJson('package.json');
  const stories = readJson('content/stories.json').sort(byId);
  const ids = new Set(stories.map((s) => s.id));
  const pack = {
    schema: 'demo-content-pack/1',
    id: 'ai-guard-sidecar',
    title: 'AI Guard Sidecar',
    version: pkg.version,
    ...(commit ? { source: { repo: 'ai-guard-sidecar', commit } } : {}),
    demo: { id: 'ai-guard-sidecar', name: 'AI Guard Sidecar', catalog: 'D12', baseUrl: 'http://localhost:6500', doctor: '/api/health', tags: ['ai-guard', 'guardrails', 'prompt-injection', 'pii', 'unverified-contract'] },
    glossary: readJson('content/terms.json').sort(byId),
    sources: [],
    cards: CARDS.map(({ href, ...c }) => ({ ...c, action: { type: 'route', href } })).sort(byId),
    diagrams: [{ id: 'gateway-flow', label: 'Client, gateway, sidecar, upstream', href: '/' }],
    stories,
  };
  const terms = new Set(pack.glossary.map((g) => g.id));
  for (const c of pack.cards) {
    if (c.story && !ids.has(c.story)) throw new Error(`card ${c.id} names unknown story ${c.story}`);
    for (const t of c.terms || []) if (!terms.has(t)) throw new Error(`card ${c.id} names unknown term ${t}`);
  }
  return pack;
}

export const serialize = (pack) => `${JSON.stringify(pack, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const commit = process.argv.find((a) => a.startsWith('--commit='))?.slice(9);
  fs.writeFileSync(PACK_PATH, serialize(buildPack({ commit })));
  console.log(`wrote ${path.relative(process.cwd(), PACK_PATH) || PACK_PATH}`);
}
