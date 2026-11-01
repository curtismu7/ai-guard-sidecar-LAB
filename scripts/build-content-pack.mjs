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
import { WHY_IT_MATTERS, h2Static } from '../server/src/h2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const PACK_PATH = path.join(ROOT, 'content-pack.json');
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(ROOT, rel), 'utf8'));
// Glossary terms about the H2 2026 release. The two "why it matters" entries come straight from server/src/h2.js (the deck's value panels).
const H2_TERMS = () => [
  { id: 'ping-release-numbers', term: 'Ping\'s release numbers versus this app\'s', definition: `Ping release claim, UNVERIFIED on our tenant. Ping's deck (slide ${h2Static().deck.slide}) says ${h2Static().deck.kinds} personal-data kinds (up from ${h2Static().deck.kindsBefore}), ${h2Static().deck.secretDetectors} secret and credential detectors, ${h2Static().deck.behaviouralRules} behavioural rules and ${h2Static().deck.totalRules} maintained rules in total. Those are Ping's figures, uncited in the deck and not measured by us. This app ships its own smaller illustrative sets (${h2Static().kinds.length} kinds, ${h2Static().secretDetectors.length} secret detectors), computed from its engine and never presented as Ping's.` },
  { id: 'personal-data-kinds', term: 'Personal-data kinds (selectable)', definition: 'Ping release claim, UNVERIFIED on our tenant: detection is per kind, numeric kinds are checksum-validated, and your own formats can be pasted. In this app each kind is a regex plus a check digit or a structural check, you choose which kinds raise a finding (the original five by default), and every kind is masked in anything shown. The kind list is this app\'s own, not Ping\'s.' },
  { id: 'own-rules', term: 'Your own gitleaks-format rules', definition: 'Ping release claim, UNVERIFIED on our tenant: "your own formats paste in unchanged". In this app you paste rules with id, description, regex, keywords, entropy, secretGroup, category, severity and an allowlist; one bad rule refuses the whole paste; patterns are checked before they run and the pattern is never shown back. The key names are the app\'s reading of the gitleaks format.' },
  { id: 'prompt-logging-sealed', term: 'Prompt logging sealed to your key', definition: 'Ping release claim, UNVERIFIED on our tenant: prompts and responses can be retained encrypted with a public key you supply, and the vendor never holds the private half. In this app the server seals each run to your X25519 public key (ephemeral key, HKDF-SHA256, AES-256-GCM: the envelope is the app\'s own invention), who and what was decided stay in the clear, nothing is recorded without a public key, and a record opens only in the page with a private key you hold. The server has no decrypt code.' },
  ...WHY_IT_MATTERS.map((w) => ({ id: `why-${w.id}`, term: `Why it matters: ${w.title}`, definition: `Ping claims, UNVERIFIED on our tenant. Challenge: ${w.challenge} Technical: ${w.technical} Business: ${w.business}` })),
];

const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

// The UI has no deep links, so every card opens the app root (the H2 2026 cards live in the "H2 2026 release" tab).
const CARDS = [
  { id: 'scenarios', label: 'Run the scripted scenarios', description: 'Benign prompt, direct injection, PII in a request, PII leaking in a response, and an A2A message through two keys. Watch the gateway allow or block.', group: 'try-it', href: '/', terms: ['ai-guard-sidecar', 'findings', 'block-threshold', 'pii-rail', 'response-scanning', 'per-key-guardrail'], story: 'S03' },
  { id: 'outage', label: 'Break the sidecar: fail closed vs fail open', description: 'Inject a 502, a timeout or a slow answer and compare what the gateway does in each mode.', group: 'try-it', href: '/', terms: ['fail-closed'], story: 'S04' },
  { id: 'stand-in-limits', label: 'What the stand-in misses', description: 'A paraphrased attack the stand-in allows and a harmless sentence it blocks. Detection quality belongs to the model.', group: 'concept', href: '/', terms: ['stand-in-detector', 'unverified'], story: 'S02' },
  { id: 'h2-kinds', label: 'H2 2026: personal-data kinds and secret detectors', description: 'Ping release claim, UNVERIFIED on our tenant. Choose which personal-data kinds raise a finding, see each check digit proved on a valid sample and a near miss, and try the app\'s own secret detectors. Ping\'s counts are quoted from its deck, never presented as the app\'s.', group: 'try-it', href: '/', terms: ['personal-data-kinds', 'ping-release-numbers', 'pii-rail', 'unverified'] },
  { id: 'h2-rules', label: 'H2 2026: paste your own gitleaks-format rules', description: 'Ping release claim, UNVERIFIED on our tenant. Paste rules in the gitleaks format; one bad rule refuses the whole paste and nothing is added.', group: 'try-it', href: '/', terms: ['own-rules', 'unverified'] },
  { id: 'h2-prompt-logging', label: 'H2 2026: prompt logging sealed to your key', description: 'Ping release claim, UNVERIFIED on our tenant. Make a key pair in the browser, seal each run to the public half on the server, and open a record in the page with the private half.', group: 'try-it', href: '/', terms: ['prompt-logging-sealed', 'why-prompt-logging', 'unverified'] },
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
    demo: { id: 'ai-guard-sidecar', name: 'AI Guard Sidecar', catalog: 'D12', baseUrl: 'http://localhost:6500', doctor: '/api/health', tags: ['ai-guard', 'guardrails', 'prompt-injection', 'pii', 'unverified-contract', 'h2-2026'] },
    glossary: [...readJson('content/terms.json'), ...H2_TERMS()].sort(byId),
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
