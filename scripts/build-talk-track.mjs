#!/usr/bin/env node
/**
 * Generates docs/talk-track.md: the hand-written talk track (content/talk-track.base.md) with the H2 2026 release section
 * generated from the engine and from server/src/h2.js at the marker "<!-- generated:h2 -->". Deterministic, no timestamps.
 * A test (scripts/talk-track.test.mjs) fails when docs/talk-track.md is stale.
 *
 *   node scripts/build-talk-track.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { h2Static } from '../server/src/h2.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const TRACK_PATH = path.join(ROOT, 'docs/talk-track.md');
export const BASE_PATH = path.join(ROOT, 'content/talk-track.base.md');
export const MARKER = '<!-- generated:h2 -->';

const cell = (s) => String(s).replace(/\|/g, '\\|');
const TAG = (h, t) => h.tags[t];

export function h2Section() {
  const h = h2Static();
  const num = (n) => `| ${cell(n.label)} | ${n.ping} (${TAG(h, n.pingTag)})${n.pingNote ? `, ${cell(n.pingNote)}` : ''} | ${n.app === null ? cell(n.appNote) : `${n.app} (${TAG(h, n.appTag)}), ${cell(n.appNote)}`} |`;
  const aiguard = h.whyItMatters.find((w) => w.id === 'aiguard');
  const lines = [
    '## H2 2026 release: data protection (Ping release claims, UNVERIFIED on our tenant)',
    '',
    `Open the **H2 2026 release** tab. The banner **${h.banner}** is on both tabs: the release (dated 2026-11-02) is not on our tenant, so every product claim here is Ping's, from its deck "ID4AI Workforce - H2 2026", slides 50 and 53. The app's own engine is a small teaching model; its counts are its own and are never Ping's.`,
    '',
    `Say the challenge first (a Ping claim): "${aiguard.challenge}"`,
    '',
    `1. **Numbers (30 s).** Point at "Ping\'s numbers, and this app\'s own". Say: "Ping says ${h.deck.kinds} kinds, ${h.deck.secretDetectors} secret detectors, ${h.deck.behaviouralRules} behavioural rules and ${h.deck.totalRules} in total. Those are Ping\'s figures, not measured by us. The right column is what this little engine actually ships, computed live."`,
    '2. **Personal-data kinds.** In "Personal-data kinds" press **Original five**, then tick one more kind, then **All** and **None**. Say: "Detection is per kind. Every numeric kind has a real check digit: the table shows a valid sample found and a near miss not found, computed now." Then run a value of that kind under "Try it through the gateway" with the kind off and on.',
    '3. **Secret detectors.** Tick the switch "Run this app\'s … bundled secret detectors" and run a made-up key under "Try it through the gateway". Say: "The category has no slider, so it blocks at high: that is this app\'s own rule for a category it has no slider for."',
    '4. **Your own rules.** Press **Load two example rules**, then **Add these rules**, then run an example ticket number. Then press **Load an example with one bad rule** and **Add these rules**. Say: "One bad rule refuses the whole paste and nothing is added. The pattern is never shown back."',
    '5. **Prompt logging.** In "Prompt logging, sealed to a key only you hold" press **Generate a key pair in this browser**, tick Enabled, press **Save the settings**, run some text, then press **Open in this page** on the record. Say: "The server sealed it to the public key and has no way to open it. Only this page holds the private half." Turn Enabled off or remove the key to show that nothing is recorded without a public key.',
    '',
    '### Ping says, and this app ships',
    '',
    '| What | Ping says | This app ships |',
    '| --- | --- | --- |',
    ...h.numbers.map(num),
    '',
    `The app's own sets, from its engine: ${h.kinds.length} personal-data kinds (${h.kinds.map((k) => k.id).join(', ')}; the original five are on by default) and ${h.secretDetectors.length} bundled secret detectors (${h.secretDetectors.map((d) => d.id).join(', ')}).`,
    '',
    '### Where each field comes from',
    '',
    '| Field or claim | Source | Note |',
    '| --- | --- | --- |',
    ...h.fields.map((f) => `| ${cell(f.field)} | ${TAG(h, f.tag)} | ${cell(f.note)} |`),
    '',
    '### Why it matters (Ping claims, UNVERIFIED on our tenant)',
    '',
    ...h.whyItMatters.flatMap((w) => [`**${w.title}**`, '', `- Challenge: ${w.challenge}`, `- Technical: ${w.technical}`, `- Business: ${w.business}`, '']),
    '### Cut on purpose',
    '',
    'The deck\'s "sanitize" outcome (redact the offending span and forward the rest) is not modelled: this app allows, alerts or blocks. Its detectors are examples, not Ping\'s sets. Behavioural scoring, framework tagging and the model-based second layer are not modelled either.',
    '',
  ];
  return lines.join('\n');
}

export function buildTalkTrack() {
  const base = fs.readFileSync(BASE_PATH, 'utf8');
  if (base.split(MARKER).length !== 2) throw new Error(`${path.relative(ROOT, BASE_PATH)} must contain the marker ${MARKER} exactly once`);
  return base.replace(MARKER, h2Section().trimEnd());
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fs.writeFileSync(TRACK_PATH, buildTalkTrack());
  console.log(`wrote ${path.relative(process.cwd(), TRACK_PATH) || TRACK_PATH}`);
}
