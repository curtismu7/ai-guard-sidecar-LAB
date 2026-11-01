// The H2 2026 release content for this app (Ping's "ID4AI Workforce - H2 2026" deck, slides 50 and 53; release dated 2026-11-02).
// ONE source for the API (GET /api/h2), the generated talk track and the content pack, so they cannot drift apart.
// Every product claim below is a Ping release claim, UNVERIFIED on our tenant: the release is not on our tenant. Ping's numbers
// (23 kinds, 364 secret detectors, 47 behavioural rules, 411 rules) are Ping's, quoted from the deck. The app's own counts are
// COMPUTED from the engine here, never typed in, and are labelled as the app's.
import { PII_GROUPS, PII_KIND_IDS, SAMPLES, findPii, LEGACY_KINDS, maskPii, piiCatalogue } from './pii.js';
import { SECRET_DETECTORS, detectSecrets } from './secrets.js';
import { STAND_IN_RULE_COUNT } from './detectors.js';
import { RULE_LIMITS, CATEGORY_IDS, SEVERITIES, TOML_LIMITS } from './rules.js';
import { PL_LIMITS, PL_STORE, SURFACES } from './promptlog.js';
import { fold } from './fold.js';
import { maskTyped } from './mask.js';

export const BANNER = 'Ping release claim, UNVERIFIED on our tenant';
export const TAGS = Object.freeze({
  deck: 'deck claim',
  swagger: 'console swagger name (schema only)',
  reading: 'lab reading',
  invented: 'lab-invented',
  measured: 'measured (our note)',
});

// Ping's figures, as the deck states them (slide 53). Nothing here was measured on our tenant.
export const DECK = Object.freeze({ kinds: 23, kindsBefore: 5, secretDetectors: 364, behaviouralRules: 47, totalRules: 411, slide: 53 });

// Challenge / Technical / Business from the deck's value panels (slides 50, 53). Ping claims, UNVERIFIED on our tenant.
export const WHY_IT_MATTERS = Object.freeze([
  { id: 'aiguard', title: 'AIGuard (deck slide 53)', challenge: 'Authorization cannot see content: an agent following hidden instructions can exfiltrate data within policy.', technical: 'Content inspected in and out across MCP, A2A, LLM and coding-agent traffic; deterministic rules add no availability dependency.', business: 'A fraction of the cost of one incident; framework-mapped evidence for AI governance sign-off.' },
  { id: 'prompt-logging', title: 'Prompt Logging (deck slide 50)', challenge: 'Retaining prompts is what investigations need and what teams refuse to hand a vendor.', technical: 'Content sealed to your public key, decrypted only in your console session; Privilege never holds the private half.', business: 'Forensic retention becomes acceptable to security and legal.' },
]);

// Per-field claim tags. `field` is the name as the API of THIS app spells it.
export const FIELD_TAGS = Object.freeze([
  { id: 'pii-kinds-field', field: 'piiKinds (swagger: PIIKinds)', tag: 'swagger', note: 'The console swagger lists PIIKinds on modelAIGuardConfig as detector ids. Only the field name is from the swagger; this app spells it camelCase and uses its own kind ids.' },
  { id: 'pii-kinds-per-kind', field: 'detection is per kind', tag: 'deck', note: 'Deck slide 53: "Personal data, your way", numeric kinds checksum-validated, detection per kind.' },
  { id: 'pii-kinds-set', field: 'the kinds in the catalogue and which are on by default', tag: 'invented', note: 'This app\'s own illustrative set. The default selection is the original five so the first demo behaves as before. Ping\'s list of 23 is not reproduced or guessed.' },
  { id: 'pii-checks', field: 'the check digit for each numeric kind', tag: 'reading', note: 'A reading of public formats (Luhn, mod 97, mod 11, mod 23, a 3-7-1 weighted sum). Not a claim about Ping\'s validators.' },
  { id: 'rule-fields', field: 'ID, Description, Category, Severity, Keywords, Pattern, Entropy, Allowlist, ValueGroup', tag: 'swagger', note: 'Field names of modelAIGuardCustomRule in the console swagger. A name proves a field exists, not how it behaves.' },
  { id: 'rule-toml-keys', field: 'the TOML keys: id, description, regex, keywords, entropy, secretGroup, category, severity, [rules.allowlist].regexes', tag: 'reading', note: 'A reading of the gitleaks rule format. Pattern source is the standard "your own formats paste in unchanged" (deck slide 53) as the app understands it.' },
  { id: 'rule-refuse-all', field: 'one bad rule refuses the whole paste', tag: 'reading', note: 'The console swagger\'s description of imodelAIGuardRuleImport says so; how the product behaves is unverified.' },
  { id: 'rule-category-set', field: 'the category names a pasted rule may use, and what the gateway does with them', tag: 'invented', note: 'The gateway here has sliders only for prompt_injection, jailbreak and pii. Any other category (secrets, data_exfiltration, malicious_content) blocks at high, the demo\'s existing rule for a category it does not know, so the rule\'s Severity decides.' },
  { id: 'rule-limits', field: 'the caps on a paste (size, lines, rules, matches)', tag: 'invented', note: 'Limits chosen for a safe local demo.' },
  { id: 'counts-ping', field: '23 kinds, 364 secret detectors, 47 behavioural rules, 411 rules', tag: 'deck', note: 'Ping\'s figures from slide 53, uncited in the deck. Shown only in the "Ping says" column.' },
  { id: 'counts-app', field: 'the "this app ships" column', tag: 'invented', note: 'Computed from this app\'s own engine at request time. These are the app\'s examples, not a measure of the product.' },
  { id: 'outcomes', field: 'four outcomes: allow, alert, sanitize, block', tag: 'deck', note: 'Deck slide 53. This app models allow, alert and block; it does not model sanitize.' },
  { id: 'prompt-log-fields', field: 'Enabled, PublicKey (X25519 JWK), KeyID, Surfaces, IncludeResponses, MaxBytes', tag: 'swagger', note: 'Field names of modelPromptLogConfig in the console swagger.' },
  { id: 'prompt-log-no-key', field: 'nothing is recorded without a public key', tag: 'reading', note: 'The swagger says so; this app follows it.' },
  { id: 'prompt-log-sealed', field: 'prompts sealed to your key, opened only with your private key', tag: 'deck', note: 'Deck slides 50 and 53: "Privilege never holds it".' },
  { id: 'prompt-log-envelope', field: 'the sealed-record envelope (X25519 + HKDF-SHA256 + AES-256-GCM), the surfaces this app produces, caps, the ring of 100 records', tag: 'invented', note: 'The product\'s format is not public. The envelope is this app\'s own and is shown so the round trip can be proved.' },
  { id: 'measured', field: 'anything measured on our tenant', tag: 'measured', note: 'Nothing. The release is not on our tenant; nothing here has been measured.' },
]);

// A near miss is by definition not recognised, so it cannot be masked: it is shown as its first four characters and its length only.
const shape = (s) => `${s.slice(0, 4)}... (${s.length} characters)`;

const kindsSample = () => PII_KIND_IDS.map((id) => {
  const alone = (text) => findPii(fold(text).norm, [id]).length > 0;
  return { id, validDetected: alone(SAMPLES[id].valid()), nearMissDetected: alone(SAMPLES[id].nearMiss()) };
});

// The numbers table: Ping's figure beside the app's computed one. The deck's own sum is checked, not assumed.
export function numbers() {
  return [
    { id: 'pii-kinds', label: 'Personal-data kinds', ping: DECK.kinds, pingNote: `went from ${DECK.kindsBefore} to ${DECK.kinds}`, app: PII_KIND_IDS.length, appNote: `the app's own illustrative set (default selection: ${LEGACY_KINDS.length})` },
    { id: 'secret-detectors', label: 'Secret and credential detectors', ping: DECK.secretDetectors, app: SECRET_DETECTORS.length, appNote: 'the app\'s own examples' },
    { id: 'behavioural-rules', label: 'Behavioural rules', ping: DECK.behaviouralRules, app: STAND_IN_RULE_COUNT, appNote: 'the app\'s stand-in injection and jailbreak rules' },
    { id: 'total-rules', label: 'Maintained rules in total', ping: DECK.totalRules, pingNote: `${DECK.behaviouralRules} behavioural + ${DECK.secretDetectors} secret = ${DECK.behaviouralRules + DECK.secretDetectors}`, app: null, appNote: 'not comparable: the app does not claim a rule total' },
  ].map((n) => ({ ...n, pingTag: 'deck', appTag: n.app === null ? null : 'invented' }));
}

// The static part: what a talk track or a content pack needs, with no state.
export function h2Static() {
  return { banner: BANNER, tags: TAGS, deck: DECK, whyItMatters: WHY_IT_MATTERS, fields: FIELD_TAGS, numbers: numbers(), kinds: piiCatalogue(), groups: PII_GROUPS, secretDetectors: SECRET_DETECTORS.map(({ id, description }) => ({ id, description })), categories: CATEGORY_IDS, severities: SEVERITIES };
}

// The live part: the proofs are computed by running the engine on its own samples now. `selected` = the kinds that are on.
export function h2Overview(selected = LEGACY_KINDS) {
  const proofs = new Map(kindsSample().map((p) => [p.id, p]));
  return {
    ...h2Static(),
    selected: PII_KIND_IDS.filter((k) => selected.includes(k)),
    kinds: piiCatalogue().map((k) => ({ ...k, enabled: selected.includes(k.id), valid: { shown: maskPii(SAMPLES[k.id].valid()), detected: proofs.get(k.id).validDetected }, nearMiss: { shown: shape(SAMPLES[k.id].nearMiss()), detected: proofs.get(k.id).nearMissDetected } })),
    secretProofs: SECRET_DETECTORS.map((d) => ({ id: d.id, description: d.description, valid: { shown: maskTyped(d.sample()), detected: detectSecrets(d.sample()).some((h) => h.rule === d.id) }, nearMiss: { shown: shape(d.nearMiss()), detected: detectSecrets(d.nearMiss()).length > 0 } })),
    limits: { rules: { ...RULE_LIMITS, tomlCharacters: TOML_LIMITS.bytes, tomlLines: TOML_LIMITS.lines }, promptLog: { ...PL_LIMITS, maxRecords: PL_STORE.maxRecords, surfaces: SURFACES } },
  };
}
