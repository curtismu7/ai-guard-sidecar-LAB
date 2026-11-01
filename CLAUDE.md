# CLAUDE.md

AI Guard Sidecar (tier Demo, port 6500). An offline demo of how an external guardrail sidecar plugs into an agent gateway: a mock gateway posts request and response text to a sidecar `/inspect`, a deterministic stand-in detector answers, and per-category block thresholds, a Fail Closed toggle and a fault injector decide allow or block. Nothing real is touched. Overview, API and UI tour: [README.md](README.md). Presenter script: [docs/talk-track.md](docs/talk-track.md).

## Commands (from package.json)

```sh
npm install
npm test            # server + web + scripts/*.test.mjs
npm run build       # web UI into web/dist
npm run doctor      # preflight, exit 0 when sound and ports free
npm run e2e         # headless Chromium against the built UI (6520/6521)
npm run content-pack  # regenerate and validate content-pack.json
npm run talk-track    # regenerate docs/talk-track.md from content/talk-track.base.md + server/src/h2.js
npm start           # http://127.0.0.1:6500 (embedded sidecar 6502); build first
npm run sidecar     # standalone sidecar on 6501 (refused under MODE=se-mock)
```

Mode: `MODE=local` (default) is the demo. `MODE=se-mock` is the mock-only SE k8s build (rule 18): live settings refused, per-visitor workspaces (`X-Workspace-Id`), a hosted banner, manifests in `k8s/`. See [docs/k8s.md](docs/k8s.md). Nothing is deployed from here; the first SE deploy needs owner approval.

Ports: 6500 app, 6501 sidecar, 6502 embedded sidecar, 6510 Vite, 6520/6521 e2e, 6530-6549 tests. Everything stays in 6500-6549.

## Rules that bite here

- Mock-only build: in `se-mock` every new piece of app state belongs to a workspace (`server/src/workspaces.js`), and a new live setting must be added to `REFUSED_IN_SE_MOCK` in `config.js`. Do not add a process-wide mutable store.
- Loopback only, with the Host check and Origin / Sec-Fetch-Site checks on writes. No real network, no real tenants, no credentials accepted. Netguard test asserts zero outbound attempts.
- All user or sidecar text is rendered inert (hidden characters shown as `[U+XXXX]`, PII masked, secrets redacted). Keep it that way in new UI.
- Test scripts use globs (`test/*.test.js`), never a directory (fails on Node 22).
- Never use `crypto.generateKeyPairSync` or async `generateKeyPair` (SIGABRT on Node 20 in CI).
- Never parse `node:test` stdout; use the exit code.
- Forbidden-strings history scan must print 0; gitleaks runs in the pre-commit hook (`.githooks`). Never print the forbidden list.
- Docker is OrbStack only, never Docker Desktop. Compose publishes `127.0.0.1:6500` only.
- Mock-issued values are labelled. Product claims about the `/inspect` contract and gateway behaviour are UNVERIFIED unless a source is added; the detector is a stand-in.

## H2 2026 release additions (Ping release claims, UNVERIFIED on our tenant)

A second tab, "H2 2026 release": selectable personal-data kinds (`pii.js`), bundled secret detectors (`secrets.js`), your own gitleaks-format rules (`toml.js`, `safeRegex.js`, `rules.js`) and prompt logging sealed to a key you hold (`seal.js`, `promptlog.js`, `web/src/lib/seal.js`). `h2.js` is the one source for the banner, the claim tags, Ping's numbers and the why-it-matters text: the API, the generated talk track and the content pack all read it.

- Never present Ping's numbers (23 kinds, 364 secret detectors, 47 behavioural rules, 411 rules) as the app's own: the app's counts come from its engine. Every field is tagged (deck claim, console swagger name, lab reading, lab-invented, measured); a swagger name proves a field exists, not how it behaves.
- Defaults keep the original behaviour (original five kinds, secrets rail off, no rules). New state lives per workspace (sidecar state for kinds and rules, the service for prompt logging) and Reset clears it.
- The server only seals: no decrypt code, a private key (a JWK with `d`) is refused, keys are built from raw bytes (never `generateKeyPair`). The page keeps private keys in memory only.
- Anything typed is masked in every response, error and log (`fold.js`, `mask.js`, `redaction.js`; a test types credential-shaped values into every field of the new endpoints). Errors never echo a pasted key name, pattern or id. Mask before truncating. A pasted regex is checked statically, and V8's linear-time fallback is armed before it is compiled (`rules.js`); no child process, no worker.
- One bad rule refuses the whole paste (400, nothing added); caps refuse the whole request. Every editable field has a test that fails if the field is ignored.
- `docs/talk-track.md` is generated (`scripts/build-talk-track.mjs`): edit `content/talk-track.base.md` or `h2.js`.

## Where the safety claims are pinned

`server/test/safety.test.js` (bind, Host, CSRF, ports, credentials), `netguard.test.js` (zero outbound), `api.test.js`, `sidecar.test.js`, `gateway.test.js` (bounds, inert text, masking, untrusted sidecar), `detectors.test.js`, `scripts/compose.test.mjs` (Docker publish), `scripts/docs.test.mjs` (docs match code), `scripts/k8s.test.mjs` (manifests), `server/test/se-mock.test.js` and `workspaces.test.js` (isolation, cap, TTL), and for the H2 additions `h2-detect.test.js`, `rules.test.js`, `promptlog.test.js`, `h2-api.test.js` and `web/src/H2.test.jsx`. Table: [docs/safety.md](docs/safety.md).

## Shelf and content pack

- Shelf: edit `docs/shelf-entry.json` (tested by `scripts/shelf-entry.test.mjs`); `composeFile` stays a placeholder-style path. Do not edit the shelf repo.
- Content pack: edit `content/terms.json` or `content/stories.json`, run `npm run content-pack`, commit `content-pack.json`. Story text must match the UI (a test checks).
