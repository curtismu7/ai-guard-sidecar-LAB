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
npm start           # http://127.0.0.1:6500 (embedded sidecar 6502); build first
npm run sidecar     # standalone sidecar on 6501
```

Ports: 6500 app, 6501 sidecar, 6502 embedded sidecar, 6510 Vite, 6520/6521 e2e, 6530-6549 tests. Everything stays in 6500-6549.

## Rules that bite here

- Loopback only, with the Host check and Origin / Sec-Fetch-Site checks on writes. No real network, no real tenants, no credentials accepted. Netguard test asserts zero outbound attempts.
- All user or sidecar text is rendered inert (hidden characters shown as `[U+XXXX]`, PII masked, secrets redacted). Keep it that way in new UI.
- Test scripts use globs (`test/*.test.js`), never a directory (fails on Node 22).
- Never use `crypto.generateKeyPairSync` or async `generateKeyPair` (SIGABRT on Node 20 in CI).
- Never parse `node:test` stdout; use the exit code.
- Forbidden-strings history scan must print 0; gitleaks runs in the pre-commit hook (`.githooks`). Never print the forbidden list.
- Docker is OrbStack only, never Docker Desktop. Compose publishes `127.0.0.1:6500` only.
- Mock-issued values are labelled. Product claims about the `/inspect` contract and gateway behaviour are UNVERIFIED unless a source is added; the detector is a stand-in.

## Where the safety claims are pinned

`server/test/safety.test.js` (bind, Host, CSRF, ports, credentials), `netguard.test.js` (zero outbound), `api.test.js`, `sidecar.test.js`, `gateway.test.js` (bounds, inert text, masking, untrusted sidecar), `detectors.test.js`, `scripts/compose.test.mjs` (Docker publish), `scripts/docs.test.mjs` (docs match code). Table: [docs/safety.md](docs/safety.md).

## Shelf and content pack

- Shelf: edit `docs/shelf-entry.json` (tested by `scripts/shelf-entry.test.mjs`); `composeFile` stays a placeholder-style path. Do not edit the shelf repo.
- Content pack: edit `content/terms.json` or `content/stories.json`, run `npm run content-pack`, commit `content-pack.json`. Story text must match the UI (a test checks).
