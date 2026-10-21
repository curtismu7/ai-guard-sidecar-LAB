# Architecture

```
client (scenario or custom text)
   |  POST /api/run
   v
mock gateway (server/src/gateway.js, in the main server on 6500)
   |  request stage:  POST /inspect  { units: [ { role: user_prompt, direction: request, text } ] }
   v
sidecar (server/src/sidecar.js; embedded on 6502, or standalone on 6501)  -> { findings: [...] }
   |
   |  decision: no findings = allow | finding >= category threshold = block | error = fail-closed toggle
   v
upstream stub (canned text; skipped when the request was blocked)
   |  response stage: POST /inspect  { units: [ { role: assistant_response, direction: response, text } ] }
   v
decision log (server/src/decisions.js)
```

All of this is "as understood from the demo environment, UNVERIFIED against product documentation" (see [safety.md](safety.md)).

## Pieces

- `server/src/sidecar.js`: the HTTP sidecar. `POST /inspect`, `GET /health`, `GET/PUT /demo/config`, `GET/PUT /demo/fault`. It owns the detector threshold, the benign labels, the rails and the fault state. Runs standalone through `server/src/sidecar-main.js` or embedded in the main server.
- `server/src/detectors.js`: the stand-in rules and the label scoring. A finding is made when a non-benign label scores at or above the threshold. `server/src/pii.js` holds the PII finder and masker.
- `server/src/gateway.js`: calls the sidecar over loopback HTTP with a timeout, validates the reply, compares each finding's severity with its category's block threshold, and applies the fail-closed toggle on error. Severity order is `low` < `medium` < `high`; a threshold of `none` means alert only.
- `server/src/scenarios.js`: the scripted scenarios, the two demo callers for the A2A case (a guardrail belongs to the calling agent's key, as the source docs describe it; unverified here) and each run's expected decision.
- `server/src/service.js`: gateway configuration, the one-at-a-time run queue (cap 4), scenario and custom runs, the fault injector (applied to the sidecar over its `/demo/fault` endpoint and restored after a scenario), reset.
- `server/src/app.js`: Express app, guards, routes, `startHttpServer()` (starts the embedded sidecar, then the gateway server).
- `server/src/safety.js`, `sanitize.js`, `redaction.js`: guards, inert text and secret redaction.

## Why the gateway talks to the sidecar over HTTP even when embedded

The point is to show the wire. The embedded sidecar is a separate Express server on its own loopback port (6502), and the gateway reaches it with `fetch`, so a timeout, a 502 or a malformed reply is a real network event rather than a thrown exception. The same code path serves a standalone sidecar on 6501 (`AI_GUARD_SIDECAR_URL=http://127.0.0.1:6501`).

## Ports

| Port | Use |
| --- | --- |
| 6500 | main server (mock gateway and API) |
| 6501 | standalone sidecar |
| 6502 | embedded sidecar; 6503-6509 are reserved for stubs |
| 6510 | Vite dev server (a later step) |
| 6520 | end-to-end runs (a later step) |
| 6530-6549 | tests, through a free-port helper; each test file owns a slice |

## Decision record

Each run adds one entry: source (scenario or custom), caller, the policy in force (fail closed, timeout, thresholds), the injected fault if any, and three stages (request, upstream, response). A stage carries the masked unit text, the sidecar call result (status, latency, error kind) and each finding with its threshold and whether it blocks. The outcome carries `blockedAt` (`request`, `response` or null) and a `reason`: `no_findings`, `alert_only_below_threshold`, `threshold_met`, `sidecar_error_fail_closed` or `sidecar_error_fail_open`.
