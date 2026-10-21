# Changelog

## 0.1.0

- AG3: packaging. Dockerfile healthcheck; content pack (`content/`, build and validate scripts, copied schema, tests); shelf entry for catalog D12 with the shelf's registry rules copied and tested; README Docker, shelf and pack sections.
- AG2: fix pass from three reviews. Zero-width and Unicode-tag evasion now caught; spaced SSNs and zero-width-split PII flagged and masked; long unrecognised digit runs hidden in logs; bounded regexes; new reason `alert_only_not_enforcing`; UI contrast, focus and bidi fixes; tests pin the 256 KB reply cap, documented limits, Origin and chunked-body checks, compose `no-new-privileges`; hang-proof and load-tolerant tests.
- AG1: web UI (React, Vite, React Flow diagram with Simulate, Reset and speed; exact /inspect viewer; live threshold sliders; fail-open vs fail-closed comparison; stand-in limits panel; decision log), served by the server with a same-origin CSP; `exchange` added to each inspected stage; `scripts/e2e.mjs` (Playwright, ports 6520/6521).
- AG0: server core. Standalone sidecar (`/inspect`, `/health`, demo config and fault endpoints), stand-in injection detector and PII rails (regex with Luhn and mod 97), detector threshold and benign-label calibration, per-category block thresholds, mock gateway with block, allow and fail-closed logic, fault injector (502, timeout, slow), ten scripted scenarios, decision log with PII masking, API, `GET /api/health` (`demo-health/1`), doctor, Dockerfile and loopback-published compose, gitleaks pre-commit hook, docs.
