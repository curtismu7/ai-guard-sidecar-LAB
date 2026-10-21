# Changelog

## 0.1.0

- AG1: web UI (React, Vite, React Flow diagram with Simulate, Reset and speed; exact /inspect viewer; live threshold sliders; fail-open vs fail-closed comparison; stand-in limits panel; decision log), served by the server with a same-origin CSP; `exchange` added to each inspected stage; `scripts/e2e.mjs` (Playwright, ports 6520/6521).
- AG0: server core. Standalone sidecar (`/inspect`, `/health`, demo config and fault endpoints), stand-in injection detector and PII rails (regex with Luhn and mod 97), detector threshold and benign-label calibration, per-category block thresholds, mock gateway with block, allow and fail-closed logic, fault injector (502, timeout, slow), ten scripted scenarios, decision log with PII masking, API, `GET /api/health` (`demo-health/1`), doctor, Dockerfile and loopback-published compose, gitleaks pre-commit hook, docs.
