# Mock-only SE k8s build (MODE=se-mock)

Rule 18 of the standalone rules: every demo ships a local standalone and a mock-only build for the SE cluster. This is
the second form of AI Guard Sidecar. It is the same image and the same Dockerfile as the local demo, selected by one
setting: `MODE=se-mock`. Nothing here has been deployed. The first deploy to the SE cluster needs the owner's approval.

## What it is

- One container, port 6500, listening on all interfaces inside the pod. The cluster ingress is the only way in.
- Hosted and simulated: the UI shows a banner on every view (`/api/info` carries the text), and `/api/health` reports
  `"mode": "se-mock"`.
- Each visitor gets a workspace. The browser tab sends `X-Workspace-Id`; a visitor's gateway config, fault injector,
  decision log and run queue are their own. Nobody can read or change another workspace without guessing its id, and
  the ids are a label, not a credential.
- A request with no `X-Workspace-Id` (a script or probe) gets a private anonymous workspace (`anon-` plus 16 hex
  characters) for that request only. It is never the shared `default`, so two no-id callers cannot see or change each
  other's state. Because each no-id request is a new workspace, a no-id caller cannot keep state across requests; send
  an id to keep it.
- The detector is still the deterministic stand-in. The contract and gateway behaviour are still UNVERIFIED against
  product documentation.

## What is compiled out or refused

| Feature | Local (`MODE` unset or `local`) | `MODE=se-mock` |
| --- | --- | --- |
| External sidecar (`AI_GUARD_SIDECAR_URL`) | accepted, loopback http only | refused: startup throws and the doctor fails |
| Standalone sidecar port (`AI_GUARD_SIDECAR_PORT`) | used by `npm run sidecar` | refused |
| Standalone sidecar process (`npm run sidecar`, `sidecar-main.js`) | runs | exits 1 under se-mock. The code is still in the image; only this entry point refuses to start |
| `.env` file | read | not read (the manifest is the only source of settings) |
| Workspace header (`X-Workspace-Id`) | ignored (one service) | validated: a malformed id is 400; absent: a private anonymous workspace for that request (never `default`) |
| Sidecar workspace header (`X-AI-Guard-Workspace`, internal) | not sent | sent by the gateway on every call; malformed is 400 |
| Banner (`/api/info`) | `banner: null` | the hosted and simulated text |
| Unknown `MODE` value | error at startup | error at startup (never a fallback) |

Still present in both modes: loopback-only bind unless `AI_GUARD_BIND` opts in (the container does), the Host check,
the Origin and Sec-Fetch-Site checks on writes (in se-mock the one extra origin allowed is `AI_GUARD_PUBLIC_ORIGIN`, which
the manifest sets to `https://<SE host>`: the ingress rewrites Host to loopback but passes the browser's Origin through, so
without it every write from the hosted UI is refused; any other origin, or a port or path on it, is still refused), the credential refusal, the bounded inputs, the zero-outbound netguard.

## State inventory (what is per visitor and what is per process)

Found by reading every module for process-wide state (`server/src`):

| Where | State | Scope in se-mock |
| --- | --- | --- |
| `workspaces.js` | the registry map of workspace id to runtime, with last-use times | process (one registry); capped at 50 workspaces, idle 30 minutes expires, `default` never dropped |
| `service.js` `createService` | gateway config (`config`), run queue (`chain`, `pending`), the decision log it owns | per workspace (one service per workspace) |
| `decisions.js` | ring buffer of up to 200 decisions | per workspace (owned by its service) |
| `sidecar.js` `createSidecarState` | the sidecar's detector config and fault injector | per workspace (`stateFor` picks it by the internal header) |
| `gateway.js` | the sidecar base URL and the workspace header; no state of its own | per workspace (created per service) |
| `health.js` | the last doctor and probe result, refreshed every 60 s | process: it describes the server, not a visitor |
| `doctor.js`, `safety.js`, `config.js` | pure functions over the environment | none |
| `scenarios.js` (`SCENARIOS`, `CALLERS`), `detectors.js` (`RULES`, `RAILS`), `pii.js`, `redaction.js`, `sanitize.js` | fixed tables and regexes, read only | process; not frozen, so a future change could mutate them (see residual risks) |
| `app.js` `API_HEADERS`, the CSP strings | constants | process |

Nothing in se-mock writes to disk or to a database, so there is nothing to clear between visitors beyond the workspace
registry itself.

## How the owner deploys (after approval)

Nothing in this repo contacts a cluster. The owner runs:

```sh
# 1. Build and push the image yourself (the script never builds or pushes), tagged with an immutable sha.
# 2. Dry run: renders the manifests and checks them. No kubectl, no cluster.
OWNER_APPROVED=1 NAMESPACE=<ns> IMAGE=<registry>/<repo>/ai-guard-sidecar:<sha> SE_HOST=<host> k8s/deploy.sh --dry-run
# 3. Deploy: only with OWNER_APPROVED=1, the explicit approval for the first SE deploy of this app.
OWNER_APPROVED=1 NAMESPACE=<ns> IMAGE=<registry>/<repo>/ai-guard-sidecar:<sha> SE_HOST=<host> k8s/deploy.sh
```

The manifests carry only the placeholders `__IMAGE__` and `__SE_HOST__`. The namespace is passed to kubectl with `-n`
and is never written into a manifest. The script refuses an unapproved run, a `latest` or untagged image, a bad host
or namespace, and any unreplaced token.

After the deploy, check by content, not by a 200:

- `GET /api/info` returns `"hosted": true`, `"mode": "se-mock"` and the banner text;
- `GET /api/health` returns `demo-health/1` with `"mode": "se-mock"` and `"state": "ready"`;
- the registry manifest and the pod's image ID match `IMAGE`;
- only then hand over the full https URL after a browser check.

The Ingress host is a placeholder until the owner supplies one. The Ingress rewrites the Host header to `127.0.0.1:6500`
for the pod, because the app accepts loopback Host headers only.

## Checks in the repo

- `scripts/k8s.test.mjs` (run by `npm test`): the manifests keep their safety properties (probes, non-root, read-only
  root filesystem, dropped capabilities, no privileged, no hostPath, no secret, image placeholder, `MODE=se-mock`), and
  the deploy script refuses what it must refuse.
- `server/test/se-mock.test.js`: refusals, the health mode, the banner, malformed ids, two workspaces that cannot see or
  change each other, and the embedded sidecar keeping per-workspace fault state.
- `server/test/workspaces.test.js`: id validation, the cap, least-recently-used eviction, the TTL and the default's
  protection.
- `web/src/lib/workspace.test.js` and `web/src/App.test.jsx`: the tab's id and the banner.

## Residual risks

- Workspace ids are a label. Anyone who can send a request to the ingress can use any id, including one a colleague
  is using. The data is synthetic, so the exposure is a demo's settings and decision log, not customer data.
- State is in memory and per pod. A restart clears every workspace. `replicas: 1` keeps one visitor on one pod; a
  second replica would split workspaces.
- The cap (50) and the TTL (30 minutes) bound memory, not request rate. The run queue is capped per workspace (4) but
  the number of workspaces is not rate-limited.
- The constant tables are not frozen. A future bug could mutate `SCENARIOS` or `CALLERS` and affect every visitor.
- The banner and the docs say the detector is a stand-in. The UI does not guarantee that a screenshot carries the
  banner.
- The container runs with a read-only root filesystem and an emptyDir `/tmp`. Node's own runtime is not sandboxed
  beyond those settings and the seccomp profile.
- Workspace flood (no auth by design): once 50 workspaces exist, a new id evicts the least recently used non-default
  workspace, so its fault setting and decision log are lost. Anyone holding the URL can do this with about 50 requests.
  This is state loss, not a data leak. Not fixed: a fix needs a credential, which this demo does not have.
- An evicted or expired workspace can be recreated by a sidecar call from a run that was still in flight, because the
  embedded sidecar looks its state up through the same registry. This could evict another workspace in turn. One
  sequential probe showed no cross-workspace leak; real concurrency was not tested.
- Writes with no `Origin` header are accepted (accepted residual risk, pinned by `se-mock.test.js`). Non-browser clients
  send no Origin, and a browser always sends one on a cross-origin write, so the Origin check does not guard them. A page on
  another site cannot send a write without an Origin header, so no browser CSRF path exists here. Only the Sec-Fetch-Site and
  Origin checks guard browser writes; they are unchanged.
- The embedded sidecar still treats a call with no internal `X-AI-Guard-Workspace` header as the shared `default`. The
  gateway always sends the header, and the sidecar port is not published, so nothing outside the pod reaches that path.
- The ingress manifest has no TLS block: TLS depends on the cluster default. Owner decision before the first deploy.
- The mode name is `se-mock`. The standing rulebook (section 6) says `MODE=mock`. Owner decision; the rulebook is not
  changed by this repo.
