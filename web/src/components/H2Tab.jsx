import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "../lib/api.js";
import ClaimTag from "./ClaimTag.jsx";
import Findings from "./Findings.jsx";
import Inert from "./Inert.jsx";
import Kinds from "./Kinds.jsx";
import Rules from "./Rules.jsx";
import PromptLog from "./PromptLog.jsx";

const MAX_TEXT = 4000;
const list = (v) => (Array.isArray(v) ? v : []);

// The H2 2026 release tab: personal-data kinds, secret detectors, your own gitleaks-format rules and prompt logging sealed to your key.
// Everything here is a Ping release claim, UNVERIFIED on our tenant; the app's own counts are computed by its engine, never typed in.
export default function H2Tab({ config, onPiiKinds, onSecretsRail, thresholds, failClosed, keyring, setKeyring, resetKey, onRan }) {
  const [h2, setH2] = useState(null);
  const [error, setError] = useState("");
  const [text, setText] = useState({ requestText: "", upstreamText: "" });
  const [ran, setRan] = useState(null);
  const [busy, setBusy] = useState(false);
  const [logSignal, setLogSignal] = useState(0);
  const seq = useRef(0);

  const load = useCallback(() => {
    const n = (seq.current += 1);
    api.getH2().then((d) => { if (n === seq.current) { setH2(d); setError(""); } }).catch((e) => { if (n === seq.current) setError(e?.message || "Could not load the H2 2026 data."); });
  }, []);
  useEffect(() => { load(); setRan(null); }, [load, resetKey]);

  const run = async () => {
    if (busy) return;
    setBusy(true); setError("");
    try {
      const c = { requestText: text.requestText };
      if (text.upstreamText) c.upstreamText = text.upstreamText;
      const res = await api.runCustom(c);
      setRan(res.runs[0]); setLogSignal((s) => s + 1); onRan?.();
    } catch (e) { setError(e?.message || "The run failed."); } finally { setBusy(false); }
  };

  const numbers = list(h2?.numbers); const fields = list(h2?.fields); const why = list(h2?.whyItMatters);
  const sidecar = config?.sidecar;
  return (
    <div className="stack" data-testid="h2-tab">
      <section className="card" aria-labelledby="h2-intro-h">
        <div className="card-head"><h2 id="h2-intro-h">AIGuard data protection, H2 2026</h2><span className="badges"><ClaimTag tag="deck" /></span></div>
        <p>Ping's deck "ID4AI Workforce - H2 2026" (slides 50 and 53, release dated 2026-11-02) says AIGuard inspects content in and out, goes from 5 to 23 personal-data kinds, lets you paste your own gitleaks-format rules, ships maintained secret detectors, and lets you keep prompts encrypted to a key only you hold. This tab lets you try the same ideas on this app's own small engine. Each field below says where it comes from.</p>
        {error && <p role="alert" className="error" data-testid="h2-error">{error}</p>}
      </section>

      <section className="card" aria-labelledby="h2-num-h">
        <div className="card-head"><h2 id="h2-num-h">Ping's numbers, and this app's own</h2></div>
        <p className="fine">The left column is what Ping's deck says (not measured by us). The right column is computed now by this app's own engine: these are its illustrative examples, not Ping's sets and not a measure of the product.</p>
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Numbers table, scrollable">
          <table data-testid="numbers">
            <thead><tr><th scope="col">What</th><th scope="col">Ping says</th><th scope="col">This app ships</th></tr></thead>
            <tbody>
              {numbers.map((n) => (
                <tr key={n.id} data-testid={`num-${n.id}`}>
                  <th scope="row">{n.label}</th>
                  <td><strong>{n.ping}</strong> <ClaimTag tag={n.pingTag} />{n.pingNote && <span className="fine"> {n.pingNote}</span>}</td>
                  <td>{n.app === null ? <span className="fine">{n.appNote}</span> : <><strong>{n.app}</strong> <ClaimTag tag={n.appTag} /><span className="fine"> {n.appNote}</span></>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <Kinds h2={h2} sidecar={sidecar} onPiiKinds={onPiiKinds} onSecretsRail={onSecretsRail} />
      <Rules h2={h2} resetKey={resetKey} />

      <section className="card" aria-labelledby="h2-try-h">
        <div className="card-head"><h2 id="h2-try-h">Try it through the gateway</h2><span className="badges"><ClaimTag tag="invented" /></span></div>
        <p className="fine">Type text and run it through the mock gateway and the sidecar with the settings above. What you type is masked before it is shown or logged. The decision uses the same thresholds as the first tab; a finding in a category without a slider (secrets, or your own rule's category) blocks at high.</p>
        <label htmlFor="h2-text">Prompt sent by the client</label>
        <textarea id="h2-text" dir="ltr" rows={3} maxLength={MAX_TEXT} value={text.requestText} onChange={(e) => setText({ ...text, requestText: e.target.value })} placeholder="A prompt with a personal-data value or a secret in it" />
        <label htmlFor="h2-reply">What the upstream answers (optional; sealed too when IncludeResponses is on)</label>
        <textarea id="h2-reply" dir="ltr" rows={2} maxLength={MAX_TEXT} value={text.upstreamText} onChange={(e) => setText({ ...text, upstreamText: e.target.value })} />
        <div className="row"><button type="button" className="btn primary" onClick={run} disabled={busy || !text.requestText.trim()} data-testid="h2-run">{busy ? "Running..." : "Run my text"}</button></div>
        {ran && (
          <p className="recorded" data-testid="h2-recorded">
            Decision <strong className={`verdict v-${ran.outcome}`}>{ran.outcome === "block" ? `BLOCK at ${ran.blockedAt}` : "ALLOW"}</strong>{" "}
            {ran.promptLog?.recorded ? <>Sealed as <code>{ran.promptLog.id}</code> under key <code><Inert text={ran.promptLog.kid} /></code>.</> : <span data-testid="h2-notrecorded">Not recorded: {ran.promptLog?.why ?? "prompt logging is off"}.</span>}
          </p>
        )}
        <Findings run={ran} thresholds={thresholds} failClosed={failClosed} />
      </section>

      <PromptLog keyring={keyring} setKeyring={setKeyring} resetKey={resetKey} signal={logSignal} limits={h2?.limits?.promptLog} />

      <section className="card" aria-labelledby="h2-why-h">
        <div className="card-head"><h2 id="h2-why-h">Why it matters</h2><span className="badges"><ClaimTag tag="deck" /></span></div>
        <p className="fine">Challenge, technical and business value as Ping's deck words them. Ping claims, UNVERIFIED on our tenant.</p>
        {why.map((w) => (
          <div key={w.id} className="limit" data-testid={`why-${w.id}`}>
            <h3>{w.title}</h3>
            <p><strong>Challenge.</strong> {w.challenge}</p>
            <p><strong>Technical.</strong> {w.technical}</p>
            <p><strong>Business.</strong> {w.business}</p>
          </div>
        ))}
      </section>

      <section className="card" aria-labelledby="h2-claims-h">
        <div className="card-head"><h2 id="h2-claims-h">Where each field comes from</h2></div>
        <p className="fine">A console swagger name proves a field exists, not how it behaves. Nothing here was measured on our tenant.</p>
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Claim tags table, scrollable">
          <table data-testid="claims">
            <thead><tr><th scope="col">Field or claim</th><th scope="col">Source</th><th scope="col">Note</th></tr></thead>
            <tbody>
              {fields.map((f) => (
                <tr key={f.id}><td>{f.field}</td><td><ClaimTag tag={f.tag} /></td><td>{f.note}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
