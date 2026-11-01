import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "../lib/api.js";
import ClaimTag from "./ClaimTag.jsx";
import Inert from "./Inert.jsx";

const MAX = 20000;
// Examples are this app's own invention. They hold no credential: a made-up ticket format and a made-up token prefix.
const GOOD = `# two example rules in the gitleaks rule format
[[rules]]
id = "acme-ticket"
description = "an internal ticket number"
regex = '''ACME-[0-9]{8}'''
keywords = ["acme"]
severity = "high"

[[rules]]
id = "acme-service-token"
description = "a made-up service token"
regex = '''acmetok_[A-Za-z0-9]{20}'''
keywords = ["acmetok_"]
severity = "critical"
`;
const BAD = `${GOOD}
[[rules]]
id = "bad-one"
description = "a pattern that could backtrack without bound"
regex = '''(a+)+b'''
`;
const list = (v) => (Array.isArray(v) ? v : []);

// Your own rules, pasted in the gitleaks rule format. One bad rule refuses the whole paste (nothing is added).
export default function Rules({ resetKey }) {
  const [toml, setToml] = useState("");
  const [rules, setRules] = useState({ custom: [], limits: null });
  const [outcome, setOutcome] = useState(null); // { ok, added } | { ok:false, errors }
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const seq = useRef(0);

  const load = useCallback(() => {
    const n = (seq.current += 1);
    api.getRules().then((r) => { if (n === seq.current) setRules(r); }).catch(() => {});
  }, []);
  useEffect(() => { load(); setOutcome(null); }, [load, resetKey]);

  const paste = async () => {
    if (busy) return;
    setBusy(true); setError(""); setOutcome(null);
    try {
      const r = await api.putRules(toml);
      setOutcome({ ok: true, added: list(r.Added) });
    } catch (e) {
      const errs = list(e.body?.Errors);
      if (errs.length) setOutcome({ ok: false, errors: errs, message: e.body.message });
      else setError(e.message || "The paste failed.");
    } finally { setBusy(false); load(); }
  };
  const clear = async () => {
    if (busy) return;
    setBusy(true); setError("");
    try { await api.deleteRules(); setOutcome(null); } catch (e) { setError(e.message || "Could not remove the rules."); } finally { setBusy(false); load(); }
  };
  const custom = list(rules.custom);
  return (
    <section className="card" aria-labelledby="h2-rules-h">
      <div className="card-head"><h2 id="h2-rules-h">Your own rules (gitleaks format)</h2><span className="badges"><ClaimTag tag="swagger" /><ClaimTag tag="reading" /></span></div>
      <p className="fine">"Your own formats paste in unchanged" is a deck claim. This app reads the gitleaks rule format as: <code>id</code>, <code>description</code>, <code>regex</code>, <code>keywords</code>, <code>entropy</code>, <code>secretGroup</code>, <code>category</code>, <code>severity</code> and <code>[rules.allowlist]</code> <code>regexes</code> (a lab reading). One bad rule refuses the whole paste: nothing is added. Your rules run whenever you have any; they need no switch. Patterns are checked before they ever run (no nesting, no backreferences, no lookaround) and run on at most 10,000 characters.</p>
      <label htmlFor="h2-toml">Paste rules (up to {MAX.toLocaleString("en-US")} characters, at most 20 rules in all)</label>
      <textarea id="h2-toml" dir="ltr" rows={9} maxLength={MAX} spellCheck={false} value={toml} onChange={(e) => setToml(e.target.value)} placeholder="[[rules]]" />
      <div className="row">
        <button type="button" className="btn primary" onClick={paste} disabled={busy || !toml.trim()} data-testid="rules-paste">Add these rules</button>
        <button type="button" className="btn" onClick={() => setToml(GOOD)} data-testid="rules-example">Load two example rules</button>
        <button type="button" className="btn" onClick={() => setToml(BAD)} data-testid="rules-example-bad">Load an example with one bad rule</button>
        <button type="button" className="btn" onClick={clear} disabled={busy || !custom.length} data-testid="rules-clear">Remove all my rules</button>
      </div>
      {error && <p role="alert" className="error" data-testid="rules-error">{error}</p>}
      {outcome?.ok && <p role="status" data-testid="rules-added">Added {outcome.added.length} rule{outcome.added.length === 1 ? "" : "s"}: {outcome.added.map((a) => a.id).join(", ")}.</p>}
      {outcome && !outcome.ok && (
        <div role="alert" className="error" data-testid="rules-refused">
          <strong>The whole paste was refused: nothing was added.</strong>
          <ul>{outcome.errors.map((e, i) => <li key={i}><Inert text={e} /></li>)}</ul>
        </div>
      )}
      <h3 className="sub-h">Your active rules ({custom.length})</h3>
      {!custom.length ? <p className="empty">None yet.</p> : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Your rules table, scrollable">
          <table data-testid="rules-table">
            <thead><tr><th scope="col">Id</th><th scope="col">Category</th><th scope="col">Severity</th><th scope="col">Keywords</th><th scope="col">Entropy</th><th scope="col">Allowlist</th><th scope="col">Description</th></tr></thead>
            <tbody>{custom.map((r) => <tr key={r.id}><td><code><Inert text={r.id} /></code></td><td>{r.category}</td><td>{r.severity}</td><td>{r.keywords}</td><td>{r.entropy}</td><td>{r.allowlist}</td><td><Inert text={r.description} /></td></tr>)}</tbody>
          </table>
        </div>
      )}
      <p className="fine">The pattern, keywords and allowlist are never shown back, only counts. Masking of what you type is a heuristic: it covers the shapes this app knows and your own rules, not every way a value can be written.</p>
    </section>
  );
}
