import React from "react";
import ClaimTag from "./ClaimTag.jsx";

const list = (v) => (Array.isArray(v) ? v : []);
const GROUP = { national: "National identifiers", financial: "Financial", health: "Health", contact: "Contact" };

// Which personal-data kinds raise a finding, and the bundled secret detectors. The proofs ("valid sample found, near miss not") are
// computed by the engine each time the tab loads. Samples are shown masked: a value of this shape never reaches the page.
export default function Kinds({ h2, sidecar, onPiiKinds, onSecretsRail }) {
  const kinds = list(h2?.kinds); const secrets = list(h2?.secretProofs);
  const selected = list(sidecar?.piiKinds);
  const toggle = (id) => onPiiKinds(selected.includes(id) ? selected.filter((k) => k !== id) : [...selected, id]);
  const ready = !!sidecar;
  return (
    <section className="card" aria-labelledby="h2-kinds-h">
      <div className="card-head"><h2 id="h2-kinds-h">Personal-data kinds</h2><span className="badges"><ClaimTag tag="swagger" /><ClaimTag tag="invented" /></span></div>
      <p className="fine">Detection is per kind (deck claim). Tick the kinds that raise a finding; the original five are on by default so the first tab behaves as it did. Whatever is ticked, every kind is still masked in anything shown. Each numeric kind has a real check digit or a structural check, tried below on a valid sample and a near miss built at run time.</p>
      <div className="row">
        <button type="button" className="btn" disabled={!ready} onClick={() => onPiiKinds(kinds.filter((k) => k.legacy).map((k) => k.id))} data-testid="kinds-original">Original five</button>
        <button type="button" className="btn" disabled={!ready} onClick={() => onPiiKinds(kinds.map((k) => k.id))} data-testid="kinds-all">All {kinds.length} of this app's kinds</button>
        <button type="button" className="btn" disabled={!ready} onClick={() => onPiiKinds([])} data-testid="kinds-none">None</button>
        <span className="fine" data-testid="kinds-count">{selected.length} of {kinds.length} on</span>
      </div>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Personal-data kinds table, scrollable">
        <table data-testid="kinds">
          <thead><tr><th scope="col">On</th><th scope="col">Kind</th><th scope="col">Family</th><th scope="col">What is checked</th><th scope="col">Valid sample (masked)</th><th scope="col">Near miss (masked)</th></tr></thead>
          <tbody>
            {kinds.map((k) => (
              <tr key={k.id} data-testid={`kind-${k.id}`}>
                <td><input type="checkbox" checked={selected.includes(k.id)} disabled={!ready} onChange={() => toggle(k.id)} aria-label={`Detect ${k.label}`} /></td>
                <td>{k.label} <code>{k.id}</code>{k.legacy && <span className="fine"> original</span>}</td>
                <td>{GROUP[k.group] ?? k.group}</td>
                <td>{k.validation} <span className={`sev sev-${k.severity}`}>({k.severity})</span></td>
                <td><code>{k.valid.shown}</code> <span className={`verdict ${k.valid.detected ? "v-allow" : "v-block"}`} data-testid={`valid-${k.id}`}>{k.valid.detected ? "found" : "MISSED"}</span></td>
                <td><code>{k.nearMiss.shown}</code> <span className={`verdict ${k.nearMiss.detected ? "v-block" : "v-allow"}`} data-testid={`near-${k.id}`}>{k.nearMiss.detected ? "FOUND" : "not found"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h3 className="sub-h">Secret and credential detectors <ClaimTag tag="invented" /></h3>
      <label className="switch"><input type="checkbox" checked={!!sidecar?.rails?.secrets} disabled={!ready} onChange={(e) => onSecretsRail(e.target.checked)} data-testid="secrets-rail" /> Run this app's {secrets.length} bundled secret detectors (off by default)</label>
      <p className="fine">Ping's deck says the release ships 364 of them; this app has {secrets.length} examples of its own, written from public key shapes. A finding here is in the category <code>secrets</code>, which has no slider, so it blocks at high.</p>
      <div className="table-wrap" tabIndex={0} role="region" aria-label="Secret detectors table, scrollable">
        <table data-testid="secrets">
          <thead><tr><th scope="col">Detector</th><th scope="col">What it looks for</th><th scope="col">Valid sample (masked)</th><th scope="col">Near miss (masked)</th></tr></thead>
          <tbody>
            {secrets.map((s) => (
              <tr key={s.id}>
                <td><code>{s.id}</code></td><td>{s.description}</td>
                <td><code>{s.valid.shown}</code> <span className={`verdict ${s.valid.detected ? "v-allow" : "v-block"}`}>{s.valid.detected ? "found" : "MISSED"}</span></td>
                <td><code>{s.nearMiss.shown}</code> <span className={`verdict ${s.nearMiss.detected ? "v-block" : "v-allow"}`}>{s.nearMiss.detected ? "FOUND" : "not found"}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
