import React from "react";
import Inert from "./Inert.jsx";

const time = (iso) => { try { return new Date(iso).toLocaleTimeString(); } catch { return iso; } };

export default function Log({ decisions }) {
  return (
    <section aria-labelledby="log-h" className="card">
      <div className="card-head"><h2 id="log-h">Decision log</h2><span className="fine">newest first, in memory, PII masked</span></div>
      {!decisions.length ? <p className="empty">No decisions yet.</p> : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Decision log table, scrollable">
          <table data-testid="log">
            <thead><tr><th scope="col">#</th><th scope="col">Time</th><th scope="col">What</th><th scope="col">Decision</th><th scope="col">Why</th><th scope="col">Fault</th></tr></thead>
            <tbody>
              {decisions.slice(0, 30).map((d) => (
                <tr key={d.id}>
                  <td>{d.id}</td><td>{time(d.at)}</td>
                  <td><Inert text={d.scenario ? `${d.scenario}: ${d.label}` : d.label} />{d.caller && <span className="fine"> ({d.caller})</span>}</td>
                  <td><span className={`verdict v-${d.outcome}`}>{d.outcome === "block" ? `BLOCK at ${d.blockedAt}` : "ALLOW"}</span></td>
                  <td><code>{d.reason}</code></td>
                  <td>{d.injectedFault ?? "-"}{d.policy && d.reason.startsWith("sidecar_error") ? (d.policy.failClosed ? " (closed)" : " (open)") : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
