import React from "react";
import Inert from "./Inert.jsx";
import { StandIn } from "./Badges.jsx";
import { REASON_TEXT, findingBlocks, parseScore, previewStage } from "../lib/model.js";

// Findings per inspected stage, with the live block/allow call against the thresholds shown now.
export default function Findings({ run, thresholds, failClosed }) {
  const stages = run ? run.stages.filter((s) => s.exchange) : [];
  return (
    <section aria-labelledby="fi-h" className="card">
      <div className="card-head">
        <h2 id="fi-h">Findings and the decision</h2>
        <span className="badges"><StandIn /></span>
      </div>
      {!stages.length ? <p className="empty">Nothing run yet.</p> : stages.map((st) => {
        const p = previewStage(st, thresholds, failClosed);
        return (
          <div key={st.stage} className="stage" data-testid={`findings-${st.stage}`}>
            <h3>{st.stage === "request" ? "Request" : "Response"}
              <span className={`verdict v-${p.decision}`} data-testid={`verdict-${st.stage}`}>{p.decision === "block" ? "BLOCK" : "ALLOW"}</span>
            </h3>
            <p className="why">{REASON_TEXT[p.reason]}</p>
            {!st.sidecar.ok && <p className="fault-note">Sidecar did not answer: <code>{st.sidecar.error}</code> after {st.sidecar.latencyMs} ms.</p>}
            {st.sidecar.ok && !st.evaluations.length && <p className="fine">Empty findings list.</p>}
            {st.evaluations.length > 0 && (
              <div className="table-wrap" tabIndex={0} role="region" aria-label={`${st.stage === "request" ? "Request" : "Response"} findings table, scrollable`}>
                <table>
                  <thead><tr><th scope="col">Category</th><th scope="col">Severity</th><th scope="col">Score</th><th scope="col">Block at</th><th scope="col">Result</th><th scope="col">Message</th></tr></thead>
                  <tbody>
                    {st.evaluations.map((e, i) => {
                      const score = parseScore(e.messages);
                      const blocks = findingBlocks(e, thresholds);
                      return (
                        <tr key={i}>
                          <td><code>{e.category}</code></td>
                          <td><span className={`sev sev-${e.severity}`}>{e.severity}</span></td>
                          <td>{score === null ? <span title="Rule based, no numeric score">-</span> : score.toFixed(2)}</td>
                          <td>{thresholds[e.category] ?? "high"}</td>
                          <td><span className={`verdict v-${blocks ? "block" : "allow"}`}>{blocks ? "blocks" : "alert only"}</span></td>
                          <td><Inert text={e.messages.join(" ")} /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}
