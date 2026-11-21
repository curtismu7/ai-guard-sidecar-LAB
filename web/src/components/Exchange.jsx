import React from "react";
import Json from "./JsonPane.jsx";
import { StandIn, Unverified } from "./Badges.jsx";

// The exact JSON the gateway sends to /inspect and the answer it gets back (display copies: PII masked, hidden characters visible).
function Pane({ title, sub, value, hot }) {
  return (
    <div className="pane">
      <h4>{title} <span className="sub">{sub}</span></h4>
      <Json value={value} label={`${title} JSON`} hot={hot} />
    </div>
  );
}

export default function Exchange({ run }) {
  const stages = run ? run.stages.filter((s) => s.exchange) : [];
  return (
    <section aria-labelledby="ex-h" className="card">
      <div className="card-head">
        <h2 id="ex-h">The /inspect exchange</h2>
        <span className="badges"><Unverified /><StandIn /></span>
      </div>
      {!stages.length ? <p className="empty">Run a scenario to see the exact request the gateway sends and the answer it gets back.</p> : stages.map((st) => (
        <div key={st.stage} className="exchange" data-testid={`exchange-${st.stage}`}>
          <h3>{st.stage === "request" ? "Request direction" : "Response direction"}</h3>
          <div className="panes">
            <Pane title="Gateway sends" sub="POST /inspect" value={st.exchange.request} hot={["text"]} />
            <Pane title="Sidecar answers" sub={st.exchange.response.status ? `HTTP ${st.exchange.response.status}` : "no answer"} value={st.exchange.response.body ?? { error: st.exchange.response.error }} hot={["category"]} />
          </div>
        </div>
      ))}
      {stages.length > 0 && <p className="fine">Shown with PII masked and secret-looking strings redacted, and long text cut at 300 characters. Hidden characters appear as <code>[U+200B]</code> style escapes. An empty findings list means allow. Each box reads as a Form or as the exact JSON (the buttons above it); neither scrolls.</p>}
    </section>
  );
}
