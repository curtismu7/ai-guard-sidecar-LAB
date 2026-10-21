import React from "react";
import Inert from "./Inert.jsx";
import { StandIn, Unverified } from "./Badges.jsx";

// The exact JSON the gateway sends to /inspect and the answer it gets back (display copies: PII masked, hidden characters visible).
const pretty = (v) => JSON.stringify(v, null, 2);

function Pane({ title, sub, value }) {
  return (
    <div className="pane">
      <h4>{title} <span className="sub">{sub}</span></h4>
      <pre tabIndex={0} aria-label={`${title} JSON`}><code><Inert text={pretty(value)} /></code></pre>
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
            <Pane title="Gateway sends" sub="POST /inspect" value={st.exchange.request} />
            <Pane title="Sidecar answers" sub={st.exchange.response.status ? `HTTP ${st.exchange.response.status}` : "no answer"} value={st.exchange.response.body ?? { error: st.exchange.response.error }} />
          </div>
        </div>
      ))}
      {stages.length > 0 && <p className="fine">Shown with PII masked and secret-looking strings redacted, and long text cut at 300 characters. Hidden characters appear as <mark className="chip">[U+200B]</mark> style chips. An empty findings list means allow.</p>}
    </section>
  );
}
