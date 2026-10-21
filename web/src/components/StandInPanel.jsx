import React from "react";
import Inert from "./Inert.jsx";
import { StandIn } from "./Badges.jsx";

// What the stand-in gets wrong, computed live by the server with the current detector threshold.
export default function StandInPanel({ info, onTry }) {
  return (
    <section aria-labelledby="si-h" className="card">
      <div className="card-head">
        <h2 id="si-h">What the stand-in misses</h2>
        <span className="badges"><StandIn /></span>
      </div>
      <p className="fine">{info ? info.notice : "Loading..."} Detection quality is a property of the model you deploy, not of the sidecar contract.</p>
      <div className="limits">
        {info?.limits.map((l) => (
          <article key={l.id} className={`limit limit-${l.kind}`} data-testid={`limit-${l.kind}`}>
            <h3>{l.kind === "miss" ? "False negative: an attack it misses" : "False positive: a harmless sentence it flags"}</h3>
            <blockquote><Inert text={l.text} /></blockquote>
            <p><strong>Stand-in says: {l.flagged ? "flagged" : "not flagged"}.</strong> {l.why}</p>
            <button type="button" className="btn" onClick={() => onTry(l.text)}>Try this text</button>
          </article>
        ))}
      </div>
    </section>
  );
}
