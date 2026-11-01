import React from "react";
import { CATEGORIES, LEVELS, previewRun } from "../lib/model.js";
import { StandIn, Unverified } from "./Badges.jsx";

const DESC = {
  prompt_injection: "Instruction overrides, prompt exfiltration, delimiter and hidden-character tricks.",
  jailbreak: "Persona switches and 'do anything' prompts. Alert only by default.",
  pii: "The personal-data kinds switched on in the H2 2026 tab (the original five by default: SSN, card, IBAN, email, phone). Regex plus check digits, no Presidio.",
};

// Per-category block threshold sliders; the decision for the last run is recomputed live.
export default function Thresholds({ thresholds, onThreshold, detector, onDetector, run, recorded, failClosed, previewThresholds }) {
  const prev = run ? previewRun(run, previewThresholds ?? thresholds, failClosed) : null;
  const flipped = prev && recorded && (prev.outcome !== recorded.outcome || prev.blockedAt !== recorded.blockedAt);
  return (
    <section aria-labelledby="th-h" className="card">
      <div className="card-head">
        <h2 id="th-h">Block thresholds</h2>
        <span className="badges"><Unverified>DEMO DEFAULTS</Unverified></span>
      </div>
      <p className="fine">A finding at or above the threshold blocks. "none" makes the category alert-only. Move a slider and the decision for the last run flips below, with no new run needed.</p>
      {CATEGORIES.map((c) => {
        const i = LEVELS.indexOf(thresholds[c]);
        return (
          <div className="slider" key={c}>
            <label htmlFor={`th-${c}`}><code>{c}</code> blocks at <strong data-testid={`th-val-${c}`}>{thresholds[c]}</strong></label>
            <input id={`th-${c}`} type="range" min="0" max="3" step="1" value={i} aria-valuetext={thresholds[c] === "none" ? "none, alert only" : `${thresholds[c]} and above`}
              onChange={(e) => onThreshold(c, LEVELS[Number(e.target.value)])} />
            <div className="ticks" aria-hidden="true">{LEVELS.map((l) => <span key={l}>{l}</span>)}</div>
            <p className="fine">{DESC[c]}</p>
          </div>
        );
      })}
      <div className="live" data-testid="live-decision" aria-live="polite">
        {!prev ? "Run a scenario, then move a slider." : run.caller ? "This run used the calling agent's own per-key guardrail, so these sliders do not change it. Pick a run without a calling key." : (
          <>
            With these settings the last run <strong className={`verdict v-${prev.outcome}`}>{prev.outcome === "block" ? `BLOCKS at ${prev.blockedAt}` : "ALLOWS"}</strong>
            {flipped ? " - this is different from what happened when it ran." : "."}
            {!prev.known && " (The response was never inspected in that run. Run it again to see the response side.)"}
          </>
        )}
      </div>
      <div className="slider">
        <label htmlFor="det-th">Stand-in detector threshold <strong data-testid="det-val">{detector.threshold.toFixed(2)}</strong> <StandIn /></label>
        <input id="det-th" type="range" min="0.5" max="1" step="0.05" value={detector.threshold} onChange={(e) => onDetector({ ...detector, threshold: Math.round(Number(e.target.value) * 100) / 100 })} />
        <p className="fine">Scores at or above this count as a hit. Raise it to cut false positives and miss more; lower it to catch more and flag more. Benign labels: <code>{detector.benignLabels.join(", ")}</code>.</p>
      </div>
    </section>
  );
}
