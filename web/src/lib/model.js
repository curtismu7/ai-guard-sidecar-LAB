// Pure helpers for the UI. The block rule is a copy of the server gateway's, so the sliders can show a decision flipping
// live. The server stays the source of truth: a run is always made by POST /api/run.
export const LEVELS = ["low", "medium", "high", "none"]; // strictest first; "none" = alert only
export const CATEGORIES = ["prompt_injection", "jailbreak", "pii"];
const RANK = { low: 1, medium: 2, high: 3 };
export const severityRank = (s) => RANK[s] ?? 0;
export const UNKNOWN_CATEGORY_THRESHOLD = "high";

// At or above the category threshold blocks. Unknown severity counts as high; "none" never blocks.
export function findingBlocks(finding, thresholds) {
  const level = thresholds[finding.category] ?? UNKNOWN_CATEGORY_THRESHOLD;
  if (level === "none") return false;
  return (severityRank(finding.severity) || RANK.high) >= RANK[level];
}

// The stand-in puts its score in the message text: "... flagged INJECTION (0.95); rules: ...". PII rules have none.
export function parseScore(messages = []) {
  for (const m of messages) {
    const hit = /\((\d(?:\.\d{1,2})?)\)/.exec(m);
    if (hit) return Number(hit[1]);
  }
  return null;
}

// Hidden characters made visible, in case a string reaches the UI that the server had not already revealed.
// eslint-disable-next-line no-misleading-character-class
const HIDDEN = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
export const inert = (s) => String(s ?? "").replace(HIDDEN, (c) => `[U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}]`);
export const CHIP = /(\[U\+[0-9A-F]{4,6}\])/;

// Re-decide one inspected stage with the thresholds and fail mode shown now.
export function previewStage(stage, thresholds, failClosed) {
  if (!stage.sidecar.ok) return failClosed ? { decision: "block", reason: "sidecar_error_fail_closed" } : { decision: "allow", reason: "sidecar_error_fail_open" };
  const blocks = (stage.evaluations || []).some((e) => findingBlocks(e, thresholds));
  if (blocks) return { decision: "block", reason: "threshold_met" };
  if (!stage.evaluations?.length) return { decision: "allow", reason: "no_findings" };
  return { decision: "allow", reason: stage.evaluations.every((e) => thresholds[e.category] === "none") ? "alert_only_not_enforcing" : "alert_only_below_threshold" };
}

// What this recorded run would decide under the thresholds/fail mode now. `known` is false when a stage the new
// settings would reach was never inspected in the recorded run (a request that was blocked never reached the response).
export function previewRun(run, thresholds, failClosed) {
  const req = run.stages.find((s) => s.stage === "request");
  const resp = run.stages.find((s) => s.stage === "response" && !s.skipped);
  const r = previewStage(req, thresholds, failClosed);
  if (r.decision === "block") return { outcome: "block", blockedAt: "request", reason: r.reason, known: true };
  if (!resp) return { outcome: "allow", blockedAt: null, reason: r.reason, known: false };
  const s = previewStage(resp, thresholds, failClosed);
  if (s.decision === "block") return { outcome: "block", blockedAt: "response", reason: s.reason, known: true };
  return { outcome: "allow", blockedAt: null, reason: s.reason !== "no_findings" ? s.reason : r.reason, known: true };
}

export const REASON_TEXT = {
  no_findings: "The sidecar returned no findings, so the gateway allows.",
  threshold_met: "A finding is at or above its category's block threshold, so the gateway blocks.",
  alert_only_below_threshold: "There are findings, but all are below their block threshold. The gateway allows and raises an alert.",
  alert_only_not_enforcing: "There are findings, but this category is set to never block (threshold none), so the gateway allows and raises an alert.",
  sidecar_error_fail_closed: "The sidecar failed and Fail Closed is on, so the gateway blocks.",
  sidecar_error_fail_open: "The sidecar failed and Fail Closed is off, so the gateway allows, unchecked.",
};

// Diagram steps built from one real run. Each step names what lights up and says what happened.
export function buildSteps(run) {
  const req = run.stages.find((s) => s.stage === "request");
  const up = run.stages.find((s) => s.stage === "upstream");
  const resp = run.stages.find((s) => s.stage === "response");
  const note = (st) => (st.sidecar.ok ? `${st.evaluations.length} finding${st.evaluations.length === 1 ? "" : "s"} in ${st.sidecar.latencyMs} ms` : `sidecar failed (${st.sidecar.error})`);
  const verdict = (st) => `${st.decision === "block" ? "BLOCK" : "ALLOW"}: ${REASON_TEXT[st.reason]}`;
  const steps = [
    { nodes: ["client", "gateway"], edges: ["e-cg"], text: `The client sends a ${req.unit.role === "a2a_message" ? "message to another agent" : "prompt"} to the gateway.` },
    { nodes: ["gateway", "sidecar"], edges: ["e-gs"], text: `The gateway POSTs the text to the sidecar's /inspect (request direction): ${note(req)}.` },
    { nodes: ["gateway", "decision"], edges: ["e-gd"], decide: req.decision, text: `At the request: ${verdict(req)}` },
  ];
  if (req.decision === "block") {
    steps.push({ nodes: ["upstream"], edges: [], skipped: true, text: "The upstream is never called, so it never sees the text." });
    return steps;
  }
  steps.push({ nodes: ["gateway", "upstream"], edges: ["e-gu"], text: `The gateway forwards to the upstream, which answers (${up.chars} characters).` });
  steps.push({ nodes: ["gateway", "sidecar"], edges: ["e-gs"], text: `The answer is inspected too (response direction): ${note(resp)}.` });
  steps.push({ nodes: ["gateway", "decision"], edges: ["e-gd"], decide: resp.decision, text: `At the response: ${verdict(resp)}` });
  return steps;
}
