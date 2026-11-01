import React from "react";

// The five per-field claim tags (see server/src/h2.js TAGS). The words carry the meaning; the colour only helps.
const LABEL = { deck: "deck claim", swagger: "console swagger name (schema only)", reading: "lab reading", invented: "lab-invented", measured: "measured (our note)" };
const CLASS = { deck: "badge-warn", swagger: "badge-info", reading: "badge-demo", invented: "badge-demo", measured: "badge-info" };

export default function ClaimTag({ tag }) {
  if (!LABEL[tag]) return null;
  return <span className={`badge ${CLASS[tag]}`} data-tag={tag} title="Where this comes from. Every Ping release claim is UNVERIFIED on our tenant.">{LABEL[tag]}</span>;
}
export const TAG_LABELS = LABEL;
