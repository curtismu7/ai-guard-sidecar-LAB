import React from "react";
import { CHIP, inert } from "../lib/model.js";

// Text from a user, an agent or the sidecar is only ever rendered as text. Hidden characters are shown as [U+XXXX] chips.
export default function Inert({ text }) {
  return <>{inert(text).split(CHIP).map((part, i) => (CHIP.test(part) ? <mark key={i} className="chip">{part}</mark> : part))}</>;
}
