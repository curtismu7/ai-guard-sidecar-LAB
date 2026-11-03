import React from "react";
import { Unverified } from "./Badges.jsx";

// The story in four steps. Fixed text: this demo has one cast and no vertical packs, so the story
// system (the {{cast.*}} token family with a vertical supplying names, as in the sibling demos) is not wired in.
const STEPS = [
  ["1", "The gateway sends text", "The text units of an agent or LLM request, and later of the response, go to the sidecar's /inspect."],
  ["2", "The sidecar answers with findings", "Each finding has a category, a severity and the index of the unit it is about. An empty list means allow."],
  ["3", "The gateway compares", "A finding at or above that category's block threshold means block. Otherwise it allows, maybe with an alert."],
  ["4", "If the sidecar fails", "A Fail Closed toggle decides: block everything, or let everything through unchecked."],
];

export default function Story() {
  return (
    <section aria-labelledby="story-h" className="story">
      <h2 id="story-h" className="sr-only">The story in four steps</h2>
      <ol className="story-strip">
        {STEPS.map(([n, t, d]) => (
          <li key={n}><span className="story-n" aria-hidden="true">{n}</span><div><strong>{t}</strong><p>{d}</p></div></li>
        ))}
      </ol>
      <p className="provenance"><Unverified /> The contract and the gateway behaviour are as understood from the demo environment, UNVERIFIED against product documentation. This app makes no claim about real product detection quality, defaults or licensing.</p>
    </section>
  );
}
