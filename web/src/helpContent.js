// What the Help dialog says. Plain, and as hedged as the rest of the lab (rule 2): what was measured, what is simulated, what is UNVERIFIED.
export const HELP_SECTIONS = [
  {
    heading: "What this lab is",
    body: [
      "A small, offline demo of how an external guardrail sidecar plugs into an agent gateway. A mock gateway sends the text of an agent request and the model's response to the sidecar's /inspect endpoint. An empty findings list means allow; a finding at or above its category's block threshold means block. If the sidecar fails, the Fail Closed switch decides between blocking and allowing.",
      "The sidecar here is a real separate HTTP service, not an in-process function call. The gateway calls an embedded sidecar over loopback HTTP (port 6502); you can also run the sidecar alone as its own process with npm run sidecar (port 6501) and point the gateway at it with AI_GUARD_SIDECAR_URL. The container ships only the app and the embedded sidecar on its own loopback — the standalone sidecar is not published."
    ]
  },
  {
    heading: "What was measured, and what is UNVERIFIED",
    body: [
      "The /inspect contract and the gateway behaviour are as understood from the demo environment, UNVERIFIED against product documentation — they come from a sibling project's sidecar README that says the contract was reverse-engineered. Check product documentation before relying on any detail.",
      "The detector is a stand-in: deterministic keyword and pattern rules with a score from 0 to 1. Not a model, not a classifier, no download, no network. It exists so the contract can be taught offline.",
      "The second tab, H2 2026 release, tries ideas from Ping's 'ID4AI Workforce - H2 2026' deck (slides 50 and 53, release 2026-11-02). Every product claim there is a Ping claim, UNVERIFIED on our tenant; the app's own counts are computed by its engine, never typed in.",
      "Nothing here says anything about real product detection quality, defaults or licensing."
    ]
  },
  {
    heading: "How to use the page",
    body: [
      "Two tabs: Sidecar demo and H2 2026 release. On the demo tab, pick something to try from the scenario list (benign, direct-injection, paraphrased-injection, false-positive, pii-request, pii-response, a2a-per-key, outage-502, outage-timeout, slow-sidecar) and press Run scenario. Some scenarios are marked 'a miss' or 'false alarm' on purpose — that is the stand-in's trade-off.",
      "Or type your own: Prompt sent by the client, What the upstream answers, Calling agent key, then Run my text (or Add a hidden character).",
      "Below the result: Thresholds and the detector setting, the Fail Closed switch with the fault injector (none, 502, timeout, slow), the stand-in panel, and the decision Log. The Diagram can be dragged; its Simulate makes a real run and plays the hops back."
    ]
  },
  {
    heading: "Mock and Real",
    body: "The Mock/Real switch changes which sidecar every call goes to. In Mock everything is in-process stand-ins and loopback only; nothing real is contacted. Real is only available if a real sidecar was configured for this deployment; the header badge and the window that opens with the page (MOCK or REAL) say which you are on."
  }
];
