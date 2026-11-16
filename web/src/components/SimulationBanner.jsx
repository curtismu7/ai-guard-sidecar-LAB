import React from "react";

// The simulation banner, first in <main> in every run (UI patterns section 2). It follows /api/info:
// the hosted mock build (MODE=se-mock) shows the server's own text; a local run says which mode is active and what is simulated.
export const MOCK_TEXT = "Mock mode: the mock gateway sends text to the embedded stand-in sidecar. The detector is a deterministic keyword stand-in, not a real classifier. No tenant, no network, no credentials.";
export const REAL_TEXT = "Real mode: the mock gateway sends text to the external sidecar set by AI_GUARD_SIDECAR_URL, and the findings come from that sidecar. The gateway, its thresholds and the scenarios are still this demo's.";

// Until /api/info answers, or if it fails, info is null and the banner falls back to the local Mock text.
export default function SimulationBanner({ info }) {
  if (info?.hosted && info.banner) return <p role="note" className="banner" data-testid="sim-banner">{info.banner}</p>;
  const real = !!info && !info.hosted && info.source === "real";
  return <p role="note" className="banner" data-testid="sim-banner" data-state={real ? "live" : undefined}>{real ? REAL_TEXT : MOCK_TEXT}</p>;
}
