// Opened from Customer Agent LAB: the strip and the header Back button show; nothing is preselected.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { returnLinkFor } from "../return-link/returnTargets.js";
import App from "../App.jsx";
import { POLICY } from "./fixtures.js";

// The same fetch stub shape as App.test.jsx: this app's api module calls fetch, so the tests stub fetch.
// The hosted banner is on so the test can check the strip sits right below it.
const SCENARIOS = [{ id: "benign", title: "Benign prompt", teaches: "No findings means allow.", knownLimit: null, runs: [{ label: "Allowed", caller: null, failClosed: null }] }];
const CONFIG = { gateway: structuredClone(POLICY), sidecar: { detector: { threshold: 0.9, benignLabels: ["benign"] }, rails: { injection: true, regex_pii: true } }, fault: { mode: "none", delayMs: 0 }, callers: {} };
const INFO = { mode: "se-mock", hosted: true, banner: "HOSTED SIMULATION: every decision here is synthetic." };
beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  vi.stubGlobal("fetch", vi.fn(async (url) => {
    const ok = (j) => ({ ok: true, status: 200, json: async () => j });
    if (url === "/api/scenarios") return ok({ scenarios: SCENARIOS });
    if (url === "/api/config") return ok(CONFIG);
    if (url === "/api/info") return ok(INFO);
    if (url === "/api/stand-in") return ok({ notice: "n", limits: [] });
    if (url === "/api/decisions") return ok({ count: 0, decisions: [] });
    throw new Error(`unexpected ${url}`);
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); window.history.replaceState(null, "", "/"); });

const NOTE = { name: "Opened from Customer Agent LAB" };

describe("return link", () => {
  it("the vendored files match return-link.sha256, which names the parent commit", () => {
    const dir = path.join(process.cwd(), "src", "return-link");
    const text = fs.readFileSync(path.join(dir, "return-link.sha256"), "utf8");
    expect(text.split("\n")[0]).toMatch(/^# vendored byte for byte from curtismu7\/AI-DEMO-Standalone shared\/return-link at [0-9a-f]{7,40}/);
    const pins = text.split("\n").filter((l) => l && !l.startsWith("#")).map((l) => l.split(/\s+/));
    expect(pins.map(([, f]) => f).sort()).toEqual(["ReturnLink.jsx", "ReturnLink.test.jsx", "returnTargets.js"]);
    for (const [h, f] of pins) expect(createHash("sha256").update(fs.readFileSync(path.join(dir, f))).digest("hex"), f).toBe(h);
  });

  it("?from=customer-agent: banner first, strip right below, header Back in the tools", async () => {
    window.history.replaceState(null, "", "/?from=customer-agent&uc=UC-LEARN11&vertical=banking");
    render(<App />);
    const note = await screen.findByRole("note", NOTE);
    expect(note.textContent).toContain("UC-LEARN11");
    expect((await screen.findByTestId("hosted-banner")).nextElementSibling).toBe(note);
    expect(document.querySelector(".top-in > button.return-link--header")).not.toBeNull();
    expect(screen.getAllByRole("button", { name: /Back to Customer Agent LAB/ })).toHaveLength(2);
  });
  it("?from=ai-demo-standalone: the strip names AI Demo Standalone; Back goes to /ai-demo-standalone/", () => {
    window.history.replaceState(null, "", "/?from=ai-demo-standalone&uc=UC-NHI2");
    expect(returnLinkFor("ai-guard-sidecar").label).toBe("AI Demo Standalone");
    expect(returnLinkFor("ai-guard-sidecar").href).toBe("http://127.0.0.1:7810/?returned=ai-guard-sidecar&uc=UC-NHI2");
  });


  it("no from, an unknown from or a bad id: no strip, no button", async () => {
    for (const q of ["/", "/?from=elsewhere&uc=UC-LEARN11", "/?from=customer-agent&uc=%3Cb%3E", "/?from=customer-agent&uc=UC-LEARN11&vertical=a%20b"]) {
      window.history.replaceState(null, "", q);
      render(<App />);
      await screen.findByLabelText("Benign prompt");
      expect(screen.queryByRole("button", { name: /Back to/ })).toBeNull();
      expect(screen.queryByRole("note", NOTE)).toBeNull();
      cleanup();
    }
  });

  it("Back goes to the proxy path behind the lab proxy, to the direct URL on the app's own port", () => {
    window.history.replaceState(null, "", "/ai-guard-sidecar/?from=customer-agent&uc=UC-LEARN11");
    expect(returnLinkFor("ai-guard-sidecar").href).toBe("/customer-agent/?returned=ai-guard-sidecar&uc=UC-LEARN11");
    window.history.replaceState(null, "", "/?from=customer-agent&uc=UC-LEARN11");
    expect(returnLinkFor("ai-guard-sidecar").href).toBe("http://127.0.0.1:5603/?returned=ai-guard-sidecar&uc=UC-LEARN11");
  });
});
