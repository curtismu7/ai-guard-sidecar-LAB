import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import React from "react";
import fs from "node:fs";
import path from "node:path";
import App from "../App.jsx";
import { POLICY } from "./fixtures.js";

// The header shows this lab's own Verified / In progress mark, read from the same /api/shelf call the Shelf link makes (through the lab-proxy that
// call reaches the shelf, whose payload lists every demo with its mark). The lab's own /api/shelf has no demos, so there is no mark then.
const SCENARIOS = [{ id: "benign", title: "Benign prompt", teaches: "No findings means allow.", knownLimit: null, runs: [{ label: "Allowed", caller: null, failClosed: null }] }];
const CONFIG = { gateway: structuredClone(POLICY), sidecar: { detector: { threshold: 0.9, benignLabels: ["benign"] }, rails: { injection: true, regex_pii: true } }, fault: { mode: "none", delayMs: 0 }, callers: {} };
const mark = (status, label, extra = {}) => ({ status, label, note: "", updatedAt: "2026-11-15", source: "shipped", ...extra });

let shelf; let shelfCalls;
beforeEach(() => {
  shelfCalls = [];
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  vi.stubGlobal("fetch", vi.fn(async (url, init = {}) => {
    const ok = (j) => ({ ok: true, status: 200, json: async () => j });
    if (url === "/api/shelf") { shelfCalls.push(init); return ok(shelf); }
    if (url === "/api/scenarios") return ok({ scenarios: SCENARIOS });
    if (url === "/api/config") return ok(CONFIG);
    if (url === "/api/info") return ok({ mode: "local", hosted: false, banner: null });
    if (url === "/api/stand-in") return ok({ notice: "n", limits: [] });
    if (url === "/api/decisions") return ok({ count: 0, decisions: [] });
    throw new Error(`unexpected ${url}`);
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("verification mark in the header", () => {
  it("shows this lab's own mark beside the Shelf link, and no other lab's", async () => {
    shelf = { shelfUrl: "http://shelf.example", demos: [{ id: "other-lab", verification: mark("in-progress", "In progress") }, { id: "ai-guard-sidecar", verification: mark("verified", "Verified", { note: "Every scenario run on the mock" }) }] };
    render(<App />);
    const header = within(document.querySelector("header.shell-bar"));
    expect(await header.findByText("Verified")).toBeInTheDocument();
    expect(header.getByRole("link", { name: "Shelf" })).toBeInTheDocument();
    expect(header.queryByText("In progress")).toBeNull();
    expect(document.querySelectorAll(".verify")).toHaveLength(1);
    expect(header.getByText("Verified").closest(".verify")).toHaveAttribute("title", expect.stringContaining("Every scenario run on the mock"));
    expect(shelfCalls.every((c) => /^w-[0-9a-f]{12}$/.test(c.headers["X-Workspace-Id"]))).toBe(true); // the workspace header goes out on every /api/shelf call, as for ShelfLink
    expect(shelfCalls.length).toBeGreaterThanOrEqual(2);
  });

  it("shows nothing when the lab is opened on its own port (its /api/shelf has no demos) or the shelf has no mark for it", async () => {
    for (const payload of [{ shelfUrl: "http://shelf.example" }, { shelfUrl: "http://shelf.example", demos: [{ id: "ai-guard-sidecar", verification: null }, { id: "other-lab", verification: mark("verified", "Verified") }] }]) {
      shelf = payload;
      const { unmount } = render(<App />);
      const header = within(document.querySelector("header.shell-bar"));
      expect(await header.findByRole("link", { name: "Shelf" })).toBeInTheDocument(); // the shelf answered, and still no badge
      await screen.findByLabelText("Benign prompt");
      expect(document.querySelector(".verify")).toBeNull();
      unmount();
    }
  });

  it("App.jsx renders exactly one <VerifyMark> with this lab's shelf id (removing the line fails the test above)", () => {
    const src = fs.readFileSync(path.join(process.cwd(), "src", "App.jsx"), "utf8");
    expect(src.match(/<VerifyMark\b/g)).toHaveLength(1);
    expect(src).toContain('<VerifyMark id="ai-guard-sidecar"');
    const entry = JSON.parse(fs.readFileSync(path.join(process.cwd(), "..", "docs", "shelf-entry.json"), "utf8"));
    expect(entry.demos[0].id).toBe("ai-guard-sidecar");
  });
});
