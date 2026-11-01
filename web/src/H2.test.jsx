import React from "react";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App.jsx";
import { POLICY, benignRun, injectionRun } from "./test/fixtures.js";
import { generateKeyPair } from "./lib/seal.js";
import { sealRecord, parsePublicJwk } from "../../server/src/seal.js";

const KIND = (id, over = {}) => ({ id, label: `Kind ${id}`, group: "national", validation: "a check", severity: "high", legacy: false, valid: { shown: `m-${id}`, detected: true }, nearMiss: { shown: `n-${id}`, detected: false }, ...over });
const KINDS = [KIND("card", { legacy: true, group: "financial" }), KIND("ssn", { legacy: true }), KIND("es-dni"), KIND("dob", { group: "health", severity: "medium" })];
const H2 = () => ({
  banner: "Ping release claim, UNVERIFIED on our tenant",
  numbers: [
    { id: "pii-kinds", label: "Personal-data kinds", ping: 23, pingTag: "deck", pingNote: "went from 5 to 23", app: 4, appTag: "invented", appNote: "the app's own set" },
    { id: "total-rules", label: "Maintained rules in total", ping: 411, pingTag: "deck", app: null, appTag: null, appNote: "not comparable" },
  ],
  fields: [{ id: "f1", field: "piiKinds", tag: "swagger", note: "only the name" }, { id: "f2", field: "envelope", tag: "invented", note: "ours" }, { id: "f3", field: "x", tag: "reading", note: "r" }, { id: "f4", field: "y", tag: "deck", note: "d" }, { id: "f5", field: "z", tag: "measured", note: "Nothing." }],
  whyItMatters: [{ id: "aiguard", title: "AIGuard (deck slide 53)", challenge: "c1", technical: "t1", business: "b1" }],
  kinds: KINDS,
  secretProofs: [{ id: "lab-aws", description: "an AWS-style key", valid: { shown: "[masked:lab-aws]", detected: true }, nearMiss: { shown: "near", detected: false } }],
  limits: { promptLog: { defaultMaxBytes: 16384, minBytes: 256, maxBytes: 65536, maxRecords: 100, surfaces: ["llm", "mcp", "a2a", "coding_agent"] } },
});
const SIDECAR = () => ({ detector: { threshold: 0.9, benignLabels: ["benign"] }, rails: { injection: true, regex_pii: true, secrets: false }, piiKinds: ["card", "ssn"] });
const SCENARIOS = [{ id: "benign", title: "Benign prompt", teaches: "t", knownLimit: null, runs: [{ label: "Allowed", caller: null, failClosed: null }] }];
const PL0 = () => ({ config: { Enabled: false, PublicKey: "", KeyID: "", Surfaces: [], IncludeResponses: false, MaxBytes: 0 }, status: { recording: false, why: "prompt logging is off" }, records: [], dropped: 0 });

let calls; let state;
const json = (status, j) => ({ ok: status < 400, status, json: async () => j });
beforeEach(() => {
  calls = [];
  state = { sidecar: SIDECAR(), h2: H2(), rules: { custom: [], limits: {} }, pl: PL0(), putRules: null, runResult: null, h2Status: 200 };
  document.documentElement.removeAttribute("data-theme");
  vi.stubGlobal("matchMedia", () => ({ matches: false, addEventListener() {}, removeEventListener() {} }));
  vi.stubGlobal("fetch", vi.fn(async (url, init = {}) => {
    const method = init.method || "GET"; const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ url, method, body });
    if (url === "/api/scenarios") return json(200, { scenarios: SCENARIOS });
    if (url === "/api/config") { if (method === "PUT" && body.sidecar) state.sidecar = body.sidecar; return json(200, { gateway: structuredClone(POLICY), sidecar: state.sidecar, fault: { mode: "none", delayMs: 0 }, callers: {} }); }
    if (url === "/api/info") return json(200, { mode: "local", hosted: false, banner: null });
    if (url === "/api/stand-in") return json(200, { notice: "n", limits: [] });
    if (url === "/api/decisions") return json(200, { count: 0, decisions: [] });
    if (url === "/api/reset") { state.rules = { custom: [], limits: {} }; state.pl = PL0(); return json(200, { ok: true }); }
    if (url === "/api/h2") return state.h2Status === 200 ? json(200, state.h2) : json(state.h2Status, { error: "server_error" });
    if (url === "/api/rules" && method === "GET") return json(200, state.rules);
    if (url === "/api/rules" && method === "PUT") return state.putRules ? state.putRules(body) : json(200, { Added: [{ id: "cst-acme" }], Errors: [] });
    if (url === "/api/rules" && method === "DELETE") { state.rules = { custom: [], limits: {} }; return json(200, { ok: true }); }
    if (url === "/api/prompt-log" && method === "GET") return json(200, state.pl);
    if (url === "/api/prompt-log" && method === "PUT") { if (body.KeyID === "bad") return json(400, { error: "bad_request", message: "refused", errors: [{ field: "KeyID", message: "must be a plain name" }] }); state.pl = { ...state.pl, config: body, status: { recording: !!body.PublicKey, why: "recording" } }; return json(200, state.pl); }
    if (url === "/api/run") return json(200, { scenario: null, title: "Custom text", runs: [state.runResult ?? injectionRun()] });
    throw new Error(`unexpected ${method} ${url}`);
  }));
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const ready = async () => { const user = userEvent.setup(); render(<App />); await screen.findByLabelText("Benign prompt"); return user; };
const openH2 = async (user) => { await user.click(screen.getByTestId("tab-h2")); await screen.findByTestId("numbers"); };

describe("H2 2026 release tab", () => {
  it("shows the release banner on both tabs, and switching tabs never blanks the page", async () => {
    const user = await ready();
    expect(screen.getByTestId("release-banner")).toHaveTextContent("Ping release claim, UNVERIFIED on our tenant");
    expect(screen.getByTestId("release-banner")).toBeVisible();
    for (let i = 0; i < 3; i += 1) {
      await openH2(user);
      expect(screen.getByTestId("release-banner")).toHaveTextContent("UNVERIFIED on our tenant");
      expect(screen.getByTestId("release-banner")).toBeVisible();
      expect(screen.getByTestId("h2-tab")).toBeVisible();
      expect(document.getElementById("panel-demo")).toHaveAttribute("hidden");
      await user.click(screen.getByTestId("tab-demo"));
      expect(screen.getByLabelText("Benign prompt")).toBeVisible();
      expect(screen.getByTestId("tab-demo")).toHaveAttribute("aria-selected", "true");
    }
  });

  it("changing the theme and resetting on either tab does not blank the page", async () => {
    const user = await ready();
    await openH2(user);
    await user.click(screen.getByRole("button", { name: /Switch to (dark|light) theme/ }));
    expect(screen.getByTestId("numbers")).toBeInTheDocument();
    await user.click(screen.getByTestId("tab-demo"));
    await user.click(screen.getByRole("button", { name: "Reset" }));
    await user.click(screen.getByTestId("tab-h2"));
    await screen.findByTestId("numbers");
    expect(calls.filter((c) => c.url === "/api/h2").length).toBeGreaterThanOrEqual(2);
  });

  it("an API failure or a malformed payload shows a message or an error boundary, never a blank page; the tabs keep working", async () => {
    state.h2Status = 500;
    const user = await ready();
    await user.click(screen.getByTestId("tab-h2"));
    expect(await screen.findByTestId("h2-error")).toBeInTheDocument();
    expect(screen.getByTestId("tab-demo")).toBeInTheDocument();
    cleanup();
    state.h2Status = 200; state.h2 = { ...H2(), numbers: "oops", kinds: null, fields: 5, secretProofs: {}, whyItMatters: undefined };
    const u2 = await ready(); await u2.click(screen.getByTestId("tab-h2"));
    expect(await screen.findByTestId("h2-tab")).toBeInTheDocument();
    cleanup();
    state.h2 = { ...H2(), numbers: [{ id: "x", label: { not: "text" }, ping: {}, app: {} }] }; // an object as a React child throws while rendering
    vi.spyOn(console, "error").mockImplementation(() => {});
    const u3 = await ready(); await u3.click(screen.getByTestId("tab-h2"));
    expect(await screen.findByTestId("boundary")).toHaveTextContent("could not be shown");
    expect(screen.getByTestId("release-banner")).toBeInTheDocument();
    await u3.click(screen.getByTestId("tab-demo"));
    expect(screen.getByLabelText("Benign prompt")).toBeVisible();
    await u3.click(screen.getByTestId("tab-h2"));
    expect(await screen.findByTestId("boundary")).toBeInTheDocument();
    console.error.mockRestore?.();
  });

  it("puts Ping's numbers beside the app's own and tags each; the app's figure is the one from the engine", async () => {
    const user = await ready(); await openH2(user);
    const row = screen.getByTestId("num-pii-kinds");
    expect(within(row).getByText("23")).toBeInTheDocument();
    expect(within(row).getByText("4")).toBeInTheDocument();
    expect(within(row).getAllByText("deck claim").length).toBe(1);
    expect(within(row).getByText("lab-invented")).toBeInTheDocument();
    expect(screen.getByTestId("num-total-rules")).toHaveTextContent("411");
    const claims = screen.getByTestId("claims");
    for (const t of ["console swagger name (schema only)", "lab-invented", "lab reading", "deck claim", "measured (our note)"]) expect(within(claims).getByText(t)).toBeInTheDocument();
    expect(screen.getByTestId("why-aiguard")).toHaveTextContent("Challenge. c1");
  });

  it("each personal-data kind checkbox saves the new selection; the quick buttons set the original five, all, none", async () => {
    const user = await ready(); await openH2(user);
    expect(screen.getByTestId("kinds-count")).toHaveTextContent("2 of 4 on");
    await user.click(screen.getByLabelText("Detect Kind es-dni"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body.sidecar?.piiKinds?.join() === "card,ssn,es-dni")).toBe(true));
    await user.click(screen.getByLabelText("Detect Kind card"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body.sidecar?.piiKinds?.join() === "ssn,es-dni")).toBe(true));
    await user.click(screen.getByTestId("kinds-all"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body.sidecar?.piiKinds?.join() === "card,ssn,es-dni,dob")).toBe(true));
    await user.click(screen.getByTestId("kinds-none"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body.sidecar?.piiKinds?.length === 0)).toBe(true));
    await user.click(screen.getByTestId("kinds-original"));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT" && c.body.sidecar?.piiKinds?.join() === "card,ssn").length).toBeGreaterThan(0));
    expect(screen.getByTestId("kinds-count")).toHaveTextContent("2 of 4 on");
  });

  it("shows the computed proofs per kind (valid found, near miss not) and flags a failed proof loudly", async () => {
    state.h2.kinds[2] = KIND("es-dni", { valid: { shown: "m", detected: false }, nearMiss: { shown: "n", detected: true } });
    const user = await ready(); await openH2(user);
    expect(screen.getByTestId("valid-card")).toHaveTextContent("found");
    expect(screen.getByTestId("near-card")).toHaveTextContent("not found");
    expect(screen.getByTestId("valid-es-dni")).toHaveTextContent("MISSED");
    expect(screen.getByTestId("near-es-dni")).toHaveTextContent("FOUND");
  });

  it("the secrets rail switch saves rails.secrets and keeps the other rails", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("secrets-rail"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.body.sidecar?.rails?.secrets === true && c.body.sidecar.rails.injection === true && c.body.sidecar.piiKinds.join() === "card,ssn")).toBe(true));
  });

  it("pasting rules sends the text unchanged and lists what was added; the examples fill the box", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("rules-example"));
    const box = screen.getByLabelText(/Paste rules/);
    expect(box.value).toContain("[[rules]]");
    await user.click(screen.getByTestId("rules-paste"));
    expect((await screen.findByTestId("rules-added"))).toHaveTextContent("cst-acme");
    expect(calls.find((c) => c.url === "/api/rules" && c.method === "PUT").body).toEqual({ toml: box.value });
  });

  it("one bad rule shows the whole paste refused, with the reasons, and nothing as added", async () => {
    state.putRules = () => json(400, { error: "bad_request", message: "the whole paste was refused: nothing was added", Errors: ["rule 3 (line 17): regex refused: nested quantifiers"] });
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("rules-example-bad"));
    await user.click(screen.getByTestId("rules-paste"));
    const out = await screen.findByTestId("rules-refused");
    expect(out).toHaveTextContent("nothing was added");
    expect(out).toHaveTextContent("rule 3 (line 17)");
    expect(screen.queryByTestId("rules-added")).toBeNull();
  });

  it("the active rules table shows counts only, and Remove all my rules clears them", async () => {
    state.rules = { custom: [{ id: "cst-acme", description: "a ticket", category: "secrets", severity: "high", keywords: 1, entropy: 0, secretGroup: 0, allowlist: 0, patternChars: 13 }], limits: {} };
    const user = await ready(); await openH2(user);
    const t = await screen.findByTestId("rules-table");
    expect(t).toHaveTextContent("cst-acme"); expect(t.textContent).not.toMatch(/regex|pattern/i);
    await user.click(screen.getByTestId("rules-clear"));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/rules")).toBe(true));
    await waitFor(() => expect(screen.queryByTestId("rules-table")).toBeNull());
  });

  it("Run my text sends the text, shows the decision and the findings, and says whether it was sealed", async () => {
    const user = await ready(); await openH2(user);
    await user.type(document.getElementById("h2-text"), "ticket please");
    await user.click(screen.getByTestId("h2-run"));
    const rec = await screen.findByTestId("h2-recorded");
    expect(rec).toHaveTextContent("BLOCK at request");
    expect(screen.getByTestId("h2-notrecorded")).toHaveTextContent("Not recorded");
    expect(calls.find((c) => c.url === "/api/run").body).toEqual({ custom: { requestText: "ticket please" } });
    expect(screen.getByTestId("findings-request")).toBeInTheDocument();
  });

  it("every prompt-log setting is sent: Enabled, PublicKey, KeyID, Surfaces, IncludeResponses, MaxBytes", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("pl-enabled"));
    await user.type(screen.getByTestId("pl-public"), '{{"kty":"OKP"}');
    await user.type(screen.getByTestId("pl-kid"), "key-9");
    await user.click(screen.getByTestId("pl-surface-a2a"));
    await user.click(screen.getByTestId("pl-responses"));
    await user.clear(screen.getByTestId("pl-max")); await user.type(screen.getByTestId("pl-max"), "512");
    await user.click(screen.getByTestId("pl-save"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url === "/api/prompt-log")).toBe(true));
    expect(calls.find((c) => c.method === "PUT" && c.url === "/api/prompt-log").body).toEqual({ Enabled: true, PublicKey: '{"kty":"OKP"}', KeyID: "key-9", Surfaces: ["a2a"], IncludeResponses: true, MaxBytes: 512 });
  });

  it("refused prompt-log settings are listed, as text", async () => {
    const user = await ready(); await openH2(user);
    await user.type(screen.getByTestId("pl-kid"), "bad");
    await user.click(screen.getByTestId("pl-save"));
    expect(await screen.findByTestId("pl-errors")).toHaveTextContent("KeyID: must be a plain name");
  });

  it("makes a key pair in the page, saves only the public half, and the private half is never sent", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("pl-gen"));
    await waitFor(() => expect(screen.getByTestId("pl-keyring")).toHaveTextContent("key-1"));
    const pub = screen.getByTestId("pl-public").value;
    expect(JSON.parse(pub).kty).toBe("OKP"); expect(JSON.parse(pub).d).toBeUndefined();
    expect(screen.getByTestId("pl-kid")).toHaveValue("key-1");
    await user.click(screen.getByTestId("pl-save"));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url === "/api/prompt-log")).toBe(true));
    const sent = JSON.stringify(calls.map((c) => c.body ?? null));
    expect(sent).not.toMatch(/"d":/);
    // the key survives a tab switch (it lives in the App, in memory)
    await user.click(screen.getByTestId("tab-demo")); await user.click(screen.getByTestId("tab-h2"));
    await screen.findByTestId("numbers");
    expect(screen.getByTestId("pl-keyring")).toHaveTextContent("key-1");
  });

  it("opens a sealed record in the page with the key held there; a missing key says so; the text is shown as text", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("pl-gen"));
    await waitFor(() => expect(screen.getByTestId("pl-keyring")).toHaveTextContent("key-1"));
    const pub = JSON.parse(screen.getByTestId("pl-public").value);
    const sealed = (rid, kid, text) => sealRecord({ publicKey: parsePublicJwk(pub), keyId: kid, recordId: rid, plaintext: JSON.stringify({ prompt: text, truncated: false }) });
    state.pl = { ...PL0(), records: [
      { id: "pl-1", at: "2026-01-01T00:00:00.000Z", surface: "llm", outcome: "allow", blockedAt: null, categories: ["pii"], kid: "key-1", truncated: false, hasResponse: false, envelope: sealed("pl-1", "key-1", "<img src=x onerror=alert(1)> hello") },
      { id: "pl-2", at: "2026-01-01T00:00:00.000Z", surface: "a2a", outcome: "block", blockedAt: "request", categories: [], kid: "other", truncated: true, hasResponse: false, envelope: sealed("pl-2", "other", "x") },
    ] };
    await user.type(document.getElementById("h2-text"), "x"); await user.click(screen.getByTestId("h2-run")); // a run reloads the record list
    const open1 = await screen.findByTestId("open-pl-1");
    await user.click(open1);
    const pre = await screen.findByTestId("opened-pl-1");
    expect(pre.textContent).toContain("<img src=x onerror=alert(1)> hello");
    expect(pre.querySelector("img")).toBeNull();
    await user.click(screen.getByTestId("open-pl-2"));
    expect(await screen.findByText(/No private key named other is loaded/)).toBeInTheDocument();
  });

  it("a record sealed to another key cannot be opened with the loaded one", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("pl-gen"));
    await waitFor(() => expect(screen.getByTestId("pl-keyring")).toHaveTextContent("key-1"));
    const other = await generateKeyPair();
    state.pl = { ...PL0(), records: [{ id: "pl-1", at: "2026-01-01T00:00:00.000Z", surface: "llm", outcome: "allow", blockedAt: null, categories: [], kid: "key-1", truncated: false, hasResponse: false, envelope: sealRecord({ publicKey: parsePublicJwk(other.publicJwk), keyId: "key-1", recordId: "pl-1", plaintext: "x" }) }] };
    await user.type(document.getElementById("h2-text"), "x"); await user.click(screen.getByTestId("h2-run"));
    await user.click(await screen.findByTestId("open-pl-1"));
    expect(await screen.findByText(/cannot open this record/)).toBeInTheDocument();
  });

  it("Forget all keys empties the keyring", async () => {
    const user = await ready(); await openH2(user);
    await user.click(screen.getByTestId("pl-gen"));
    await waitFor(() => expect(screen.getByTestId("pl-keyring")).toHaveTextContent("key-1"));
    await user.click(screen.getByTestId("pl-forget"));
    expect(screen.getByTestId("pl-keyring")).toHaveTextContent("none");
  });
});
