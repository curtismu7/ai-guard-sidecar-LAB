import { describe, expect, it } from "vitest";
import { buildSteps, findingBlocks, inert, parseScore, previewRun, previewStage } from "../lib/model.js";
import { POLICY, benignRun, injectionRun, outageRun } from "./fixtures.js";

const T = POLICY.blockThresholds;

describe("block rule", () => {
  it("blocks at the threshold, not only above it", () => {
    expect(findingBlocks({ category: "prompt_injection", severity: "medium" }, T)).toBe(true);
    expect(findingBlocks({ category: "prompt_injection", severity: "low" }, T)).toBe(false);
    expect(findingBlocks({ category: "pii", severity: "high" }, T)).toBe(true);
    expect(findingBlocks({ category: "pii", severity: "medium" }, T)).toBe(false);
  });
  it("none is alert-only, unknown severity counts as high, unknown category blocks at high", () => {
    expect(findingBlocks({ category: "jailbreak", severity: "high" }, T)).toBe(false);
    expect(findingBlocks({ category: "pii", severity: "weird" }, { pii: "high" })).toBe(true);
    expect(findingBlocks({ category: "novel", severity: "high" }, T)).toBe(true);
    expect(findingBlocks({ category: "novel", severity: "medium" }, T)).toBe(false);
  });
});

describe("live preview", () => {
  it("flips a recorded block to allow when the category becomes alert-only", () => {
    const run = injectionRun();
    expect(previewRun(run, T, true)).toMatchObject({ outcome: "block", blockedAt: "request" });
    expect(previewRun(run, { ...T, prompt_injection: "none" }, true)).toMatchObject({ outcome: "allow", reason: "alert_only_below_threshold" });
    expect(previewRun(run, { ...T, prompt_injection: "none" }, true).known).toBe(false);
  });
  it("applies the fail mode to a failed stage", () => {
    expect(previewStage(outageRun(true).stages[0], T, true).decision).toBe("block");
    expect(previewStage(outageRun(true).stages[0], T, false).decision).toBe("allow");
  });
  it("a benign run stays allowed and is fully known", () => {
    expect(previewRun(benignRun(), T, true)).toMatchObject({ outcome: "allow", known: true });
  });
});

describe("helpers", () => {
  it("reads the stand-in score from the message and returns null for rule-only messages", () => {
    expect(parseScore(["Stand-in detector flagged INJECTION (0.95); rules: x"])).toBe(0.95);
    expect(parseScore(["PII rail (regex) flagged ssn"])).toBeNull();
  });
  it("makes hidden characters visible", () => {
    expect(inert("a​b‮c\u0000")).toBe("a[U+200B]b[U+202E]c[U+0000]");
    expect(inert("plain text")).toBe("plain text");
  });
  it("builds steps from a real run: a block at the request never reaches the upstream", () => {
    const blocked = buildSteps(injectionRun());
    expect(blocked.at(-1)).toMatchObject({ nodes: ["upstream"], skipped: true });
    expect(blocked.find((s) => s.decide).decide).toBe("block");
    const ok = buildSteps(benignRun());
    expect(ok.length).toBe(6);
    expect(ok.at(-1).decide).toBe("allow");
    expect(buildSteps(outageRun(false)).find((s) => s.decide).text).toMatch(/failed and Fail Closed is off/);
  });
});
