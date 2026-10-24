import { afterEach, describe, expect, it, vi } from "vitest";

// workspace.js keeps its id in a module variable, so each case loads a fresh copy.
const load = async () => { vi.resetModules(); return import("./workspace.js"); };

afterEach(() => { vi.unstubAllGlobals(); });

describe("workspace id", () => {
  it("is generated once, matches the server's pattern, and is kept for the tab", async () => {
    const store = new Map();
    vi.stubGlobal("sessionStorage", { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) });
    const { getWorkspaceId } = await load();
    const a = getWorkspaceId();
    expect(a).toMatch(/^[a-z0-9][a-z0-9-]{0,31}$/);
    expect(a.length).toBeLessThanOrEqual(32);
    expect(getWorkspaceId()).toBe(a);
    expect(store.get("ai-guard-workspace")).toBe(a);
  });

  it("reuses a saved id only when it is valid; a hostile saved value is replaced", async () => {
    const store = new Map([["ai-guard-workspace", "../../etc"]]);
    vi.stubGlobal("sessionStorage", { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)) });
    const { getWorkspaceId } = await load();
    expect(getWorkspaceId()).not.toBe("../../etc");
    expect(store.get("ai-guard-workspace")).toMatch(/^w-/);
  });

  it("works with storage blocked: a memory-only id", async () => {
    vi.stubGlobal("sessionStorage", { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } });
    const { getWorkspaceId } = await load();
    const id = getWorkspaceId();
    expect(id).toMatch(/^w-[0-9a-f]{12}$/);
    expect(getWorkspaceId()).toBe(id);
  });
});
