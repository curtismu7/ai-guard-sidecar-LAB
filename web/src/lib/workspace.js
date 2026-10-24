// The visitor's workspace id (mock-only SE build): a random label kept for this browser tab, sent as X-Workspace-Id so the
// server gives this tab its own config, fault settings and decision log. Not a credential. Memory-only if storage is blocked.
const KEY = "ai-guard-workspace";
const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
let memory = null;

const fresh = () => {
  const b = new Uint8Array(6);
  globalThis.crypto.getRandomValues(b);
  return `w-${Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("")}`;
};

export function getWorkspaceId() {
  if (memory) return memory;
  try {
    const saved = sessionStorage.getItem(KEY);
    if (saved && ID_RE.test(saved)) { memory = saved; return memory; }
  } catch { /* storage blocked: fall through to a memory-only id */ }
  memory = fresh();
  try { sessionStorage.setItem(KEY, memory); } catch { /* storage blocked */ }
  return memory;
}
