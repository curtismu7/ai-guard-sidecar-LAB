// Workspace registry (rule 13, mock-only build): one in-memory runtime per workspace id, so one visitor's config, fault
// injection, scenario runs and decision log never touch another's. The id comes from the X-Workspace-Id header (default
// 'default'). It is a label, not a credential: it grants nothing, and nobody can reach another workspace without its id.
// Capped at MAX_WORKSPACES (least recently used non-default workspace dropped first) and idle workspaces expire after
// WORKSPACE_TTL_MS. The default workspace is never dropped by the cap or by expiry.
export const DEFAULT_WORKSPACE = 'default';
export const WORKSPACE_HEADER = 'x-workspace-id';
export const WORKSPACE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const MAX_WORKSPACES = 50;
export const WORKSPACE_TTL_MS = 30 * 60 * 1000;

export function createWorkspaces({ create, max = MAX_WORKSPACES, ttlMs = WORKSPACE_TTL_MS, now = () => Date.now() }) {
  if (!Number.isInteger(max) || max < 2) throw new Error('a workspace registry holds at least 2 workspaces (default plus one)');
  const map = new Map(); // id -> { rt, last }; insertion order is least recently used first

  const expire = () => {
    const t = now();
    for (const [id, e] of map) if (id !== DEFAULT_WORKSPACE && t - e.last > ttlMs) map.delete(id);
  };

  return {
    // Returns the runtime for a valid id, creating it on first use. Invalid ids throw; callers validate headers first.
    get(id = DEFAULT_WORKSPACE) {
      if (typeof id !== 'string' || !WORKSPACE_RE.test(id)) throw new Error('invalid workspace id');
      expire();
      const hit = map.get(id);
      if (hit) { map.delete(id); map.set(id, { rt: hit.rt, last: now() }); return hit.rt; }
      while (map.size >= max) {
        const victim = [...map.keys()].find((k) => k !== DEFAULT_WORKSPACE);
        if (victim === undefined) break;
        map.delete(victim);
      }
      const rt = create(id);
      map.set(id, { rt, last: now() });
      return rt;
    },
    get size() { return map.size; },
    ids: () => [...map.keys()],
  };
}
