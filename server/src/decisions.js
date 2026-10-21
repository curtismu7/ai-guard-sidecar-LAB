// In-memory decision log: a capped ring buffer. Entries are built from already-masked, already-inert stage data.
export const MAX_DECISIONS = 200;

export function createDecisionLog({ max = MAX_DECISIONS, now = () => new Date() } = {}) {
  let entries = []; let seq = 0;
  return {
    add(entry) {
      seq += 1;
      const full = { id: seq, at: now().toISOString(), ...entry };
      entries.push(full);
      if (entries.length > max) entries = entries.slice(entries.length - max);
      return full;
    },
    list: () => entries.slice().reverse(),
    clear() { entries = []; },
    get size() { return entries.length; },
  };
}
