// Switches the page between Mock (the built-in stand-in sidecar, nothing external needed) and Real (an external AI Guard sidecar).
// Real is offered only when the server was started with one; the hosted build is Mock only and cannot be switched.
const REAL_HOW = "Real needs an AI Guard sidecar: start the server with AI_GUARD_SIDECAR_URL set to it, then switch.";
const HOSTED = "The hosted build is Mock only.";

export default function ModeToggle({ info, onSelect }) {
  const loading = !info;
  const source = info?.source;
  const hosted = info?.hosted === true;
  const realOff = loading || hosted || info?.realAvailable !== true;
  const pick = (next) => { if (next !== source) onSelect?.(next); };
  return (
    <div className="mode-toggle" role="group" aria-label="Mode" data-testid="mode">
      <button type="button" aria-pressed={source === "mock"} disabled={loading} onClick={() => pick("mock")} data-testid="mode-mock">Mock</button>
      <button type="button" aria-pressed={source === "real"} disabled={realOff} title={hosted ? HOSTED : realOff && !loading ? REAL_HOW : undefined} onClick={() => pick("real")} data-testid="mode-real">Real</button>
    </div>
  );
}
