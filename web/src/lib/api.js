// Thin fetch wrapper. JSON only, same origin, no credentials, no extra headers.
async function call(path, method = "GET", body) {
  const init = { method, headers: { Accept: "application/json" } };
  if (body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  const res = await fetch(path, init);
  let json = null;
  try { json = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error(json?.message || json?.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return json;
}

export const getScenarios = () => call("/api/scenarios");
export const getConfig = () => call("/api/config");
export const putConfig = (body) => call("/api/config", "PUT", body);
export const getFault = () => call("/api/fault");
export const putFault = (fault) => call("/api/fault", "PUT", fault);
export const getStandIn = () => call("/api/stand-in");
export const getDecisions = () => call("/api/decisions");
export const runScenario = (scenario) => call("/api/run", "POST", { scenario });
export const runCustom = (custom) => call("/api/run", "POST", { custom });
export const postReset = () => call("/api/reset", "POST");
