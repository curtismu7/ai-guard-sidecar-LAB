import { getWorkspaceId } from "./workspace.js";

// Thin fetch wrapper. JSON only, same origin, no credentials. The only extra header is the workspace id (used by the
// mock-only SE build; the local server ignores it).
async function call(path, method = "GET", body) {
  const init = { method, headers: { Accept: "application/json", "X-Workspace-Id": getWorkspaceId() } };
  if (body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
  const res = await fetch(path, init);
  let json = null;
  try { json = await res.json(); } catch { /* not JSON */ }
  if (!res.ok) {
    const err = new Error(json?.message || json?.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.body = json; // a refusal can carry a list of reasons (Errors for a rule paste, errors for prompt-log settings)
    throw err;
  }
  return json;
}

export const getInfo = () => call("/api/info");
export const setMode = (source) => call("/api/mode", "POST", { source });
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
export const getH2 = () => call("/api/h2");
export const getRules = () => call("/api/rules");
export const putRules = (toml) => call("/api/rules", "PUT", { toml });
export const deleteRules = () => call("/api/rules", "DELETE");
export const getPromptLog = () => call("/api/prompt-log");
export const putPromptLog = (config) => call("/api/prompt-log", "PUT", config);
