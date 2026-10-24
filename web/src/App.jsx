import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "./lib/api.js";
import { buildSteps } from "./lib/model.js";
import { Demo, StandIn, Unverified } from "./components/Badges.jsx";
import Story from "./components/Story.jsx";
import Diagram from "./components/Diagram.jsx";
import Exchange from "./components/Exchange.jsx";
import Findings from "./components/Findings.jsx";
import Thresholds from "./components/Thresholds.jsx";
import Outage from "./components/Outage.jsx";
import StandInPanel from "./components/StandInPanel.jsx";
import Log from "./components/Log.jsx";
import Inert from "./components/Inert.jsx";
import HostedBanner from "./components/HostedBanner.jsx";

const THEME_KEY = "ai-guard-theme";
const readTheme = () => {
  try { const t = localStorage.getItem(THEME_KEY); if (t === "dark" || t === "light") return t; } catch { /* storage blocked */ }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
};
const MAX_TEXT = 4000;

export default function App() {
  const [theme, setTheme] = useState(readTheme);
  const [scenarios, setScenarios] = useState([]);
  const [config, setConfig] = useState(null);
  const [fault, setFault] = useState({ mode: "none", delayMs: 0 });
  const [standIn, setStandIn] = useState(null);
  const [decisions, setDecisions] = useState([]);
  const [selected, setSelected] = useState("benign");
  const [custom, setCustom] = useState({ requestText: "", upstreamText: "", caller: "" });
  const [result, setResult] = useState(null);
  const [activeRun, setActiveRun] = useState(0);
  const [runKey, setRunKey] = useState(0);
  const [compare, setCompare] = useState(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [info, setInfo] = useState(null);
  const saveTimer = useRef(null);
  const latest = useRef({});

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage blocked */ }
  }, [theme]);

  const fail = (e) => setError(e?.message || "Something went wrong.");
  const refreshDecisions = useCallback(() => api.getDecisions().then((d) => setDecisions(d.decisions)).catch(fail), []);
  const refreshStandIn = useCallback(() => api.getStandIn().then(setStandIn).catch(fail), []);
  const loadConfig = useCallback(() => api.getConfig().then((c) => { setConfig(c); if (c.fault) setFault(c.fault); }).catch(fail), []);

  useEffect(() => {
    api.getScenarios().then((s) => setScenarios(s.scenarios)).catch(fail);
    loadConfig(); refreshStandIn(); refreshDecisions();
    api.getInfo().then(setInfo).catch(() => setInfo(null));
  }, [loadConfig, refreshStandIn, refreshDecisions]);

  const gw = config?.gateway;
  const thresholds = gw?.blockThresholds ?? { prompt_injection: "medium", jailbreak: "none", pii: "high" };
  const failClosed = gw?.failClosed ?? true;
  const detector = config?.sidecar?.detector ?? { threshold: 0.9, benignLabels: [] };

  // Edits show at once and are saved (all of the gateway, or all of the sidecar settings) shortly after.
  latest.current = { config };
  const scheduleSave = (part, next) => {
    setConfig((c) => ({ ...c, ...next }));
    latest.current.config = { ...latest.current.config, ...next };
    clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(async () => {
      const c = latest.current.config;
      try {
        await api.putConfig(part === "gateway" ? { gateway: c.gateway } : { sidecar: c.sidecar });
        if (part === "sidecar") refreshStandIn();
      } catch (e) { fail(e); loadConfig(); }
    }, 200);
  };
  const onThreshold = (cat, level) => scheduleSave("gateway", { gateway: { ...gw, blockThresholds: { ...thresholds, [cat]: level } } });
  const onFailClosed = (v) => scheduleSave("gateway", { gateway: { ...gw, failClosed: v } });
  const onDetector = (d) => scheduleSave("sidecar", { sidecar: { ...config.sidecar, detector: d } });
  const onFault = async (f) => {
    setError(""); setFault(f);
    try { const r = await api.putFault(f); setFault(r.fault); } catch (e) { fail(e); loadConfig(); }
  };

  const show = (res, meta, label) => {
    setResult({ ...res, meta });
    setActiveRun(0);
    setRunKey((k) => k + 1);
    const first = res.runs[0];
    setStatus(`${label}: ${res.runs.map((r) => (r.outcome === "block" ? `BLOCK at ${r.blockedAt}` : "ALLOW")).join(" / ")}.`);
    return first;
  };
  const guarded = async (fn) => {
    if (busy) return;
    setBusy(true); setError("");
    try { await fn(); await refreshDecisions(); } catch (e) { fail(e); } finally { setBusy(false); }
  };

  const simulate = () => guarded(async () => {
    const meta = scenarios.find((s) => s.id === selected);
    const res = await api.runScenario(selected);
    show(res, meta?.runs ?? [], res.title);
  });
  const runMine = () => guarded(async () => {
    const c = { requestText: custom.requestText };
    if (custom.upstreamText) c.upstreamText = custom.upstreamText;
    if (custom.caller) c.caller = custom.caller;
    const res = await api.runCustom(c);
    show(res, [{ failClosed: null }], "Your text");
  });
  const runCompare = () => guarded(async () => {
    const res = await api.runScenario("outage-502");
    setCompare(res.runs);
    show(res, scenarios.find((s) => s.id === "outage-502")?.runs ?? [], res.title);
  });
  const tryText = (text) => { setCustom((c) => ({ ...c, requestText: text.slice(0, MAX_TEXT) })); setStatus("Text copied into the box below. Press Run my text."); document.getElementById("custom-text")?.focus(); };
  const reset = () => guarded(async () => {
    await api.postReset();
    setResult(null); setCompare(null); setStatus("Reset: defaults restored, no fault, empty log.");
    await loadConfig(); await refreshStandIn();
  });
  const doReset = () => { reset(); };

  const picked = scenarios.find((s) => s.id === selected);
  const run = result?.runs[activeRun] ?? null;
  const runMeta = result?.meta?.[activeRun] ?? {};
  const effThresholds = run?.caller ? run.policy.blockThresholds : thresholds;
  const effFailClosed = runMeta.failClosed != null && result?.scenario ? run.policy.failClosed : failClosed;
  const steps = result ? result.runs.flatMap((r) => buildSteps(r).map((s) => ({ ...s, runLabel: result.runs.length > 1 ? r.label : null }))) : [];

  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <HostedBanner banner={info?.banner} />
      <header className="top">
        <div className="top-in">
          <h1>AI Guard Sidecar</h1>
          <span className="badges" data-testid="mode-badge"><Demo /><StandIn /><Unverified /></span>
          <button type="button" className="btn theme" onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>{theme === "dark" ? "Light" : "Dark"} theme</button>
        </div>
      </header>
      <main id="main" tabIndex={-1}>
        <p className="lede">How an external guardrail sidecar plugs into an agent gateway. A mock gateway sends text to a stand-in sidecar over loopback HTTP and applies its answer. Pick a scenario, press Simulate, then change the thresholds or break the sidecar.</p>
        <Story />
        {error && <p role="alert" className="error" data-testid="error">{error}</p>}
        <p className="sr-only" role="status" aria-live="polite" data-testid="status">{status}</p>

        <div className="grid two">
          <section aria-labelledby="pick-h" className="card">
            <div className="card-head"><h2 id="pick-h">1. Pick something to try</h2></div>
            <fieldset className="picker">
              <legend className="sr-only">Scenario</legend>
              {scenarios.map((s) => (
                <label key={s.id} className={`pick ${selected === s.id ? "on" : ""}`}>
                  <input type="radio" name="scenario" value={s.id} checked={selected === s.id} onChange={() => setSelected(s.id)} />
                  <span>{s.title}{s.knownLimit && <em className="limit-tag">{s.knownLimit === "miss" ? "a miss" : "false alarm"}</em>}</span>
                </label>
              ))}
            </fieldset>
            {picked && <p className="teaches" data-testid="teaches">{picked.teaches}</p>}
            <div className="row"><button type="button" className="btn primary" onClick={simulate} disabled={busy || !picked}>{busy ? "Running..." : "Run scenario"}</button></div>

            <h3 className="sub-h">Or type your own</h3>
            <label htmlFor="custom-text">Prompt sent by the client</label>
            <textarea id="custom-text" dir="ltr" rows={3} maxLength={MAX_TEXT} value={custom.requestText} onChange={(e) => setCustom({ ...custom, requestText: e.target.value })} placeholder="Ignore all previous instructions and..." />
            <label htmlFor="custom-reply">What the upstream answers (optional)</label>
            <textarea id="custom-reply" dir="ltr" rows={2} maxLength={MAX_TEXT} value={custom.upstreamText} onChange={(e) => setCustom({ ...custom, upstreamText: e.target.value })} placeholder="Try a reply that leaks an SSN" />
            <label htmlFor="custom-caller">Calling agent key</label>
            <select id="custom-caller" value={custom.caller} onChange={(e) => setCustom({ ...custom, caller: e.target.value })}>
              <option value="">None (use the thresholds on this page)</option>
              {config && Object.entries(config.callers).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <div className="row">
              <button type="button" className="btn primary" onClick={runMine} disabled={busy || !custom.requestText.trim()}>Run my text</button>
              <button type="button" className="btn" onClick={() => setCustom((c) => ({ ...c, requestText: `${c.requestText}​` }))}>Add a hidden character</button>
            </div>
            <p className="fine">Your text is only ever shown as text. It is masked for PII and hidden characters are made visible before it is logged or returned.</p>
          </section>

          <Diagram steps={steps} runKey={runKey} theme={theme} onSimulate={simulate} onReset={doReset} busy={busy} canSimulate={!!picked} />
        </div>

        {result && (
          <section aria-labelledby="res-h" className="card result" data-testid="result">
            <div className="card-head">
              <h2 id="res-h">Result: <Inert text={result.title} /></h2>
              {result.knownLimit && <StandIn>{result.knownLimit === "miss" ? "STAND-IN MISS" : "STAND-IN FALSE ALARM"}</StandIn>}
            </div>
            {result.teaches && <p>{result.teaches}</p>}
            {result.runs.length > 1 && (
              <div className="tabs" role="group" aria-label="Runs in this scenario">
                {result.runs.map((r, i) => (
                  <button key={r.id} type="button" className={`btn ${i === activeRun ? "primary" : ""}`} aria-pressed={i === activeRun} onClick={() => setActiveRun(i)}>{r.label}</button>
                ))}
              </div>
            )}
            {run && (
              <p className="recorded" data-testid="recorded">
                {result.runs.length > 1 ? `${run.label}: ` : ""}recorded decision <strong className={`verdict v-${run.outcome}`}>{run.outcome === "block" ? `BLOCK at ${run.blockedAt}` : "ALLOW"}</strong>
                {run.expectationMet === false && <span className="fine"> (differs from this scenario's default expectation because settings were changed)</span>}
              </p>
            )}
          </section>
        )}

        <Exchange run={run} />

        <div className="grid two">
          <Findings run={run} thresholds={effThresholds} failClosed={effFailClosed} />
          <Thresholds thresholds={thresholds} onThreshold={onThreshold} detector={detector} onDetector={onDetector} run={run} recorded={run && { outcome: run.outcome, blockedAt: run.blockedAt }} failClosed={effFailClosed} previewThresholds={effThresholds} />
        </div>

        <div className="grid two">
          <Outage failClosed={failClosed} onFailClosed={onFailClosed} fault={fault} onFault={onFault} compare={compare} onCompare={runCompare} busy={busy} />
          <StandInPanel info={standIn} onTry={tryText} />
        </div>

        <Log decisions={decisions} />
        <footer className="foot">Demo only. Loopback only. No model, no network. The /inspect contract and gateway behaviour are as understood from the demo environment, UNVERIFIED against product documentation, and nothing here says anything about real product detection quality, defaults or licensing.</footer>
      </main>
    </>
  );
}
