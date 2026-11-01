import React, { useCallback, useEffect, useRef, useState } from "react";
import * as api from "../lib/api.js";
import ClaimTag from "./ClaimTag.jsx";
import Inert from "./Inert.jsx";
import { generateKeyPair, openEnvelope, x25519Support } from "../lib/seal.js";

const list = (v) => (Array.isArray(v) ? v : []);
const EMPTY = { Enabled: false, PublicKey: "", KeyID: "", Surfaces: [], IncludeResponses: false, MaxBytes: 0 };
const time = (iso) => { try { return new Date(iso).toLocaleTimeString(); } catch { return iso; } };

// Prompt logging, sealed to a key you hold. The key pair is made HERE with WebCrypto; its private half is kept in memory (`keyring`, held by the
// App), is never sent to the server, never stored and never logged. The server only ever gets the public half. A record opens only here.
export default function PromptLog({ keyring, setKeyring, resetKey, signal, limits }) {
  const [cfg, setCfg] = useState(EMPTY);
  const [view, setView] = useState({ status: null, records: [], dropped: 0 });
  const [errors, setErrors] = useState([]);
  const [msg, setMsg] = useState("");
  const [kid, setKid] = useState("key-1");
  const [support, setSupport] = useState({ ok: true, reason: "" });
  const [opened, setOpened] = useState({});
  const seq = useRef(0);
  const surfaces = list(limits?.surfaces).length ? limits.surfaces : ["llm", "mcp", "a2a", "coding_agent"];

  const load = useCallback((withConfig) => {
    const n = (seq.current += 1);
    api.getPromptLog().then((v) => { if (n !== seq.current) return; setView(v); if (withConfig) setCfg({ ...EMPTY, ...v.config }); }).catch(() => {});
  }, []);
  useEffect(() => { load(true); setOpened({}); setErrors([]); setMsg(""); }, [load, resetKey]);
  useEffect(() => { if (signal) load(false); }, [signal, load]);
  useEffect(() => { x25519Support().then(setSupport); }, []);

  const make = async () => {
    setMsg("");
    const id = kid.trim();
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(id)) { setMsg("Name the key with letters, digits, dot, dash or underscore (up to 64)."); return; }
    if (keyring.some((k) => k.kid === id)) { setMsg(`A key named ${id} is already loaded: choose another name.`); return; }
    try {
      const pair = await generateKeyPair();
      setKeyring([...keyring, { kid: id, publicJwk: pair.publicJwk, privateJwk: pair.privateJwk }]);
      setCfg((c) => ({ ...c, PublicKey: JSON.stringify(pair.publicJwk), KeyID: id }));
      setKid(`key-${keyring.length + 2}`);
      setMsg(`Key ${id} made in this browser. Its private half is held in memory only. Its public half is in the PublicKey box: press Save.`);
    } catch { setMsg("This browser could not make an X25519 key."); }
  };
  const save = async () => {
    setErrors([]); setMsg("");
    try {
      const body = { Enabled: cfg.Enabled, PublicKey: cfg.PublicKey, KeyID: cfg.KeyID, Surfaces: cfg.Surfaces, IncludeResponses: cfg.IncludeResponses, MaxBytes: Number(cfg.MaxBytes) || 0 };
      const v = await api.putPromptLog(body);
      setView(v); setCfg({ ...EMPTY, ...v.config }); setMsg("Saved.");
    } catch (e) {
      const errs = list(e.body?.errors);
      setErrors(errs.length ? errs.map((x) => `${x.field}: ${x.message}`) : [e.message || "The settings were refused."]);
    }
  };
  const toggleSurface = (s) => setCfg((c) => ({ ...c, Surfaces: c.Surfaces.includes(s) ? c.Surfaces.filter((x) => x !== s) : [...c.Surfaces, s] }));
  const open = async (rec) => {
    const k = keyring.find((x) => x.kid === rec.kid);
    if (!k) { setOpened((o) => ({ ...o, [rec.id]: { error: `No private key named ${rec.kid} is loaded in this page.` } })); return; }
    const r = await openEnvelope(k.privateJwk, rec.envelope);
    let parsed = null;
    if (r.ok) { try { parsed = JSON.parse(r.plaintext); } catch { /* shown as text below */ } }
    setOpened((o) => ({ ...o, [rec.id]: r.ok ? { text: parsed ? parsed : r.plaintext } : { error: r.reason } }));
  };
  const status = view.status;
  const records = list(view.records);
  return (
    <section className="card" aria-labelledby="h2-pl-h">
      <div className="card-head"><h2 id="h2-pl-h">Prompt logging, sealed to a key only you hold</h2><span className="badges"><ClaimTag tag="deck" /><ClaimTag tag="swagger" /><ClaimTag tag="invented" /></span></div>
      <p className="fine" data-testid="pl-note">Off until you turn it on, and nothing is recorded without a public key. Each run is sealed on the server to the public key you supply, then who ran it, what was detected and what was decided stay in the clear, and the text opens only in this page with the private key you keep. The settings are console swagger names; that "Privilege never holds the private half" is a deck claim; the envelope format (X25519, HKDF-SHA256, AES-256-GCM) and every limit are this app's own. Run some text above to make records.</p>
      {!support.ok && <p role="alert" className="error" data-testid="no-x25519">{support.reason}</p>}

      <h3 className="sub-h">1. A key pair, made in this browser</h3>
      <label htmlFor="pl-newkid">Key name</label>
      <input id="pl-newkid" value={kid} maxLength={64} onChange={(e) => setKid(e.target.value)} data-testid="pl-newkid" />
      <div className="row"><button type="button" className="btn primary" onClick={make} disabled={!support.ok} data-testid="pl-gen">Generate a key pair in this browser</button>
        <button type="button" className="btn" onClick={() => setKeyring([])} disabled={!keyring.length} data-testid="pl-forget">Forget all keys</button></div>
      <p className="fine" role="status" data-testid="pl-keymsg">{msg}</p>
      <p className="fine" data-testid="pl-keyring">Private keys held in this page's memory: {keyring.length ? keyring.map((k) => k.kid).join(", ") : "none"}. A reload forgets them.</p>

      <h3 className="sub-h">2. The settings (modelPromptLogConfig)</h3>
      <label className="switch"><input type="checkbox" checked={cfg.Enabled} onChange={(e) => setCfg({ ...cfg, Enabled: e.target.checked })} data-testid="pl-enabled" /> Enabled</label>
      <label htmlFor="pl-public">PublicKey (an X25519 public JWK; a private key is refused)</label>
      <textarea id="pl-public" rows={2} spellCheck={false} value={cfg.PublicKey} onChange={(e) => setCfg({ ...cfg, PublicKey: e.target.value })} data-testid="pl-public" />
      <label htmlFor="pl-kid">KeyID</label>
      <input id="pl-kid" value={cfg.KeyID} maxLength={64} onChange={(e) => setCfg({ ...cfg, KeyID: e.target.value })} data-testid="pl-kid" />
      <fieldset><legend>Surfaces (none ticked records every surface; this app only produces llm and a2a)</legend>
        <div className="radios">{surfaces.map((s) => <label key={s} className="inline"><input type="checkbox" checked={cfg.Surfaces.includes(s)} onChange={() => toggleSurface(s)} data-testid={`pl-surface-${s}`} />{s}</label>)}</div>
      </fieldset>
      <label className="switch"><input type="checkbox" checked={cfg.IncludeResponses} onChange={(e) => setCfg({ ...cfg, IncludeResponses: e.target.checked })} data-testid="pl-responses" /> IncludeResponses</label>
      <label htmlFor="pl-max">MaxBytes (0 takes the default{limits ? ` ${limits.defaultMaxBytes}` : ""}; otherwise {limits ? `${limits.minBytes} to ${limits.maxBytes}` : "a bounded size"}; the text of one record, prompt first)</label>
      <input id="pl-max" type="number" min="0" value={cfg.MaxBytes} onChange={(e) => setCfg({ ...cfg, MaxBytes: e.target.value })} data-testid="pl-max" />
      <div className="row"><button type="button" className="btn primary" onClick={save} data-testid="pl-save">Save the settings</button></div>
      {errors.length > 0 && <ul role="alert" className="error" data-testid="pl-errors">{errors.map((e, i) => <li key={i}><Inert text={e} /></li>)}</ul>}
      {status && <p data-testid="pl-status" data-state={status.recording ? "ok" : "warn"}>{status.recording ? "Recording. " : "Not recording. "}{status.why}</p>}

      <h3 className="sub-h">3. Sealed records ({records.length}{view.dropped ? `, ${view.dropped} oldest dropped` : ""})</h3>
      {!records.length ? <p className="empty">No records yet.</p> : (
        <div className="table-wrap" tabIndex={0} role="region" aria-label="Sealed records table, scrollable">
          <table data-testid="pl-records">
            <thead><tr><th scope="col">Id</th><th scope="col">Time</th><th scope="col">Surface</th><th scope="col">Decision</th><th scope="col">Detected</th><th scope="col">Key</th><th scope="col">Content</th></tr></thead>
            <tbody>
              {records.map((r) => (
                <tr key={r.id} data-testid={`rec-${r.id}`}>
                  <td><code>{r.id}</code></td><td>{time(r.at)}</td><td>{r.surface}</td>
                  <td><span className={`verdict v-${r.outcome}`}>{r.outcome === "block" ? `BLOCK at ${r.blockedAt}` : "ALLOW"}</span></td>
                  <td>{list(r.categories).join(", ") || "-"}</td><td><code><Inert text={r.kid} /></code></td>
                  <td>
                    {opened[r.id]?.error && <span className="fault-note" role="alert">{opened[r.id].error}</span>}
                    {opened[r.id]?.text !== undefined && (
                      <pre data-testid={`opened-${r.id}`}><Inert text={typeof opened[r.id].text === "string" ? opened[r.id].text : JSON.stringify(opened[r.id].text, null, 1)} /></pre>
                    )}
                    {opened[r.id]?.text === undefined && <><span className="fine">sealed ({r.envelope?.ct?.length ?? 0} characters){r.truncated ? ", cut at MaxBytes" : ""} </span><button type="button" className="btn" onClick={() => open(r)} data-testid={`open-${r.id}`}>Open in this page</button></>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="fine">What a seal does and does not do: it hides the content from anyone without the private key, including this server, which has no decrypt code. It does not hide the clear fields above, and it does not prove who made a record: the server seals to whatever public key it is given.</p>
    </section>
  );
}
