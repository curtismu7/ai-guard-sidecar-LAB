import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, Controls, Handle, MarkerType, Position, ReactFlow, applyNodeChanges } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { StandIn, Unverified } from "./Badges.jsx";

// client -> gateway -> sidecar -> upstream, with the decision box. Boxes are movable. The stepper is driven by a real run.
const WIDE = {
  client: { x: 0, y: 70 }, gateway: { x: 230, y: 70 }, sidecar: { x: 470, y: 0 }, upstream: { x: 470, y: 150 }, decision: { x: 230, y: 210 },
};
const COMPACT = {
  client: { x: 0, y: 0 }, gateway: { x: 0, y: 95 }, sidecar: { x: 170, y: 95 }, upstream: { x: 0, y: 190 }, decision: { x: 170, y: 190 },
};
const INFO = {
  client: ["Client", "agent or app"],
  gateway: ["Mock gateway", "applies the decision"],
  sidecar: ["Sidecar", "STAND-IN detector"],
  upstream: ["Upstream", "LLM or agent stub"],
  decision: ["Decision", "allow or block"],
};
const mkEdges = (compact) => [
  { id: "e-cg", source: "client", target: "gateway", sourceHandle: compact ? "b" : "r", targetHandle: compact ? "t" : "l", label: "request" },
  { id: "e-gs", source: "gateway", target: "sidecar", sourceHandle: "r", targetHandle: "l", label: "POST /inspect" },
  { id: "e-gu", source: "gateway", target: "upstream", sourceHandle: compact ? "b" : "r", targetHandle: compact ? "t" : "l", label: "if allowed" },
  { id: "e-gd", source: "gateway", target: "decision", sourceHandle: "b", targetHandle: compact ? "l" : "t" },
];

function Box({ data }) {
  return (
    <div className={`fbox ${data.on ? "on" : ""} ${data.state ? `s-${data.state}` : ""}`} data-node={data.id} tabIndex={-1}>
      <Handle id="l" type="target" position={Position.Left} />
      <Handle id="t" type="target" position={Position.Top} />
      <Handle id="r" type="source" position={Position.Right} />
      <Handle id="b" type="source" position={Position.Bottom} />
      <strong>{data.title}</strong>
      <span>{data.sub}</span>
      {data.badge && <em className="fbadge">{data.badge}</em>}
    </div>
  );
}
const nodeTypes = { box: Box };

const SPEEDS = [["0.5", "0.5x"], ["1", "1x"], ["2", "2x"], ["4", "4x"]];
const BASE_MS = 1500;

// props: steps (from buildSteps, one list for all runs of a scenario, may be empty), runKey (changes on each new run), theme, onSimulate, onReset, busy
export default function Diagram({ steps, runKey, theme, onSimulate, onReset, busy, canSimulate }) {
  const [compact, setCompact] = useState(false);
  const [positions, setPositions] = useState(WIDE);
  const [speed, setSpeed] = useState("1");
  const [idx, setIdx] = useState(-1); // current step; -1 idle
  const box = useRef(null);
  const timer = useRef(null);
  const rf = useRef(null);
  const refit = () => requestAnimationFrame(() => rf.current?.fitView({ padding: 0.12 }));

  useEffect(() => {
    const el = box.current;
    if (!el || typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(() => { setCompact(el.clientWidth > 0 && el.clientWidth < 600); refit(); });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  useEffect(() => { setPositions(compact ? COMPACT : WIDE); refit(); }, [compact]); // eslint-disable-line react-hooks/exhaustive-deps

  // Walk the steps of each new run.
  useEffect(() => {
    clearTimeout(timer.current);
    if (!steps.length) { setIdx(-1); return undefined; }
    setIdx(0);
    let i = 0;
    const tick = () => {
      if (i >= steps.length - 1) return;
      timer.current = setTimeout(() => { i += 1; setIdx(i); tick(); }, BASE_MS / Number(speed));
    };
    tick();
    return () => clearTimeout(timer.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runKey]);

  const step = idx >= 0 ? steps[idx] : null;
  const done = step && idx === steps.length - 1;
  const lit = new Set(step ? step.nodes : []);

  const nodes = useMemo(() => Object.keys(INFO).map((id) => {
    let state = null; let badge = null;
    if (step && lit.has(id)) state = "on";
    if (id === "decision" && step?.decide) { state = step.decide === "block" ? "block" : "allow"; badge = step.decide === "block" ? "BLOCK" : "ALLOW"; }
    if (id === "upstream" && step?.skipped) { state = "skipped"; badge = "NOT CALLED"; }
    return { id, type: "box", position: positions[id], data: { id, title: INFO[id][0], sub: INFO[id][1], on: !!step && lit.has(id), state, badge }, draggable: true };
  }), [positions, step]); // eslint-disable-line react-hooks/exhaustive-deps

  const edges = useMemo(() => mkEdges(compact).map((e) => {
    const on = step?.edges.includes(e.id);
    return { ...e, animated: !!on, className: on ? "edge-on" : "", markerEnd: { type: MarkerType.ArrowClosed }, labelBgPadding: [4, 2], labelBgBorderRadius: 4 };
  }), [compact, step]); // eslint-disable-line react-hooks/exhaustive-deps

  const onNodesChange = useCallback((changes) => {
    setPositions((p) => {
      const arr = applyNodeChanges(changes, Object.keys(p).map((id) => ({ id, position: p[id] })));
      return Object.fromEntries(arr.map((n) => [n.id, n.position]));
    });
  }, []);

  const reset = () => { clearTimeout(timer.current); setIdx(-1); setPositions(compact ? COMPACT : WIDE); refit(); onReset(); };

  return (
    <section aria-labelledby="diagram-h" className="card diagram-card">
      <div className="card-head">
        <h2 id="diagram-h">How the check flows</h2>
        <span className="badges"><StandIn /><Unverified /></span>
      </div>
      <div className="controls" role="group" aria-label="Diagram controls">
        <button type="button" className="btn primary" onClick={onSimulate} disabled={busy || !canSimulate}>{busy ? "Running..." : "Simulate"}</button>
        <button type="button" className="btn" onClick={reset} disabled={busy}>Reset</button>
        <label className="inline">Speed
          <select value={speed} onChange={(e) => setSpeed(e.target.value)} aria-label="Speed">
            {SPEEDS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <span className="hint">Simulate makes a real run of the scenario or text you picked, then plays it back. Drag the boxes to rearrange them.</span>
      </div>
      <div className="flow" ref={box} data-testid="flow" role="group" aria-label="Diagram: client, gateway, sidecar, upstream and decision">
        <ReactFlow
          onInit={(inst) => { rf.current = inst; }} nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange}
          nodesDraggable nodesConnectable={false} elementsSelectable={false} fitView fitViewOptions={{ padding: 0.12 }}
          minZoom={0.3} maxZoom={1.4} zoomOnScroll={false} preventScrolling={false} colorMode={theme}
        >
          <Background gap={20} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <p className="caption" data-testid="caption" aria-live="polite">
        {step ? <><strong>{step.runLabel ? `${step.runLabel} - ` : ""}Step {idx + 1} of {steps.length}.</strong> {step.text}</> : "Press Simulate to run the picked scenario and watch each hop."}
      </p>
      {done && <p className="sr-only" data-testid="sim-done">Simulation finished.</p>}
    </section>
  );
}
