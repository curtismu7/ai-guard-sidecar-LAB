import React from "react";

// Provenance and honesty badges. They sit next to anything that shows detection or gateway behaviour.
export const Unverified = ({ children = "UNVERIFIED" }) => (
  <span className="badge badge-warn" title="As understood from the demo environment; not checked against product documentation.">{children}</span>
);
export const StandIn = ({ children = "STAND-IN" }) => (
  <span className="badge badge-info" title="A deterministic keyword stand-in for a real classifier. It says nothing about any product's detection quality.">{children}</span>
);
export const Demo = () => <span className="badge badge-demo" data-testid="demo-badge" title="Nothing real is touched: no model, no network.">DEMO</span>;
