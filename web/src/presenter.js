// Presenter mode (rule 3): the chrome steps back, the text grows, the story panel opens.
// The Present button in the header turns it on; ?presenter=1 turns it on at load; the
// button or Esc turns it off. Kept in the page only (the URL decides on a fresh load).
// The CSS keys on data-presenter="on".
import React from "react";

let on = false;
const subs = new Set();
const apply = () => {
  if (typeof document === "undefined") return;
  if (on) document.documentElement.dataset.presenter = "on"; else delete document.documentElement.dataset.presenter;
};
export function setPresenter(next) { on = Boolean(next); apply(); subs.forEach((f) => f()); }
export function initPresenter() {
  try { if (new URLSearchParams(window.location.search).get("presenter") === "1") setPresenter(true); } catch { /* no URL */ }
}
export function presenterOn() { return on; }
const subscribe = (f) => { subs.add(f); return () => subs.delete(f); };
export const usePresenter = () => React.useSyncExternalStore(subscribe, () => on, () => false);
