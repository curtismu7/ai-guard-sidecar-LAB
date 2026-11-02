import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
// The family's shared stylesheet first (tokens, controls, dark mode), then this app's own layout.
import "./standalone-ui.css";
import "./app.css";

createRoot(document.getElementById("root")).render(<App />);
