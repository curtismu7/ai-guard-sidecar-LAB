import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: the API runs on AI_GUARD_PORT (default 6500) and Vite on VITE_PORT (default 6510); /api is proxied.
const api = { target: `http://127.0.0.1:${Number(process.env.AI_GUARD_PORT) || 6500}` };

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: Number(process.env.VITE_PORT) || 6510, strictPort: true, proxy: { "/api": api } },
  test: { environment: "jsdom", globals: true, setupFiles: "./src/testSetup.js" },
});
