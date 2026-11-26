import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The bundle is served by the admin API under a strict CSP: no inline scripts,
// no external origins. Keep assets as files (no inlined data URLs for scripts).
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", sourcemap: false, assetsInlineLimit: 0, modulePreload: { polyfill: false } },
  server: { proxy: { "/api": "http://127.0.0.1:9080" } },
});
