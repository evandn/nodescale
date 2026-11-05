import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    // No inline scripts: the CSP forbids them.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    // `pnpm dev` serves the UI; run `pnpm dev:worker` alongside for the API.
    proxy: { "/api": "http://localhost:8787" },
  },
});
