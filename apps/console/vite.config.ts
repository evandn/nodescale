import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, loadEnv } from "vite";

export default defineConfig(({ command, mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env };
  // Install scripts run the gate as root on your servers, so a production
  // build must pin exactly which release (and SHA-256) they download. CI and
  // tests opt out explicitly.
  if (command === "build" && mode === "production" && env.NODESCALE_ALLOW_UNPINNED_GATE !== "1") {
    const missing = ["VITE_GATE_VERSION", "VITE_GATE_SHA256_AMD64", "VITE_GATE_SHA256_ARM64"].filter((k) => !env[k]);
    if (missing.length || env.VITE_GATE_VERSION === "latest") {
      throw new Error(
        `Refusing to build without a pinned gate release (missing ${missing.join(", ") || "a version other than latest"}). ` +
          "Set the values printed by the Release workflow (see docs/deployment.md), or NODESCALE_ALLOW_UNPINNED_GATE=1 for development builds.",
      );
    }
  }
  return {
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
  };
});
