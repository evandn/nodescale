import type { GateRelease } from "./install.ts";

/**
 * The gate release that generated install scripts download. Compiled into
 * the frontend at build time (VITE_GATE_* variables) rather than fetched
 * from the control plane, which is not trusted to choose what runs as root
 * on your servers.
 */
export const GATE_RELEASE: GateRelease = {
  repo: import.meta.env.VITE_GATE_REPO || "evandn/nodescale",
  version: import.meta.env.VITE_GATE_VERSION || "latest",
  sha256: {
    amd64: import.meta.env.VITE_GATE_SHA256_AMD64 || undefined,
    arm64: import.meta.env.VITE_GATE_SHA256_ARM64 || undefined,
  },
  baseUrl: import.meta.env.VITE_GATE_BASE_URL || undefined,
};

/**
 * The relying party and origin servers must trust. The origin is where this
 * code actually runs; the RP ID must be that host or a parent domain.
 */
export function trustedRp(rpId: string): { rpId: string; origin: string } {
  const host = location.hostname;
  if (host !== rpId && !host.endsWith(`.${rpId}`)) throw new Error(`The console reports RP ID ${rpId}, which does not match this site (${host})`);
  return { rpId, origin: location.origin };
}
