/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_GATE_REPO?: string;
  readonly VITE_GATE_VERSION?: string;
  readonly VITE_GATE_SHA256_AMD64?: string;
  readonly VITE_GATE_SHA256_ARM64?: string;
  readonly VITE_GATE_BASE_URL?: string;
}
