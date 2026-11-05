import { useSyncExternalStore } from "react";

/** Minimal external store; avoids a state-management dependency. */
export function createStore<T>(initial: T) {
  let state = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => state,
    set(patch: Partial<T> | ((s: T) => Partial<T>)) {
      const p = typeof patch === "function" ? patch(state) : patch;
      state = { ...state, ...p };
      listeners.forEach((l) => l());
    },
    subscribe(l: () => void) {
      listeners.add(l);
      return () => listeners.delete(l);
    },
    use<S>(select: (s: T) => S): S {
      return useSyncExternalStore(this.subscribe, () => select(state));
    },
  };
}
