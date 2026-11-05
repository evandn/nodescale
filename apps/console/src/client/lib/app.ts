import { DOMAIN, b64, challenge, encodeSessionCert, nowSeconds, type Certificate, type Scope, type SignerKey, type Alg } from "@nodescale/protocol";
import { api, ApiError, type Me, type PasskeyInfo } from "./api.ts";
import { createStore } from "./store.ts";
import {
  decryptData,
  deriveKek,
  encryptData,
  generateRecoveryKey,
  importDek,
  parseRecoveryKey,
  unwrapDek,
  wrapDek,
  type VaultData,
  type VaultEnvelope,
} from "./vaultCrypto.ts";
import { createPasskey, getAssertion } from "./webauthn.ts";

/**
 * A delegated operations session: a non-extractable P-256 key living only in
 * this tab, plus a passkey-signed certificate that agents verify. Closing the
 * tab, locking, or expiry destroys it.
 */
export interface OpsSession {
  key: CryptoKey;
  certificate: Certificate;
  scope: Scope;
  exp: number;
  credentialId: string;
}

type VaultState =
  | { status: "unknown" }
  | { status: "missing" }
  | { status: "locked"; envelope: VaultEnvelope; version: number }
  | { status: "unlocked"; envelope: VaultEnvelope; version: number; data: VaultData; dek: CryptoKey; kek: CryptoKey; unlockedWith: VaultEnvelope["keys"][number] };

interface State {
  booted: boolean;
  me: Me | null;
  session: OpsSession | null;
  vault: VaultState;
  /** Shown once after vault creation; cleared when the user confirms. */
  pendingRecoveryKey: string | null;
  sessionTtl: number;
  sessionScope: Scope;
}

const prefs = (() => {
  try {
    return JSON.parse(localStorage.getItem("nodescale.prefs") ?? "{}") as { ttl?: number; scope?: Scope };
  } catch {
    return {};
  }
})();

export const app = createStore<State>({
  booted: false,
  me: null,
  session: null,
  vault: { status: "unknown" },
  pendingRecoveryKey: null,
  sessionTtl: prefs.ttl ?? 3600,
  sessionScope: prefs.scope ?? "operate",
});

export function setSessionPrefs(ttl: number, scope: Scope) {
  app.set({ sessionTtl: ttl, sessionScope: scope });
  try {
    localStorage.setItem("nodescale.prefs", JSON.stringify({ ttl, scope }));
  } catch {
    /* storage unavailable */
  }
}

export async function boot() {
  try {
    const me = await api.get<Me>("/me");
    // A valid cookie but no in-memory keys: the user must touch their passkey
    // again to unlock (keys never persist across reloads).
    app.set({ me, booted: true });
  } catch (e) {
    app.set({ me: null, booted: true });
    if (!(e instanceof ApiError && e.status === 401)) console.error(e);
  }
}

// ---------------------------------------------------------------------------
// Sign-in

/**
 * One passkey touch: signs a session certificate (authenticates to the
 * control plane and authorises the in-browser session key for agents) and
 * evaluates the PRF to unlock the vault.
 */
export async function signIn(opts: { allow?: string[] } = {}) {
  const { sessionTtl, sessionScope } = app.get();
  const start = await api.post<{ challengeId: string; nonce: string; rp: { id: string } }>("/auth/login/start");
  const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const spki = b64(await crypto.subtle.exportKey("spki", kp.publicKey));
  const certPayload = encodeSessionCert({ key: spki, scope: sessionScope, ttlSeconds: sessionTtl, nonce: start.nonce });
  const got = await getAssertion({ challenge: await challenge(DOMAIN.session, certPayload), rpId: start.rp.id, allow: opts.allow, prf: true });
  const certificate: Certificate = { payload: b64(certPayload), assertion: got.assertion };
  await api.post("/auth/login/finish", { challengeId: start.challengeId, certificate });

  const me = await api.get<Me>("/me");
  app.set({
    me,
    session: { key: kp.privateKey, certificate, scope: sessionScope, exp: nowSeconds() + sessionTtl, credentialId: got.assertion.credentialId },
  });
  await loadVault(got.assertion.credentialId, got.prfOutput);
}

/** Renews the operations session with the same passkey. */
export async function renewSession() {
  const me = app.get().me;
  await signIn({ allow: me?.user.credentialId ? [me.user.credentialId] : undefined });
}

export function sessionValid(s: OpsSession | null, slack = 15): s is OpsSession {
  return !!s && s.exp - slack > nowSeconds();
}

export async function register(name: string, label: string, invite: string | null) {
  const start = await api.post<{ challengeId: string; challenge: string; user: { id: string; name: string }; rp: { id: string; name: string } }>("/auth/register/start", {
    name,
    invite,
  });
  const cred = await createPasskey(start);
  const { prfOutput, ...credential } = cred;
  await api.post("/auth/register/finish", { challengeId: start.challengeId, credential, label });
  // Sign in straight away (second touch). This also evaluates the PRF for
  // authenticators that only support it during assertions.
  await signIn({ allow: [cred.id] });
  if (app.get().vault.status === "missing") {
    await createVault({ id: cred.id, alg: cred.alg as Alg, publicKey: cred.publicKey, label }, lastPrf ?? prfOutput);
  }
}

export async function signOut() {
  await api.post("/auth/logout").catch(() => {});
  lock();
  app.set({ me: null });
}

/** Forget every key held in memory. */
export function lock() {
  const v = app.get().vault;
  app.set({
    session: null,
    vault: v.status === "unlocked" ? { status: "locked", envelope: v.envelope, version: v.version } : v,
  });
  lastPrf = undefined;
}

// ---------------------------------------------------------------------------
// Vault

let lastPrf: Uint8Array | undefined;

async function loadVault(credentialId: string, prfOutput?: Uint8Array) {
  lastPrf = prfOutput;
  const me = app.get().me!;
  const row = await api.get<{ version: number; blob: string } | null>("/vault");
  if (!row) {
    app.set({ vault: { status: "missing" } });
    return;
  }
  const envelope = JSON.parse(row.blob) as VaultEnvelope;
  const wrapped = envelope.keys.find((k) => k.kind === "prf" && k.credentialId === credentialId);
  if (prfOutput && wrapped) {
    try {
      const kek = await deriveKek(new Uint8Array(prfOutput), "prf");
      await openVault(envelope, row.version, kek, wrapped, me.user.id);
      return;
    } catch (e) {
      console.warn("PRF unlock failed", e);
    }
  }
  app.set({ vault: { status: "locked", envelope, version: row.version } });
}

async function openVault(envelope: VaultEnvelope, version: number, kek: CryptoKey, wrapped: VaultEnvelope["keys"][number], userId: string) {
  const dekRaw = await unwrapDek(kek, wrapped, userId);
  const dek = await importDek(dekRaw);
  dekRaw.fill(0);
  const data = await decryptData(dek, envelope, userId);
  checkRollback(userId, data.rev);
  app.set({ vault: { status: "unlocked", envelope, version, data, dek, kek, unlockedWith: wrapped } });
}

function checkRollback(userId: string, rev: number) {
  try {
    const key = `nodescale.vaultrev.${userId}`;
    const seen = Number(localStorage.getItem(key) ?? "0");
    if (rev < seen) throw new Error(`Vault rollback detected (revision ${rev} < ${seen}). The server returned an older copy of your vault.`);
    localStorage.setItem(key, String(rev));
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("Vault rollback")) throw e;
  }
}

export async function unlockWithRecoveryKey(text: string) {
  const v = app.get().vault;
  const me = app.get().me!;
  if (v.status !== "locked") return;
  const wrapped = v.envelope.keys.find((k) => k.kind === "recovery");
  if (!wrapped) throw new Error("This vault has no recovery key");
  const kek = await deriveKek(parseRecoveryKey(text), "recovery");
  try {
    await openVault(v.envelope, v.version, kek, wrapped, me.user.id);
  } catch {
    throw new Error("That recovery key does not open this vault");
  }
  // Let the passkey used for this sign-in unlock the vault next time.
  const cred = app.get().session?.credentialId;
  if (cred && lastPrf) await wrapForPasskey(cred, lastPrf);
}

async function createVault(signer: Omit<SignerKey, "role">, prfOutput?: Uint8Array) {
  const me = app.get().me!;
  const dekRaw = crypto.getRandomValues(new Uint8Array(32));
  const recovery = generateRecoveryKey();
  const recoveryKek = await deriveKek(recovery.bytes, "recovery");
  recovery.bytes.fill(0);
  const keys: VaultEnvelope["keys"] = [await wrapDek(recoveryKek, dekRaw, me.user.id, { kind: "recovery" })];
  let kek = recoveryKek;
  if (prfOutput) {
    kek = await deriveKek(new Uint8Array(prfOutput), "prf");
    keys.push(await wrapDek(kek, dekRaw, me.user.id, { kind: "prf", credentialId: signer.id }));
  }
  const dek = await importDek(dekRaw);
  dekRaw.fill(0);
  const data: VaultData = { v: 1, rev: 1, pins: {}, signers: [{ ...signer, role: "admin" }] };
  const envelope: VaultEnvelope = { v: 1, keys, data: await encryptData(dek, data, me.user.id) };
  const { version } = await api.put<{ version: number }>("/vault", { version: 0, blob: JSON.stringify(envelope) });
  checkRollback(me.user.id, 1);
  app.set({
    pendingRecoveryKey: recovery.text,
    vault: { status: "unlocked", envelope, version, data, dek, kek, unlockedWith: keys[keys.length - 1]! },
  });
}

/** Creates the vault for a user who signed in before one existed. */
export async function setupVault() {
  const session = app.get().session;
  const keys = await api.get<PasskeyInfo[]>("/passkeys");
  const mine = keys.find((k) => k.id === session?.credentialId) ?? keys[0]!;
  await createVault({ id: mine.id, alg: mine.alg as Alg, publicKey: mine.publicKey, label: mine.label }, lastPrf);
}

export function requireVault(): VaultData {
  const v = app.get().vault;
  if (v.status !== "unlocked") throw new Error("Unlock your vault first");
  return v.data;
}

/** Applies `mutate` to the vault and saves it (re-encrypted client-side). */
export async function updateVault(mutate: (d: VaultData) => VaultData | void) {
  const v = app.get().vault;
  const me = app.get().me!;
  if (v.status !== "unlocked") throw new Error("Unlock your vault first");
  const next = structuredClone(v.data);
  const out = mutate(next) ?? next;
  out.rev = v.data.rev + 1;
  const envelope: VaultEnvelope = { ...v.envelope, data: await encryptData(v.dek, out, me.user.id) };
  const { version } = await api.put<{ version: number }>("/vault", { version: v.version, blob: JSON.stringify(envelope) });
  checkRollback(me.user.id, out.rev);
  app.set({ vault: { ...v, envelope, version, data: out } });
}

async function saveEnvelopeKeys(keys: VaultEnvelope["keys"]) {
  const v = app.get().vault;
  if (v.status !== "unlocked") throw new Error("Unlock your vault first");
  const envelope = { ...v.envelope, keys };
  const { version } = await api.put<{ version: number }>("/vault", { version: v.version, blob: JSON.stringify(envelope) });
  app.set({ vault: { ...v, envelope, version } });
}

/** Re-wraps the vault key for a newly added passkey. */
async function wrapForPasskey(credentialId: string, prfOutput: Uint8Array) {
  const v = app.get().vault;
  const me = app.get().me!;
  if (v.status !== "unlocked") throw new Error("Unlock your vault first");
  const dekRaw = await unwrapDek(v.kek, v.unlockedWith, me.user.id);
  const w = await wrapDek(await deriveKek(new Uint8Array(prfOutput), "prf"), dekRaw, me.user.id, { kind: "prf", credentialId });
  dekRaw.fill(0);
  await saveEnvelopeKeys([...v.envelope.keys.filter((k) => !(k.kind === "prf" && k.credentialId === credentialId)), w]);
}

export async function rotateRecoveryKey(): Promise<string> {
  const v = app.get().vault;
  const me = app.get().me!;
  if (v.status !== "unlocked") throw new Error("Unlock your vault first");
  const dekRaw = await unwrapDek(v.kek, v.unlockedWith, me.user.id);
  const recovery = generateRecoveryKey();
  const w = await wrapDek(await deriveKek(recovery.bytes, "recovery"), dekRaw, me.user.id, { kind: "recovery" });
  dekRaw.fill(0);
  recovery.bytes.fill(0);
  await saveEnvelopeKeys([...v.envelope.keys.filter((k) => k.kind !== "recovery"), w]);
  return recovery.text;
}

/** Adds a passkey to the account, the vault, and my trusted signer list. */
export async function addPasskey(label: string) {
  const me = app.get().me!;
  const start = await api.post<{ challengeId: string; challenge: string; user: { id: string; name: string }; rp: { id: string; name: string }; exclude: string[] }>("/passkeys/start");
  const cred = await createPasskey(start);
  const { prfOutput, ...credential } = cred;
  await api.post("/passkeys/finish", { challengeId: start.challengeId, credential, label });
  let prf = prfOutput;
  if (!prf && cred.prf) {
    const got = await getAssertion({ challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: me.rp.id, allow: [cred.id], prf: true });
    prf = got.prfOutput;
  }
  if (app.get().vault.status === "unlocked") {
    if (prf) await wrapForPasskey(cred.id, prf);
    await updateVault((d) => {
      d.signers = [...d.signers.filter((s) => s.id !== cred.id), { id: cred.id, alg: cred.alg as Alg, publicKey: cred.publicKey, role: "admin", label }];
    });
  }
  return { ...cred, prfWrapped: !!prf };
}

export async function removePasskeyFromVault(credentialId: string) {
  const v = app.get().vault;
  if (v.status !== "unlocked") return;
  await saveEnvelopeKeys(v.envelope.keys.filter((k) => !(k.kind === "prf" && k.credentialId === credentialId)));
  await updateVault((d) => {
    d.signers = d.signers.filter((s) => s.id !== credentialId);
  });
}
