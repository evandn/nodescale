// Generates requests signed by the TypeScript implementation that the Go agent
// must accept (gate/internal/gate/testdata/ts-vectors.json). Run with:
//   pnpm --filter @nodescale/protocol vectors
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { b64, concat, sha256, utf8, unb64 } from "../src/encoding.ts";
import { challenge, encodeRequest, encodeSessionCert, agentIdFromKey, signWithSession } from "../src/crypto.ts";
import { DOMAIN, type Assertion, type SignedRequest } from "../src/types.ts";

const RP_ID = "nodescale.example.com";
const ORIGIN = "https://nodescale.example.com";
const NOW = 1_800_000_000;

function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.subarray(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

async function assertion(key: CryptoKey, credId: Uint8Array, chal: Uint8Array): Promise<Assertion> {
  const cdj = utf8(JSON.stringify({ type: "webauthn.get", challenge: b64(chal), origin: ORIGIN, crossOrigin: false }));
  const authData = concat(await sha256(utf8(RP_ID)), new Uint8Array([0x05, 0, 0, 0, 7]));
  const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(authData, await sha256(cdj))));
  return { credentialId: b64(credId), authenticatorData: b64(authData), clientDataJSON: b64(cdj), signature: b64(rawToDer(raw)) };
}

const passkey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const credId = crypto.getRandomValues(new Uint8Array(20));
const spki = b64(await crypto.subtle.exportKey("spki", passkey.publicKey));

const seed = crypto.getRandomValues(new Uint8Array(32));
const pkcs8 = concat(unb64("MC4CAQAwBQYDK2VwBCIEIA"), seed);
const agentPriv = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
const jwk = await crypto.subtle.exportKey("jwk", agentPriv);
const agentId = await agentIdFromKey(unb64(jwk.x!));

const requests: { name: string; request: SignedRequest }[] = [];

const direct = encodeRequest(agentId, "signers.list", undefined, 60, NOW);
requests.push({
  name: "webauthn",
  request: { payload: b64(direct), auth: { kind: "webauthn", assertion: await assertion(passkey.privateKey, credId, await challenge(DOMAIN.request, direct)) } },
});

const sessionKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
const certPayload = encodeSessionCert({
  key: b64(await crypto.subtle.exportKey("spki", sessionKey.publicKey)),
  scope: "operate",
  ttlSeconds: 3600,
  now: NOW - 5,
});
const certificate = { payload: b64(certPayload), assertion: await assertion(passkey.privateKey, credId, await challenge(DOMAIN.session, certPayload)) };
requests.push({ name: "session", request: await signWithSession(sessionKey.privateKey, certificate, encodeRequest(agentId, "agent.info", {}, 60, NOW)) });

const out = {
  rpId: RP_ID,
  origin: ORIGIN,
  now: NOW,
  agentSeed: b64(seed),
  agentId,
  signer: { id: b64(credId), alg: -7, publicKey: spki, role: "admin", label: "ts-vector" },
  requests,
};
const dest = fileURLToPath(new URL("../../../gate/internal/gate/testdata/ts-vectors.json", import.meta.url));
writeFileSync(dest, JSON.stringify(out, null, 2) + "\n");
console.log("wrote", dest);
