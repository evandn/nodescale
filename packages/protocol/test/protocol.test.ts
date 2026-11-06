import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ALG,
  DOMAIN,
  OPS,
  b64,
  challenge,
  concat,
  derToRaw,
  openSealed,
  replyKeyPair,
  sealEnv,
  sessionCanSign,
  sha256,
  unb64,
  utf8,
  verifyAssertion,
  verifyResponse,
  type SignedResponse,
} from "../src/index.ts";

const goVectors = JSON.parse(readFileSync(new URL("./go-vectors.json", import.meta.url), "utf8")) as {
  agentId: string;
  vectors: { name: string; requestPayload: string; response: SignedResponse }[];
  reply: { privateKey: string; publicKey: string; sealed: string; plaintext: string };
};

describe("sealed values", () => {
  it("opens a reply sealed by the Go gate", async () => {
    const r = goVectors.reply;
    const priv = await crypto.subtle.importKey("pkcs8", concat(unb64("MC4CAQAwBQYDK2VuBCIEIA"), unb64(r.privateKey)), { name: "X25519" }, false, ["deriveBits"]);
    expect(await openSealed(priv, r.publicKey, goVectors.agentId, r.sealed, "containers.env")).toBe(r.plaintext);
    await expect(openSealed(priv, r.publicKey, goVectors.agentId, r.sealed, "other-label")).rejects.toThrow();
  });

  it("seals every env value and rejects bad names", async () => {
    const server = await replyKeyPair();
    const [empty, secret, prefixed] = await sealEnv(server.publicKey, "ag_x", ["B=", "C=v=1", "D=nsseal1.hunter2"]);
    for (const e of [empty, secret, prefixed]) expect(e).toMatch(/^[A-D]=nsseal1\./);
    expect(await openSealed(server.privateKey, server.publicKey, "ag_x", secret!.slice(2), "C")).toBe("v=1");
    // A value that merely looks sealed is sealed again, never passed through.
    expect(await openSealed(server.privateKey, server.publicKey, "ag_x", prefixed!.slice(2), "D")).toBe("nsseal1.hunter2");
    await expect(sealEnv(server.publicKey, "ag_x", ["=secret"])).rejects.toThrow(/invalid/);
    await expect(sealEnv(server.publicKey, "ag_x", ["NOVALUE"])).rejects.toThrow(/invalid/);
    await expect(sealEnv(server.publicKey, "ag_x", ["BAD KEY=x"])).rejects.toThrow(/invalid/);
  });
});

describe("agent responses (signed by the Go agent)", () => {
  it("verify and bind to the request", async () => {
    for (const v of goVectors.vectors) {
      const r = await verifyResponse(v.response, { agentId: goVectors.agentId, requestPayload: unb64(v.requestPayload) });
      expect(r.ok, v.name).toBe(true);
    }
  });

  it("reject a different pinned agent", async () => {
    const v = goVectors.vectors[0]!;
    await expect(verifyResponse(v.response, { agentId: "ag_00000000000000000000000000000000", requestPayload: unb64(v.requestPayload) })).rejects.toThrow(/identity changed/);
  });

  it("reject a response replayed for another request", async () => {
    const [a, b] = goVectors.vectors;
    await expect(verifyResponse(a!.response, { agentId: goVectors.agentId, requestPayload: unb64(b!.requestPayload) })).rejects.toThrow(/does not match/);
  });

  it("reject tampering", async () => {
    const v = goVectors.vectors[0]!;
    const forged = JSON.parse(new TextDecoder().decode(unb64(v.response.payload)));
    forged.result = [];
    const resp = { ...v.response, payload: b64(utf8(JSON.stringify(forged))) };
    await expect(verifyResponse(resp, { agentId: goVectors.agentId, requestPayload: unb64(v.requestPayload) })).rejects.toThrow(/signature/);
  });
});

describe("WebAuthn assertions", () => {
  const rp = { id: "nodescale.example.com", origins: ["https://nodescale.example.com"] };

  async function makeAssertion(chal: Uint8Array, flags = 0x05, origin = rp.origins[0]!) {
    const key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const cdj = utf8(JSON.stringify({ type: "webauthn.get", challenge: b64(chal), origin }));
    const authData = concat(await sha256(utf8(rp.id)), new Uint8Array([flags, 0, 0, 0, 1]));
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, key.privateKey, concat(authData, await sha256(cdj)));
    return {
      publicKey: b64(await crypto.subtle.exportKey("spki", key.publicKey)),
      assertion: { credentialId: "AAAA", authenticatorData: b64(authData), clientDataJSON: b64(cdj), signature: b64(sig) },
    };
  }

  it("accepts a valid assertion", async () => {
    const chal = await challenge(DOMAIN.session, utf8("{}"));
    const { publicKey, assertion } = await makeAssertion(chal);
    const r = await verifyAssertion({ rp, alg: ALG.EdDSA, publicKey, assertion, challenge: chal, requireUserVerification: true });
    expect(r.signCount).toBe(1);
  });

  it("rejects missing user verification, wrong origin and wrong challenge", async () => {
    const chal = await challenge(DOMAIN.session, utf8("{}"));
    const noUV = await makeAssertion(chal, 0x01);
    await expect(verifyAssertion({ rp, alg: ALG.EdDSA, ...noUV, challenge: chal, requireUserVerification: true })).rejects.toThrow(/verification/);
    const evil = await makeAssertion(chal, 0x05, "https://evil.example");
    await expect(verifyAssertion({ rp, alg: ALG.EdDSA, ...evil, challenge: chal, requireUserVerification: true })).rejects.toThrow(/origin/);
    const ok = await makeAssertion(chal);
    const other = await challenge(DOMAIN.request, utf8("{}"));
    await expect(verifyAssertion({ rp, alg: ALG.EdDSA, ...ok, challenge: other, requireUserVerification: true })).rejects.toThrow(/challenge/);
  });

  it("converts DER ECDSA signatures", () => {
    const r = new Uint8Array(32).fill(1);
    const s = new Uint8Array(32).fill(0x80);
    const der = concat(new Uint8Array([0x30, 0x45, 0x02, 0x20]), r, new Uint8Array([0x02, 0x21, 0x00]), s);
    expect(derToRaw(der)).toEqual(concat(r, s));
  });
});

describe("operation catalogue", () => {
  it("matches the Go gate", () => {
    const src = readFileSync(new URL("../../../gate/internal/gate/auth.go", import.meta.url), "utf8");
    const block = src.slice(src.indexOf("var Ops = map[string]Level{"));
    const goOps = Object.fromEntries(
      [...block.slice(0, block.indexOf("\n}")).matchAll(/"([a-z.]+)":\s+Level(\w+)/g)].map((m) => [m[1], m[2]!.toLowerCase()]),
    );
    const tsOps = Object.fromEntries(Object.entries(OPS).map(([k, v]) => [k, v.level]));
    expect(tsOps).toEqual(goOps);
  });

  it("never lets a session key sign admin operations", () => {
    expect(sessionCanSign("operate", "containers.restart")).toBe(true);
    expect(sessionCanSign("read", "containers.restart")).toBe(false);
    expect(sessionCanSign("operate", "containers.remove")).toBe(false);
    expect(sessionCanSign("operate", "signers.add")).toBe(false);
  });
});
