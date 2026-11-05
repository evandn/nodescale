import { writeFileSync } from "node:fs";
import { installScript } from "../../apps/console/src/client/lib/install.ts";
import { b64 } from "../../packages/protocol/src/encoding.ts";
const dir = process.argv[2]!;
const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const id = b64(crypto.getRandomValues(new Uint8Array(16)));
const spki = b64(await crypto.subtle.exportKey("spki", kp.publicKey));
writeFileSync(`${dir}/passkey.json`, JSON.stringify({ id, jwk: await crypto.subtle.exportKey("jwk", kp.privateKey) }));
writeFileSync(`${dir}/install.sh`, installScript({
  serverName: "it-server", rpId: "nodescale.example.com", origin: "https://nodescale.example.com",
  signers: [{ id, alg: -7, publicKey: spki, role: "admin", label: "it-admin" }],
  release: { repo: "evandn/nodescale", version: "v0.0.0-test", sha256: {}, baseUrl: "http://127.0.0.1:8099" },
}));
