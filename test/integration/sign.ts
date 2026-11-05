// usage: sign.ts <passkey.json> <aud> <op> [argsJSON] [--no-uv]
import { readFileSync } from "node:fs";
import { b64, concat, sha256, utf8 } from "../../packages/protocol/src/encoding.ts";
import { challenge, encodeRequest } from "../../packages/protocol/src/crypto.ts";
import { DOMAIN } from "../../packages/protocol/src/types.ts";
const [pkPath, aud, op, args] = process.argv.slice(2);
const pk = JSON.parse(readFileSync(pkPath, "utf8"));
const key = await crypto.subtle.importKey("jwk", pk.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const payload = encodeRequest(aud, op as never, args ? JSON.parse(args) : undefined, 60);
const chal = await challenge(DOMAIN.request, payload);
const cdj = utf8(JSON.stringify({ type: "webauthn.get", challenge: b64(chal), origin: "https://nodescale.example.com" }));
const authData = concat(await sha256(utf8("nodescale.example.com")), new Uint8Array([process.argv.includes("--no-uv") ? 1 : 5, 0, 0, 0, 1]));
const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, concat(authData, await sha256(cdj))));
const int = (b: Uint8Array) => { let i = 0; while (i < 31 && b[i] === 0) i++; let v = b.subarray(i); if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v); return concat(new Uint8Array([2, v.length]), v); };
const body = concat(int(raw.subarray(0, 32)), int(raw.subarray(32)));
const der = concat(new Uint8Array([0x30, body.length]), body);
console.log(JSON.stringify({ payload: b64(payload), auth: { kind: "webauthn", assertion: { credentialId: pk.id, authenticatorData: b64(authData), clientDataJSON: b64(cdj), signature: b64(der) } } }));
