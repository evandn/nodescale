# Signed request protocol (v1)

Implementations: `packages/protocol` (TypeScript, browser and Worker) and
`agent/internal/protocol` + `agent/internal/agent` (Go). Cross-language test
vectors live in `agent/internal/agent/testdata/ts-vectors.json` and
`packages/protocol/test/go-vectors.json`.

## Encoding

- `b64` is base64url without padding.
- Every signature is computed over `message(domain, payload) = utf8(domain) ‖ 0x00 ‖ payload`.
- Payloads are transmitted as `b64(bytes)`, and the signature covers those
  exact bytes. Receivers verify first, then parse. JSON canonicalisation is
  never needed.

| Domain | Used for |
| --- | --- |
| `nodescale/v1/request` | WebAuthn challenge for a directly signed request |
| `nodescale/v1/session` | WebAuthn challenge for a session certificate |
| `nodescale/v1/session-request` | Session-key signature over a request |
| `nodescale/v1/response` | Agent signature over a response |

A WebAuthn challenge is `SHA-256(message(domain, payload))`.

## Request

```jsonc
// payload (signed bytes)
{
  "v": 1,
  "typ": "nodescale.request",
  "aud": "ag_<32 hex>",        // target agent ID; "*" only for agent.hello
  "op": "containers.restart",
  "args": { "id": "web" },
  "iat": 1800000000,           // seconds
  "exp": 1800000060,           // exp - iat <= policy.maxRequestSeconds (300)
  "nonce": "<16-64 chars>"
}
```

Wire format, one JSON line:

```jsonc
// Direct passkey signature
{ "payload": "<b64>", "auth": { "kind": "webauthn", "assertion": {
    "credentialId": "<b64>", "authenticatorData": "<b64>",
    "clientDataJSON": "<b64>", "signature": "<b64 DER/raw per alg>" } } }

// Delegated session key
{ "payload": "<b64>", "auth": { "kind": "session",
    "certificate": { "payload": "<b64 cert>", "assertion": { … } },
    "signature": "<b64 raw r||s, ECDSA P-256 SHA-256 over message(session-request, payload)>" } }
```

## Session certificate

```jsonc
{
  "v": 1,
  "typ": "nodescale.session",
  "key": "<b64 SPKI of P-256 public key>",
  "aud": ["*"],               // or specific agent IDs
  "scope": "operate",         // "read" | "operate"
  "iat": 1800000000,
  "exp": 1800003600,          // exp - iat <= agent policy.maxSessionSeconds
  "nonce": "<console login challenge>"
}
```

The certificate must be signed by an enrolled passkey with user verification.
The console reuses the same assertion as its sign-in proof: it checks that
`nonce` equals the challenge it issued.

## Verification (agent)

1. `payload` decodes to a known `op`, with `v` = 1 and `typ` =
   `nodescale.request`. Unknown JSON fields are rejected.
2. `aud` equals this agent's ID (or `*` for public ops).
3. The time window is valid: `0 < exp-iat ≤ maxRequestSeconds`,
   `iat ≤ now+skew`, `exp ≥ now-skew`, and `iat ≥ agent start time`.
4. Auth:
   - `webauthn`: credential enrolled; `clientData.type == "webauthn.get"`;
     challenge matches; origin ∈ `origins`; not cross-origin;
     `rpIdHash == SHA-256(rpId)`; UP set; UV set if `level ≥ operate`; and
     the signature is valid over `authenticatorData ‖ SHA-256(clientDataJSON)`.
   - `session`: level < admin; certificate fields valid; `aud` contains this
     agent or `*`; scope allowed by policy and ≥ level; lifetime ≤ policy;
     not expired; request expiry ≤ certificate expiry; the certificate
     assertion verifies as above with UV required; and the request signature
     verifies with the certificate key.
5. The signer's role is ≥ the operation's level
   (`viewer`=read, `operator`=operate, `admin`=admin).
6. The nonce hasn't been seen (it's cached until `exp + skew`).

## Response

```jsonc
// payload
{ "v": 1, "typ": "nodescale.response", "agent": "ag_…",
  "req": "<b64 SHA-256(request payload bytes)>",
  "ok": true, "result": …, "error": { "code": "forbidden", "message": "…" },
  "ts": 1800000001 }

// wire
{ "payload": "<b64>", "signature": "<b64 Ed25519 over message(response, payload)>",
  "publicKey": "<b64 raw Ed25519 key>" }
```

The client checks that `"ag_" + hex(SHA-256(publicKey)[0:16])` equals the
pinned agent ID, that the signature is valid, and that `req` matches the
request it sent.

## Operations

| Level | Operations |
| --- | --- |
| public | `agent.hello` |
| read | `agent.info`, `system.info`, `containers.list`, `containers.inspect`, `containers.logs`, `containers.stats`, `images.list`, `networks.list`, `signers.list` |
| operate | `containers.start`, `containers.stop`, `containers.restart` |
| admin | `containers.create`, `containers.remove`, `images.pull`, `images.remove`, `signers.add`, `signers.remove` |

## Transport

The agent listens on a unix socket: one request line in, one response line
out. In production the path is: Worker → relay container → Tailscale SSH as
user `nodescale` → `nodescale-gate` (login shell) → socket. Nothing in the
transport is trusted.
