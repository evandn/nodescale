# Signed request protocol (v1)

There are two implementations:

- **Browser and Worker** (TypeScript): `packages/protocol`.
- **Server gate** (Go): `gate/internal/protocol` and `gate/internal/gate`.

Cross-language test vectors live in `gate/internal/gate/testdata/ts-vectors.json`
and `packages/protocol/test/go-vectors.json`. Both test suites check that the
operation tables are identical.

## Transport

Tailscale SSH runs the user's login shell, `nodescale-gate -c …`. The gate
ignores the command, reads **one JSON request** from stdin, writes **one JSON
response** line to stdout, and exits. Nothing in the transport is trusted.

## Encoding

- `b64` is base64url without padding.
- Signatures are computed over `message(domain, payload) = utf8(domain) ‖ 0x00 ‖ payload`.
- Payloads are sent as `b64(bytes)`, and the signature covers those exact
  bytes. Receivers verify first, then parse, so JSON canonicalisation is never
  needed.

| Domain | Used for |
| --- | --- |
| `nodescale/v1/request` | WebAuthn challenge for a directly signed request |
| `nodescale/v1/session` | WebAuthn challenge for a session certificate |
| `nodescale/v1/session-request` | Session-key signature over a request |
| `nodescale/v1/response` | Gate signature over a response |

A WebAuthn challenge is `SHA-256(message(domain, payload))`.

## Request

```jsonc
// payload (signed bytes)
{ "v": 1, "typ": "nodescale.request",
  "aud": "ag_<32 hex>",          // server identity; "*" only for agent.hello
  "op": "stacks.deploy", "args": { … },
  "iat": 1800000000, "exp": 1800000060,   // exp - iat <= policy.maxRequestSeconds (300)
  "nonce": "<16-64 chars>" }

// wire, direct passkey
{ "payload": "<b64>", "auth": { "kind": "webauthn", "assertion": {
    "credentialId": "<b64>", "authenticatorData": "<b64>", "clientDataJSON": "<b64>", "signature": "<b64>" } } }

// wire, delegated session key
{ "payload": "<b64>", "auth": { "kind": "session",
    "certificate": { "payload": "<b64 cert>", "assertion": { … } },
    "signature": "<b64 raw r||s ECDSA P-256 SHA-256 over message(session-request, payload)>" } }
```

## Session certificate

```jsonc
{ "v": 1, "typ": "nodescale.session",
  "key": "<b64 SPKI P-256>", "aud": ["*"], "scope": "operate",   // "read" | "operate"
  "iat": 1800000000, "exp": 1800003600,                          // <= policy.maxSessionSeconds
  "nonce": "<console login challenge>" }
```

The certificate is signed by an enrolled passkey with user verification. The
console reuses the same assertion as its sign-in proof: it checks that `nonce`
is the challenge it issued.

## Verification (gate)

1. The payload must decode to a known `op`, with `v` = 1 and `typ`
   `nodescale.request`. Unknown JSON fields are rejected.
2. `aud` must equal this server's identity (or `*` for public operations).
3. Time window: `0 < exp-iat ≤ maxRequestSeconds`, `iat ≤ now+skew`, and
   `exp ≥ now-skew`.
4. Authentication:
   - `webauthn`: the credential is trusted, and
     `clientData.type == "webauthn.get"`. The challenge matches, the origin is
     in `origins`, the request isn't cross-origin, and
     `rpIdHash == SHA-256(rpId)`. UP must be set, and UV must be set if
     `level ≥ operate`. The signature over
     `authenticatorData ‖ SHA-256(clientDataJSON)` must verify.
   - `session`: the operation's level must be below admin. The certificate
     must be well formed, its `aud` must contain this server or `*`, and its
     scope must be allowed by policy and at least the operation's level. Its
     lifetime must be within policy, it must not be expired, and the request
     must expire no later than the certificate. The certificate's assertion
     must verify as above with UV required, and the request signature must
     verify with the certificate key.
5. The signer's role must be at least the operation's level
   (`viewer` = read, `operator` = operate, `admin` = admin).
6. The nonce file `nonces/hex(SHA-256(signer ‖ 0 ‖ nonce)[:16])` must be newly
   created (`O_EXCL`).

## Response

```jsonc
// payload
{ "v": 1, "typ": "nodescale.response", "agent": "ag_…",
  "req": "<b64 SHA-256(request payload bytes)>", "ok": true,
  "result": …, "error": { "code": "forbidden", "message": "…" }, "ts": 1800000001 }

// wire
{ "payload": "<b64>", "signature": "<b64 Ed25519 over message(response, payload)>",
  "publicKey": "<b64 raw Ed25519 key>" }
```

The client checks:

- `"ag_" + hex(SHA-256(publicKey)[0:16])` equals the pinned identity;
- the signature verifies;
- `req` matches the request it sent.

## Sealed values

The gate's seal key is X25519, with the private key derived as
`HKDF-SHA256(identity seed, salt = "", info = "nodescale/v1/x25519")`. It's
returned as `sealKey` by `agent.hello` and `agent.info`.

```
nsseal1.<b64 ephemeral X25519 public>.<b64 12-byte IV>.<b64 AES-256-GCM ciphertext>
key = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub ‖ recipient_pub,
                  info = "nodescale/v1/seal" ‖ 0x00 ‖ serverIdentity)
AAD = label
```

- In `containers.create`, `containers.exec` and `stacks.deploy`, any
  `env` entry `KEY=nsseal1.…` is decrypted with label `KEY`.
- `containers.env` requires `replyKey` (a browser X25519 public key) and
  returns `{ sealed }`, encrypted with label `containers.env`.

## Operations

| Level | Operations |
| --- | --- |
| public | `agent.hello` |
| read | `agent.info`, `audit.read`, `host.info`, `system.info`, `system.df`, `containers.list`, `containers.inspect` (env redacted), `containers.logs`, `containers.stats`, `containers.top`, `images.list`, `networks.list`, `volumes.list`, `signers.list` |
| operate | `containers.start`, `containers.stop`, `containers.restart`, `containers.kill`, `containers.pause`, `containers.unpause` |
| admin | `containers.create`, `containers.remove`, `containers.rename`, `containers.update`, `containers.exec`, `containers.env`, `images.pull`, `images.remove`, `images.prune`, `networks.create`, `networks.remove`, `volumes.create`, `volumes.remove`, `stacks.deploy`, `stacks.remove`, `signers.add`, `signers.remove` |

### Stacks

`stacks.deploy` takes:

```jsonc
{ "name": "shop", "volumes": ["shop_data"], "networks": ["nodescale"], "pull": "missing",
  "services": [ { "service": "web", "image": "…", "env": ["K=nsseal1…"], "networks": ["nodescale"],
                  "mounts": [{ "type": "volume", "source": "shop_data", "target": "/data" }], … } ] }
```

- Containers are named `<stack>-<service>`.
- Every service joins `<stack>_default` with its service name as an alias,
  plus any networks it lists.
- Labels: `io.nodescale.stack`, `io.nodescale.service`, `io.nodescale.hash`.
- A service is recreated only when its keyed hash (spec plus image ID)
  changes. Services removed from the spec are removed.
- `stacks.remove` removes the containers and the stack network, and with
  `volumes: true` also the stack's labelled volumes.
