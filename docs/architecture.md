# Architecture and security model

nodescale manages Docker on Debian/Ubuntu servers that have **no inbound
ports**, sit on a **Tailscale tailnet with Tailscale SSH**, and publish services
through **Cloudflare Tunnels**. The console runs entirely on Cloudflare
(Workers, static assets, D1, Durable Objects and Containers).

The design goal is: **if the hosted console is compromised, the attacker can't
read your API keys and can't touch your containers.** The rest of this
document explains how, and where the limits are.

## The core idea: the console is untrusted

Most dashboards hold credentials and act on your behalf. nodescale's console
holds nothing that can act on its own:

| Asset | Where it lives | What the console sees |
| --- | --- | --- |
| Authority over a server | Passkey public keys in `/etc/nodescale/agent.json` **on that server** | Nothing it can use |
| Tailscale / Cloudflare tokens | Encrypted vault, decrypted only in your browser | Ciphertext |
| Vault key | Derived from your passkey (WebAuthn PRF) or offline recovery key | Nothing |
| Server identity | Ed25519 key on the server, pinned in your vault | The public key |

```
 Browser (trusted code, your passkey)
   │  1. passkey signs request ───────────────────────────────┐
   ▼                                                          │
 Cloudflare Worker  ──►  Relay container  ──►  Tailscale SSH ──►  nodescale-gate ──►  agent
 (D1: metadata,          (ephemeral tailnet     (user "nodescale",   (login shell,       (verifies signature,
  ciphertext vault)       node, tag-limited)     no shell/sudo)       pipes one request)  runs Docker op,
                                                                                         signs response)
   ▲                                                                                         │
   └──────────────────────── 2. browser verifies agent's signed response ◄──────────────────┘
```

Everything between the browser and the agent is a **dumb pipe**. It can
drop or delay messages, but it can't forge or change them.

## Components

### Agent (`agent/`, Go, standard library only)

Runs on each server as a container with **no network** (`--network none`),
a read-only root filesystem and all capabilities dropped except `CHOWN`. It
mounts the Docker socket and listens on a unix socket
`/run/nodescale/agent.sock` (mode `0660`, group `nodescale`).

For every request it:

1. Decodes the payload: the exact bytes the passkey signed.
2. Checks the operation is in its fixed allow-list (`containers.list`,
   `containers.restart`, …). There is no generic "exec" or "shell" operation.
3. Checks the audience (`aud`) is its own agent ID, the time window, and that
   the request isn't older than the agent process.
4. Verifies the signature:
   - **Direct passkey** (`webauthn`): a WebAuthn assertion whose challenge is
     `SHA-256("nodescale/v1/request" ‖ 0x00 ‖ payload)`, bound to the
     configured RP ID and origin, with user-presence set. User verification
     (PIN/biometric) is required for anything that changes state.
   - **Session key** (`session`): a passkey-signed certificate (user
     verification required) that delegates `read` or `read+operate` to an
     ephemeral, non-extractable P-256 key held only in the browser tab, plus
     that key's signature over the request. Lifetime is capped by the agent's
     policy (8h by default). **Admin operations can never use a session key.**
5. Checks the signer's role on this server (`viewer`, `operator`, `admin`).
6. Records the nonce so the request can't be replayed.
7. Runs the operation and returns a response signed with its Ed25519
   identity key. The response is bound to the SHA-256 of the request.
8. Appends to a local audit log, `/var/lib/nodescale/audit.jsonl`.

The trusted-passkey list can only change through `signers.add` or
`signers.remove`, which are admin operations needing a fresh passkey
signature, or through root access to the server. The agent refuses to stop or
remove its own container, and refuses to bind-mount the Docker socket or its
own state into containers it creates.

### Gate (`nodescale-gate`)

This is the agent binary, installed on the host as the **login shell** of a
system user `nodescale`. That user has no password, no home directory, and
isn't in the `docker` or `sudo` groups. When Tailscale SSH runs a command
as this user, the gate ignores the command line, reads one request from
stdin, passes it to the agent socket, and prints the response. Even
arbitrary code running as `nodescale` can only submit requests the agent
will verify.

### Relay (`relay/`, Go, Cloudflare Container)

Cloudflare Workers can't join a tailnet, so a small container does. It
embeds Tailscale (`tsnet`) and an SSH client. It joins as an **ephemeral**
node tagged `tag:nodescale-relay`, using a **single-use, five-minute auth key
minted in your browser** with your vault credentials. The platform never
stores a tailnet credential. The tailnet policy only lets it reach
`tcp:22` on `tag:nodescale-server` and SSH only as `nodescale`. It talks only
to the Worker, using a shared secret.

### Console (`apps/console/`, Cloudflare Worker + React SPA)

- **Sign-in** uses passkeys only (resident keys, user verification required).
  One passkey touch does three things:
  1. signs a session certificate whose nonce is the server's login
     challenge, which authenticates you to the console;
  2. authorises the browser's session key for agents (the same certificate);
  3. evaluates the WebAuthn **PRF** extension, from which the browser
     derives the vault key.
- **Vault**: a random AES-256 data key encrypts your provider tokens, server
  identity pins and your own passkey public keys. That key is wrapped once
  per passkey (key derived with HKDF from the PRF output) and once by a
  **recovery key** that's shown once and never sent to the server. D1 stores
  only the envelope. A monotonically increasing revision in the ciphertext
  lets the browser detect rollback to an older copy.
- **Provider APIs**: Cloudflare and Tailscale don't allow browser CORS
  calls, so requests go through `/api/egress/{cloudflare,tailscale}/*`. This
  is a stateless pass-through to two fixed hosts that forwards the token
  supplied by the browser for that request, without logging or storing it.
- **D1** stores users, passkey public keys, sessions, workspaces, server
  metadata, invites, a console-side audit log and the vault ciphertext.
- **Security headers**: strict CSP (`script-src 'self'`, no inline script,
  no third-party origins), HSTS, `frame-ancestors 'none'`, COOP/CORP. Cookies
  are `__Host-`, `HttpOnly`, `Secure`, `SameSite=Strict`. Mutating API calls
  also need a same-origin `Origin` and a custom header.

## Threat model

### What a console compromise can't do

Suppose an attacker fully controls the Worker, D1, the relay and the
Cloudflare account, but **not the static frontend your browser executes**
(see the next section).

| Attack | Why it fails |
| --- | --- |
| Read Tailscale/Cloudflare tokens from the database | Only AES-GCM ciphertext; the key comes from your authenticator or offline recovery key. |
| Run or stop containers | Agents need a passkey signature from a key in their local trust list. |
| Add their own key to a server | `signers.add` is an admin operation and needs a fresh passkey signature. |
| Replay a captured request | Nonce cache, short expiry, audience binding, and rejection of requests issued before agent start. |
| Change a request in transit (e.g. `restart` → `remove`) | The signature covers the exact payload bytes. |
| Use a stolen session certificate | It's useless without the non-extractable private key in your tab. |
| Fake server state (pretend a container is running) | Responses are signed by the agent's key, pinned in your encrypted vault, and bound to the request hash. |
| Swap a server's address to an attacker-controlled node | The fake node can't produce responses under the pinned agent identity. |
| Use the relay's tailnet access | It can only SSH as `nodescale`, whose shell only forwards signed requests. |
| Inject a key into a new server's bootstrap script | Your own signer keys come from the encrypted vault, not the database. You must confirm teammates' keys by fingerprint. |
| Phish passkeys on another domain | WebAuthn binds assertions to the RP ID; agents also check the origin. |

### The irreducible limit: the code your browser runs

A web app's security ultimately depends on the JavaScript it serves. An
attacker who can **change the frontend served to you** (a malicious
deployment, or a compromised CI or Cloudflare account) can, **while you're
using it**:

- read provider tokens once you unlock your vault;
- use your session key, within its scope and lifetime;
- ask you for a passkey touch for an action other than the one shown.
  Browsers can't display custom text inside the passkey prompt.

nodescale limits this blast radius:

- **No standing access.** Nothing works while nobody is signed in. A
  compromise only matters during live sessions and only for that user's
  servers and role.
- **Scoped, short sessions.** Session keys default to 1 hour and `operate`
  scope (start/stop/restart). Set the scope to *read only* in Settings to
  require a touch for every change. Agents cap lifetime with
  `maxSessionSeconds` and can restrict scopes with `allowSessionScopes`.
- **Admin actions always need a fresh touch.** That covers create, remove,
  image pull and trusted-key changes.
- **Least-privilege provider tokens.** The Tailscale credential should be an
  OAuth client with only `auth_keys` and `devices:core`, limited to the
  nodescale tags. **Never grant `policy_file`**: a token that can edit the
  tailnet policy could grant itself SSH. The Cloudflare token should be
  limited to Tunnel and DNS edits on specific zones, ideally with client-IP
  filtering.
- **Server-side audit.** Every verified request is logged on the server
  itself, out of the console's reach.

Hardening options for high-assurance deployments:

1. Deploy the frontend from a protected branch with required reviews, and
   restrict who can deploy the Worker (separate Cloudflare account roles).
2. Put the console behind Cloudflare Access so only your identity provider's
   users can even load it.
3. Use **hardware security keys** for admin passkeys, and keep a second key
   offline.
4. Set `"allowSessionScopes": ["read"]` in each agent's policy.
5. Verify what you're signing outside the browser: the protocol is
   documented ([protocol.md](protocol.md)), so a CLI or browser extension can
   sign requests independently of the served frontend.

### Other residual risks

- **Trust on first use.** You pin a server's identity by comparing the agent
  ID printed by the install script with the one the console shows. Skipping
  that comparison weakens the "fake server" protection.
- **Tailscale SSH port forwarding.** An attacker who controls the relay
  could try to forward ports through the `nodescale` SSH user to services
  that listen only on the server's `localhost`. Don't publish container
  ports on the host. Use the `nodescale` Docker network and Cloudflare
  Tunnel routes, and keep the Docker API off TCP. Treat any
  unauthenticated localhost service as reachable by tailnet peers allowed to
  SSH.
- **Root on the server** can change `/etc/nodescale/agent.json`. nodescale
  protects the management path, not a compromised host.
- **Container specs are visible to the console.** Environment variables in
  a `containers.create` request are signed but not encrypted. Use Docker
  secrets or files for sensitive values.
- **Availability.** The console can refuse to relay requests. You can still
  reach servers directly over Tailscale SSH with your own identity.

## Alternatives considered

- **Agent dials out to a Durable Object over WebSocket** instead of Tailscale
  SSH. This is simpler and needs no container, and the security properties
  are identical because the signed protocol doesn't depend on the transport.
  We use Tailscale SSH because it matches the existing setup and adds a
  second, independent access control layer (tailnet policy). The protocol
  allows adding this transport later.
- **Encrypt tokens with a server-side KMS key.** This protects against a
  database leak but not against a compromised Worker, which could decrypt
  them. Client-side encryption covers both.
- **Per-action passkey prompts only.** This is the most secure option but
  tiring for routine reads. Session keys give a configurable middle ground,
  and admin actions always prompt.
