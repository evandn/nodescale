# Architecture and security model

nodescale manages Docker on Debian/Ubuntu servers that have **no inbound
ports**, sit on a **Tailscale tailnet with Tailscale SSH**, and publish services
through **Cloudflare Tunnels**. The console runs entirely on Cloudflare:
Workers, static assets, D1, Durable Objects and Containers. **Nothing runs in
the background on your servers** for nodescale.

The design goal: **if the hosted console is compromised, the attacker can't
read your API keys or secrets, and can't touch your containers.**

## The core idea: the console is untrusted

| Asset | Where it lives | What the console sees |
| --- | --- | --- |
| Authority over a server | Passkey public keys in `/etc/nodescale/gate.json` **on that server** | Nothing it can use |
| Tailscale / Cloudflare tokens | Encrypted vault, decrypted only in your browser | Ciphertext |
| Container secrets (env values) | Your vault, then **sealed to the server's key** in the browser | Ciphertext |
| Vault key | Derived from your passkey (WebAuthn PRF) or offline recovery key | Nothing |
| Server identity | Ed25519 key on the server, pinned in your vault | The public key |

```
 Browser (your passkey; vault and seal keys in memory)
   │ 1. passkey/session key signs the request; env values sealed to the server
   ▼
 Cloudflare Worker ──► Relay container ──► Tailscale SSH ──► nodescale-gate ──► /var/run/docker.sock
 (D1: metadata,         (ephemeral, tagged   (user "nodescale",   (its login shell; setgid docker;
  ciphertext)            tailnet node)        no shell, no groups)  verifies, executes, signs, exits)
   ▲
   └── 2. browser verifies the server's signed response ◄──────────────────────────┘
```

Everything between the browser and the gate is a **dumb pipe**. It can drop
or delay messages, but it can't forge them, change them, or read the secrets
inside them.

## Why not forward the Docker socket over SSH directly?

You can reach `docker.sock` over SSH with no server-side component at all,
but then **whoever controls the SSH client controls Docker, which means root
on every server**. The SSH client here is a relay running in the cloud
console. Making that safe needs a check *on the server* that the request
really comes from your passkey, and that check needs a small program there.

nodescale's answer is the smallest possible one: **a single static binary that
is the SSH login shell** of a dedicated user. It runs only while a request is
being handled (milliseconds), keeps no listening socket, and exits. It speaks
the Docker Engine API to the local socket directly.

## Server footprint

Created by the generated install script (`apps/console/src/client/lib/install.ts`):

| Item | Ownership / mode | Purpose |
| --- | --- | --- |
| `/usr/local/bin/nodescale-gate` | `root:docker 2755` (setgid docker) | Login shell; the only thing that can reach Docker |
| user `nodescale` | no password, no home, **no supplementary groups**, shell = gate | The account Tailscale SSH maps the relay to |
| `/etc/nodescale/` | `root:docker 2770` | `gate.json`: trusted passkeys and policy |
| `/var/lib/nodescale/` | `root:docker 2770` | `identity.key`, `nonces/`, `audit.jsonl` |

The `nodescale` user can't traverse those directories or open `docker.sock`
(`root:docker 0660`). Only the setgid gate process can, and it:

- ignores its command line, so the SSH command can't choose what runs;
- ignores environment variables for every path while it runs setgid;
- is non-dumpable because it's setgid, so other processes of the same user
  can't ptrace it or read its memory.

What we checked in Tailscale's SSH server (v1.104):

- Commands run as `su -l nodescale -c <cmd>` (or by executing the login shell
  directly). So the gate always runs, and `no_new_privs` isn't set, so the
  setgid bit takes effect.
- SFTP runs as the user, without the docker group.
- Unix-socket forwarding is limited to the user's home, `/tmp` and
  `/run/user/<uid>`, and also runs with the user's own groups. So
  `docker.sock` can't be forwarded.

## Request verification (in the gate)

For every request the gate:

1. Decodes the payload (the exact signed bytes) and checks the operation is in
   its fixed allow-list: containers, images, networks, volumes, stacks,
   signers, info. There's no generic "shell" or "raw API" operation.
2. Checks the audience is this server's identity and the time window.
3. Verifies the signature:
   - **Direct passkey**: a WebAuthn assertion over
     `SHA-256("nodescale/v1/request" ‖ 0 ‖ payload)`, bound to the configured
     RP ID and origin. User verification (PIN/biometric) is required for
     anything that changes state.
   - **Session key**: a passkey-signed certificate (UV required) delegating
     `read` or `read+operate` to a non-extractable P-256 key that lives only
     in the browser tab, plus that key's signature. Lifetime is capped by
     policy (8h by default). **Admin operations never accept a session key.**
4. Checks the signer's role on this server (`viewer`, `operator`, `admin`).
5. Records the nonce by creating `nonces/<hash>` with `O_EXCL`. This gives
   replay protection without a daemon, and it survives across processes.
6. Applies the **container policy**. By default it refuses privileged
   containers, host network/pid/ipc namespaces, devices, published ports,
   capabilities beyond Docker's defaults, and bind mounts outside `/srv`,
   `/opt/apps`, `/data`, `/mnt`. Bind sources are resolved through symlinks
   first. Only root can change the policy, by editing `gate.json`.
7. Decrypts sealed environment values, calls the Docker Engine API, and
   returns a response signed by the server's Ed25519 identity and bound to
   the request hash.
8. Appends state-changing and failed authenticated requests to
   `audit.jsonl`, with environment values redacted.

## Secrets end to end

Each server derives an X25519 **seal key** from its identity. It's published
in the signed `agent.hello` response and pinned in your vault together with
the identity. The browser encrypts every container environment value to that
key (ECDH, then HKDF-SHA256, then AES-256-GCM, with the variable name as
associated data) before signing the request. The gate decrypts it.

- **Stack secrets**: compose files reference `${NAME}`. The values live only
  in your encrypted vault, and the compose text stored in D1 contains just
  the placeholders.
- **Reading env back**: `containers.inspect` redacts values. The admin
  operation `containers.env` returns them encrypted to a key generated in the
  browser for that one request.
- **Change detection for stacks**: stack hashes stored as container labels
  are keyed with a server secret, so a label can't be used to guess values.

## Console components

- **Sign-in**: passkeys only, resident keys, with user verification. One
  touch signs a session certificate that authenticates you to the console
  (its nonce is the login challenge), authorises the tab's session key for
  servers, and evaluates the WebAuthn PRF that unlocks the vault.
- **Vault**: a random AES-256 key encrypts provider tokens, server pins,
  stack secrets and your own passkey public keys. It's wrapped per passkey
  (HKDF of the PRF output) and by a recovery key that's shown once. D1 stores
  only the envelope. A revision counter in the ciphertext detects rollback.
- **Provider APIs**: Cloudflare and Tailscale don't allow browser CORS, so
  calls go through `/api/egress/{cloudflare,tailscale}/*`. It's a stateless
  pass-through to two fixed hosts that forwards the per-request token without
  storing or logging it.
- **Relay**: a Cloudflare Container per workspace, running Go with an
  embedded Tailscale (`tsnet`). It joins as an **ephemeral** node tagged
  `tag:nodescale-relay` using a single-use, five-minute auth key minted in
  your browser, so the platform stores no tailnet credential. The tailnet
  policy lets it reach only `tcp:22` on `tag:nodescale-server`, and only as
  `nodescale`.
- **Hardening**: strict CSP (no inline or third-party script), HSTS,
  `frame-ancestors 'none'`, COOP/CORP. Cookies are `__Host-`, `HttpOnly`,
  `SameSite=Strict`. Mutating calls need a same-origin `Origin` header and a
  custom header. Auth endpoints are rate-limited.

## Threat model

### What a console compromise can't do

Suppose an attacker fully controls the Worker, D1, the relay and the
Cloudflare account, but **not the frontend code your browser executes** (see
the next section).

| Attack | Why it fails |
| --- | --- |
| Read Tailscale/Cloudflare tokens or stack secrets | AES-GCM ciphertext; keys come from your authenticator or offline recovery key |
| Read secrets in transit (deploys, env reveal) | Sealed to the server's X25519 key, or to a key that exists only in the tab |
| Run, stop or deploy containers | The gate needs a passkey signature from its local trust list |
| Add its own passkey to a server | `signers.add` is admin-only and needs a fresh passkey signature |
| Replay or modify a captured request | Nonce files, short expiry, audience binding; the signature covers the exact bytes |
| Use the relay's SSH access | It lands in the gate, which only accepts signed requests; the user has no shell or groups |
| Fake server state | Responses are signed by the pinned identity and bound to the request |
| Swap a server for an attacker-controlled node | It can't produce responses under the pinned identity |
| Inject a key into a new server's bootstrap | Your own keys come from the vault; teammates' keys are confirmed by fingerprint |
| Phish passkeys on another domain | WebAuthn binds to the RP ID, and gates also check the origin |

### The irreducible limit: the code your browser runs

If an attacker can **change the frontend served to you** (a malicious
deployment, or a compromised CI or Cloudflare account), they can act **while
you use it**:

- read provider tokens and stack secrets once you unlock;
- use your session key within its scope and lifetime;
- show one action but ask your passkey to sign another. Browsers can't
  display custom text inside the passkey prompt.

Ways to limit this:

- **No standing access.** Nothing works unless someone is signed in, and only
  within that user's servers and role.
- **Short, scoped sessions.** Sessions default to 1h and `operate` scope. The
  *read only* scope makes every change need a touch. Each server can cap the
  lifetime and allowed scopes in `gate.json`.
- **Admin actions always need a fresh touch**, and the server-side policy
  still forbids host escapes even for admins.
- **Least-privilege tokens.** Use a Tailscale OAuth client with only
  `auth_keys` and `devices:core`, limited to the nodescale tags, and **never
  `policy_file`**. Use a Cloudflare token limited to Tunnel and DNS edits.
- **Server-side audit** that the console can't alter.
- **Hardening for high assurance**: put the console behind Cloudflare Access,
  restrict who can deploy (protected branches, separate Cloudflare roles),
  and use hardware security keys for admins. The protocol is documented
  ([protocol.md](protocol.md)), so an independent CLI could sign requests
  without the hosted frontend.

### Residual risks

- **Trust on first use.** Compare the server identity printed by the install
  script before clicking Trust.
- **TCP port forwarding.** An attacker controlling the relay can SSH as
  `nodescale` and, if your tailnet policy allows forwarding, reach TCP
  services that listen only on the server's localhost. They run as an
  unprivileged user without Docker access. The default policy refuses
  published container ports; don't run unauthenticated admin services on
  localhost.
- **Output isn't sealed.** Logs, exec output and inspect data travel through
  the console in plaintext. If you `echo` a secret in exec, the console sees
  it.
- **Bind-mount race.** Symlinks are resolved before Docker mounts the path.
  A container that can write under an allowed prefix could race a later
  deploy. Keep allowed prefixes for data, not for paths that untrusted
  containers write to.
- **Root on the server** can change `gate.json`. nodescale protects the
  management path, not a compromised host.
- **Availability.** The console can refuse to relay. You can always reach
  servers with `tailscale ssh` under your own identity.

## Alternatives considered

- **A long-running agent (an earlier iteration).** It has the same security
  properties but a daemon on every server. The on-demand gate removes it.
- **The agent dials out to a Durable Object over WebSocket.** No relay
  container is needed, but it requires a daemon. Rejected for the same
  reason.
- **Encrypting tokens with a server-side KMS key.** This protects against a
  database leak but not a compromised Worker. Client-side encryption covers
  both.
