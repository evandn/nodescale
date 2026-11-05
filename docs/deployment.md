# Deploying nodescale

## Prerequisites

- A Cloudflare account on the Workers Paid plan (Containers and Durable
  Objects need it) and a hostname for the console, e.g.
  `nodescale.example.com`.
- Node.js 22+, pnpm 10, Docker (to build the relay image), Go 1.24+.
- A Tailscale tailnet where you can edit the policy file.

## 1. Publish the gate

Server install scripts download `nodescale-gate` from this repository's
GitHub Releases and verify its SHA-256. Tag a release:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The **Release** workflow tests and builds `nodescale-gate-linux-{amd64,arm64}`,
publishes `SHA256SUMS`, attaches build provenance (`gh attestation verify`),
and prints the hashes to pin in step 4. If you fork, set `GATE_REPO`
accordingly.

## 2. Tailnet policy

Merge into your tailnet policy (Admin console → Access controls). It's also
shown under Settings → Integrations.

```jsonc
{
  "tagOwners": {
    "tag:nodescale-server": ["autogroup:admin"],
    "tag:nodescale-relay":  ["autogroup:admin"]
  },
  "grants": [
    { "src": ["tag:nodescale-relay"], "dst": ["tag:nodescale-server"], "ip": ["tcp:22"] }
  ],
  "ssh": [
    { "action": "accept", "src": ["tag:nodescale-relay"], "dst": ["tag:nodescale-server"], "users": ["nodescale"] }
  ]
}
```

Keep your own SSH rules (for example `autogroup:member` →
`tag:nodescale-server` as `root` with `"action": "check"`) for break-glass
access and for running upgrade scripts.

Create an **OAuth client** (Settings → OAuth clients):

- `auth_keys` (write), tags `tag:nodescale-server`, `tag:nodescale-relay`
- `devices:core` (write), same tags

Do **not** grant `policy_file`. Each user enters the client into their own
encrypted vault. One client per person keeps accountability clear.

## 3. Cloudflare API token

Create a custom token (My Profile → API Tokens) with:

- Account → **Cloudflare Tunnel: Edit**
- Zone → **DNS: Edit** and **Zone: Read**, limited to the zones you serve

Consider client IP filtering and an expiry date.

## 4. Deploy the console

```sh
pnpm install
cd apps/console

npx wrangler d1 create nodescale              # put database_id in wrangler.jsonc
npx wrangler d1 migrations apply nodescale --remote

# wrangler.jsonc → vars:
#   RP_ID  = "nodescale.example.com"
#   ORIGIN = "https://nodescale.example.com"
#   GATE_VERSION / GATE_SHA256_AMD64 / GATE_SHA256_ARM64 = from the Release summary
# and add a custom domain route for the Worker.
openssl rand -base64 48 | npx wrangler secret put RELAY_SECRET

pnpm deploy        # builds the SPA, deploys the Worker, Durable Object and relay container
```

The first person to sign up becomes the owner of a new workspace. After that,
sign-up needs an invite link (Team → Invites), unless `SIGNUP = "open"`.

**`RP_ID` and `ORIGIN` are permanent.** Passkeys are bound to the RP ID, and
every server only accepts the configured origin.

Recommended hardening:

- Put the console behind **Cloudflare Access** (your IdP as an outer gate).
- Restrict who can deploy the Worker (Cloudflare roles, protected branches,
  required reviews).

## 5. Add servers

**Servers → Add server**:

1. Your browser mints a one-hour, single-use Tailscale auth key and,
   optionally, creates a Cloudflare Tunnel linked to the server.
2. Run the generated `nodescale-install.sh` once as root, e.g. from your
   provider's console. It:
   - installs Docker and Tailscale if missing and enables Tailscale SSH;
   - downloads and verifies the gate and installs it `root:docker 2755`;
   - creates the restricted `nodescale` user (login shell = gate, no groups);
   - writes `/etc/nodescale/gate.json` (your passkeys and default policy)
     and creates the identity key;
   - runs `cloudflared` on the `nodescale` Docker network when a tunnel was
     created;
   - runs `nodescale-gate check` and prints the server identity.
3. Back in the console, **compare the identity and click Trust**.

For machines already on your tailnet, choose **Already on my tailnet**. The
console tags the device and the script skips the Tailscale join.

Upgrade and uninstall scripts are under Server → Settings. Run them as root,
e.g. `tailscale ssh root@<server>`.

### Server policy

`/etc/nodescale/gate.json` → `policy` can only be changed by root on the
server:

```jsonc
"policy": {
  "maxSessionSeconds": 28800,           // cap on browser session keys
  "allowSessionScopes": ["read", "operate"],   // ["read"] = touch passkey for every change
  "containers": {
    "allowPrivileged": false, "allowHostNamespaces": false, "allowDevices": false,
    "allowPublishedPorts": false,
    "bindMountPrefixes": ["/srv", "/opt/apps", "/data", "/mnt"]
  }
}
```

Run `sudo nodescale-gate check` after editing.

## Local development

```sh
pnpm install
cd apps/console
npx wrangler d1 migrations apply nodescale --local
cp .dev.vars.example .dev.vars
pnpm build && npx wrangler dev --enable-containers=false      # http://localhost:8787

# Relay in dev mode: no tailnet, runs a local gate binary per request.
cd relay && RELAY_SECRET=<same as .dev.vars> RELAY_DEV_GATE=/path/to/nodescale-gate go run .
```

Without root, point the gate at a scratch config with `NODESCALE_CONFIG`,
`NODESCALE_STATE` and `DOCKER_SOCKET` (these overrides are ignored when the
gate runs setgid). The config needs `"rpId": "localhost"`,
`"origins": ["http://localhost:8787"]` and your passkey from
`GET /api/passkeys` as an `admin` signer.

## Tests

| Command | What it covers |
| --- | --- |
| `pnpm test` | TypeScript unit tests, cross-language vectors, Go tests (including real-Docker tests when a daemon is available) |
| `sudo -E env "PATH=$PATH" sh test/integration/server-install.sh` | Runs the generated install script on this host and drives the setgid gate through `su nodescale` |
| `sudo -E env "PATH=$PATH" sh test/e2e/run.sh` | Full browser → Worker → relay → gate → Docker flow with a virtual passkey |

The last two modify the host; CI runs them on disposable runners.
