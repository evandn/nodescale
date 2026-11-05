# Deploying nodescale

## Prerequisites

- A Cloudflare account on the Workers Paid plan (Containers and Durable
  Objects need it) and a hostname for the console, e.g.
  `nodescale.example.com`.
- Node.js 22+, pnpm 10, Docker (to build the relay image), Go 1.24+ (agent).
- A Tailscale tailnet where you can edit the policy file.

## 1. Tailnet policy

Merge the following into your tailnet policy (Admin console → Access
controls). It is also shown in the console under Settings → Integrations.

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

Keep your own SSH rules (for example `autogroup:member` → `tag:nodescale-server`
as `root` with `"action": "check"`) for break-glass access.

Then create an **OAuth client** (Settings → OAuth clients) with these scopes:

- `auth_keys` (write), tags `tag:nodescale-server`, `tag:nodescale-relay`
- `devices:core` (write), same tags

Do **not** grant `policy_file`. Each user enters this client into their own
encrypted vault in the console. You can create one per person to keep
accountability.

## 2. Cloudflare API token

Create a token (My Profile → API Tokens → Create custom token) with:

- Account → **Cloudflare Tunnel: Edit**
- Zone → **DNS: Edit** and **Zone: Read**, limited to the zones you serve

Consider client IP filtering and an expiry date.

## 3. Deploy the console

```sh
pnpm install
cd apps/console

# D1
npx wrangler d1 create nodescale         # copy database_id into wrangler.jsonc
npx wrangler d1 migrations apply nodescale --remote

# Configuration
#   wrangler.jsonc → vars.RP_ID  = "nodescale.example.com"
#                    vars.ORIGIN = "https://nodescale.example.com"
#                    add a custom domain route for the Worker
openssl rand -base64 48 | npx wrangler secret put RELAY_SECRET

# Build the SPA and deploy the Worker, Durable Object and relay container
pnpm deploy
```

The first person to sign up becomes the owner of a new workspace. After
that, sign-up needs an invite link (Team → Invites), unless you set
`SIGNUP = "open"`.

**`RP_ID` and `ORIGIN` are permanent.** Passkeys are bound to the RP ID and
every agent only accepts the configured origin. Changing them means
re-registering passkeys and updating `/etc/nodescale/agent.json` on every
server.

Optional hardening:

- Put the console behind **Cloudflare Access**, with your identity provider
  as an outer gate.
- Restrict who can deploy (Cloudflare account roles, protected branches, and
  required reviews on the repo the console deploys from).

## 4. Publish the agent image

Installs pull `ghcr.io/evandn/nodescale-agent:latest` by default.
`.github/workflows/agent-image.yml` builds and pushes it for `linux/amd64`
and `linux/arm64` on every push to `main` and on tags. If you fork, change
`AGENT_IMAGE` in `apps/console/src/client/lib/install.ts`.

## 5. Add servers

In the console go to **Servers → Add server**. It will:

1. mint a one-hour, single-use Tailscale auth key in your browser
   (`tag:nodescale-server`);
2. optionally create a Cloudflare Tunnel;
3. generate `nodescale-install.sh`.

Run the script once as root (for example from your provider's console). On
the server it:

- installs Docker and Tailscale if missing, and joins with `--ssh`;
- creates the `nodescale` user with the gate as its login shell;
- writes `/etc/nodescale/agent.json` with your passkeys;
- runs the agent with `--network none --read-only --cap-drop ALL`;
- starts `cloudflared` on the `nodescale` Docker network if you chose a
  tunnel;
- prints the agent ID. Compare it in the console before clicking **Trust**.

For servers already on your tailnet, choose **Already on my tailnet**. The
console tags the device and the script skips the Tailscale join.

### Exposing a service

Deploy containers on the `nodescale` network without publishing ports. Then
go to **Tunnels → Route** and map `app.example.com` → `http://<container>:<port>`.
The console updates the tunnel's ingress and creates the proxied DNS record.

## Local development

```sh
pnpm install
cd apps/console
npx wrangler d1 migrations apply nodescale --local
cp .dev.vars.example .dev.vars
pnpm build && npx wrangler dev --enable-containers=false   # http://localhost:8787

# In another shell: a relay that skips Tailscale and talks to a local agent
cd relay && RELAY_SECRET=<same as .dev.vars> RELAY_DEV_AGENT_SOCKET=/tmp/ns/agent.sock go run .

# And a local agent (Docker must be running)
cd agent && NODESCALE_CONFIG=/tmp/ns/agent.json NODESCALE_IDENTITY=/tmp/ns/id.key \
  NODESCALE_SOCKET=/tmp/ns/agent.sock NODESCALE_AUDIT=/tmp/ns/audit.jsonl go run ./cmd/nodescale-agent
```

`/tmp/ns/agent.json` needs `"rpId": "localhost"`, `"origins": ["http://localhost:8787"]`
and your passkey from `GET /api/passkeys` as an `admin` signer.
`RELAY_DEV_URL` only takes effect when `ORIGIN` starts with
`http://localhost`.
