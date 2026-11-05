# nodescale

A minimal self-hosted PaaS for managing containers and servers.

nodescale is a console for Debian/Ubuntu servers spread across providers. The
servers have **no inbound ports**, are reachable only over **Tailscale (with
Tailscale SSH)**, run everything in **Docker**, and publish services through
**Cloudflare Tunnels**. The console runs entirely on Cloudflare: Workers, D1,
Durable Objects and Containers. **Nothing runs in the background on your
servers.**

## How it works

The console reaches each server over Tailscale SSH as a restricted user whose
login shell is `nodescale-gate`: one small static binary, setgid `docker`,
that runs only for the duration of a request. It:

- checks that the request is signed by a passkey trusted *by that server*;
- applies the server's own policy;
- calls the Docker Engine API on the local socket;
- signs the response and exits.

## Security in one paragraph

The hosted console is treated as untrusted:

- **Your servers.** It holds no key that can act on a server. Day-to-day
  actions use a short-lived key that your passkey delegates to your browser
  tab. Deploys, removals, exec and access changes always need a fresh
  passkey touch.
- **Credentials and secrets.** Tailscale and Cloudflare tokens, and stack
  secrets, are encrypted in your browser with a key derived from your
  passkey. Container environment values are encrypted to the target server
  before they leave the browser.
- **Fake responses.** Servers sign their replies, so the console can't fake
  server state.

A breached console therefore has no tokens to steal, no secrets to read, and
no keys that can touch your containers. See
[docs/architecture.md](docs/architecture.md) for the threat model, including
what a malicious frontend could still do.

## Features

- Passkey-only sign-in. One touch signs you in, unlocks your vault and starts
  an operations session.
- Servers:
  - add new machines or adopt existing tailnet devices with a generated,
    checksum-verified bootstrap script;
  - identity pinning;
  - upgrade and uninstall scripts.
- Dashboard with live load, memory and disk, and container health per server.
- Containers: logs, details, restart policy, encrypted env reveal, one-shot
  exec, processes, start/stop/restart/pause, run, remove.
- **Stacks from compose files**:
  - secrets via `${NAME}`, kept in your vault and sealed end to end;
  - minimal-change redeploys;
  - `x-nodescale.expose` for public hostnames through the server's Cloudflare
    Tunnel.
- Images (pull, prune), networks and volumes.
- Per-server access control (viewer, operator, admin passkeys), stored on the
  server itself.
- Server policy that blocks container escapes by default: no privileged
  containers, host namespaces, devices or published ports, and bind mounts
  only from allowed prefixes.
- Cloudflare Tunnels: health and public hostnames (ingress plus proxied DNS).
- Teams: workspaces, invite links, roles.
- Audit logs: a console log plus a server-side log the console can't alter.

## Repository layout

| Path | What |
| --- | --- |
| `gate` | On-server gate: SSH login shell (Go, standard library only) |
| `relay` | Tailnet relay running as a Cloudflare Container (Go, `tsnet`) |
| `apps/console` | Cloudflare Worker (Hono, D1, relay container) and React SPA |
| `packages/protocol` | Signed-request and sealing protocol shared by the browser and the Worker |
| `test` | Server install integration test and full-stack E2E |
| `docs` | [Architecture & threat model](docs/architecture.md), [protocol](docs/protocol.md), [stacks](docs/stacks.md), [deployment](docs/deployment.md) |

## Quick start

```sh
pnpm install
pnpm test
pnpm typecheck
```

Deployment is covered in [docs/deployment.md](docs/deployment.md).

## License

AGPL-3.0. See [LICENSE](LICENSE).
