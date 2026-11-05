# nodescale

A minimal self-hosted PaaS for managing containers and servers.

nodescale is a console for a fleet of Debian/Ubuntu servers spread across
providers. The servers have **no inbound ports**, are reachable only over
**Tailscale (with Tailscale SSH)**, run everything in **Docker**, and publish
services through **Cloudflare Tunnels**. The console runs entirely on
Cloudflare: Workers, D1, Durable Objects and Containers.

## Security model in one paragraph

The console is treated as untrusted. Each server runs a small agent that
only executes allow-listed Docker operations, and only when they are
**signed by a passkey enrolled on that server**. Day-to-day actions use a
short-lived key in your browser tab that your passkey delegated to. Admin
actions (deploy, remove, change trusted keys) always need a fresh passkey
touch. Agents sign their responses, so the console can't fake server state.
Your Tailscale and Cloudflare tokens are encrypted **in your browser** with a
key derived from your passkey (WebAuthn PRF), so the database only holds
ciphertext. A breached console has no tokens to steal and no keys that can
act on a server. See [docs/architecture.md](docs/architecture.md) for the
threat model, including what a malicious frontend could still do.

## Features

- Passkey-only sign-in; one touch signs you in, unlocks the vault and starts
  an operations session
- Servers: add a new machine or adopt one already on the tailnet, with a
  generated one-time bootstrap script and identity pinning
- Containers: list, logs, start/stop/restart, deploy, remove; images: list,
  pull, remove; host and agent info
- Per-server access control: viewer / operator / admin passkeys, managed on
  the server itself
- Cloudflare Tunnels: list tunnels and health, add and remove public
  hostnames (ingress plus proxied DNS)
- Teams: workspaces, invite links, roles
- Audit logs: in the console, plus a tamper-resistant log on every server

## Repository layout

| Path | What |
| --- | --- |
| `apps/console` | Cloudflare Worker (Hono, D1, relay Container) and React SPA |
| `packages/protocol` | Signed-request protocol shared by the browser and the Worker |
| `agent` | On-server agent and SSH gate (Go, standard library only) |
| `relay` | Tailnet relay running as a Cloudflare Container (Go, `tsnet`) |
| `docs` | [Architecture & threat model](docs/architecture.md), [protocol](docs/protocol.md), [deployment](docs/deployment.md) |

## Quick start

```sh
pnpm install
pnpm test          # TypeScript tests, cross-language vectors and Go tests
pnpm typecheck
```

Deploying is covered in [docs/deployment.md](docs/deployment.md).

## License

AGPL-3.0. See [LICENSE](LICENSE).
