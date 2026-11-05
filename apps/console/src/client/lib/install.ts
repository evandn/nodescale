import type { SignerKey } from "@nodescale/protocol";
import { SERVER_TAG } from "./providers.ts";

export const AGENT_IMAGE = "ghcr.io/evandn/nodescale-agent:latest";

export interface InstallOptions {
  serverName: string;
  rpId: string;
  origin: string;
  signers: SignerKey[];
  /** One-time Tailscale auth key; omit for a device already on the tailnet. */
  tailscaleAuthKey?: string;
  cloudflareTunnelToken?: string;
  maxSessionSeconds?: number;
}

function shq(s: string) {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** Generates the bootstrap script a user runs once on a new server. */
export function installScript(o: InstallOptions): string {
  const config = {
    rpId: o.rpId,
    origins: [o.origin],
    signers: o.signers.map(({ id, alg, publicKey, role, label, user }) => ({ id, alg, publicKey, role, label, user })),
    policy: { maxSessionSeconds: o.maxSessionSeconds ?? 8 * 3600 },
  };
  return `#!/bin/sh
# nodescale bootstrap for "${o.serverName}" — generated ${new Date().toISOString()}
#
# Run once as root:   sudo sh nodescale-install.sh
#
# This script contains one-time secrets (a Tailscale auth key that expires in
# one hour${o.cloudflareTunnelToken ? " and a Cloudflare Tunnel token" : ""}). Do not commit or share it.
#
# What it does:
#   1. installs Docker and Tailscale if missing and joins your tailnet with
#      Tailscale SSH enabled, tagged ${SERVER_TAG};
#   2. creates a locked-down "nodescale" user whose login shell can only hand
#      a signed request to the agent (no shell, no sudo, no docker group);
#   3. writes the list of passkeys this server trusts to /etc/nodescale;
#   4. starts the nodescale agent (no network access; talks to Docker over
#      its socket and to the gate over a unix socket);
${o.cloudflareTunnelToken ? "#   5. starts cloudflared for this server's Cloudflare Tunnel.\n" : ""}set -eu

[ "$(id -u)" = 0 ] || { echo "Please run as root (sudo sh $0)" >&2; exit 1; }

NODESCALE_IMAGE=${shq(AGENT_IMAGE)}
TS_AUTHKEY=${shq(o.tailscaleAuthKey ?? "")}
TS_HOSTNAME=${shq(o.serverName)}
CF_TUNNEL_TOKEN=${shq(o.cloudflareTunnelToken ?? "")}

echo "==> Docker"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

echo "==> Tailscale (with Tailscale SSH)"
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi
if [ -n "$TS_AUTHKEY" ]; then
  tailscale up --authkey="$TS_AUTHKEY" --ssh --hostname="$TS_HOSTNAME" --advertise-tags=${SERVER_TAG}
else
  tailscale set --ssh
fi

echo "==> Restricted nodescale user"
getent group nodescale >/dev/null || groupadd --system nodescale
if ! id nodescale >/dev/null 2>&1; then
  useradd --system --gid nodescale --home-dir /nonexistent --no-create-home --shell /usr/local/bin/nodescale-gate nodescale
fi
usermod --shell /usr/local/bin/nodescale-gate nodescale
for g in docker sudo adm wheel; do gpasswd -d nodescale "$g" >/dev/null 2>&1 || true; done
passwd -l nodescale >/dev/null 2>&1 || true

echo "==> Trusted passkeys"
install -d -m 0700 /etc/nodescale /var/lib/nodescale
cat > /etc/tmpfiles.d/nodescale.conf <<'NODESCALE_EOF'
d /run/nodescale 0750 root nodescale -
NODESCALE_EOF
systemd-tmpfiles --create /etc/tmpfiles.d/nodescale.conf 2>/dev/null || install -d -m 0750 -g nodescale /run/nodescale
if [ -f /etc/nodescale/agent.json ]; then
  cp /etc/nodescale/agent.json "/etc/nodescale/agent.json.$(date +%s).bak"
fi
umask 077
cat > /etc/nodescale/agent.json <<'NODESCALE_EOF'
${JSON.stringify(config, null, 2)}
NODESCALE_EOF

echo "==> nodescale agent"
docker pull "$NODESCALE_IMAGE"
docker run --rm -v /usr/local/bin:/host/usr/local/bin "$NODESCALE_IMAGE" install-gate /host/usr/local/bin/nodescale-gate
docker rm -f nodescale-agent >/dev/null 2>&1 || true
docker run -d --name nodescale-agent --restart unless-stopped \\
  --network none --read-only --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges \\
  -e NODESCALE_SOCKET_GID="$(getent group nodescale | cut -d: -f3)" \\
  -e NODESCALE_HOSTNAME="$(hostname)" \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  -v /etc/nodescale:/etc/nodescale \\
  -v /var/lib/nodescale:/var/lib/nodescale \\
  -v /run/nodescale:/run/nodescale \\
  "$NODESCALE_IMAGE"

if [ -n "$CF_TUNNEL_TOKEN" ]; then
  echo "==> Cloudflare Tunnel"
  docker network inspect nodescale >/dev/null 2>&1 || docker network create nodescale
  docker rm -f cloudflared >/dev/null 2>&1 || true
  docker run -d --name cloudflared --restart unless-stopped --network nodescale \\
    -e TUNNEL_TOKEN="$CF_TUNNEL_TOKEN" \\
    cloudflare/cloudflared:latest tunnel --no-autoupdate run
fi

sleep 2
echo
echo "==> Done. Compare this agent ID with the one shown in nodescale before trusting the server:"
docker exec nodescale-agent /usr/local/bin/nodescale-agent id
`;
}

/** The tailnet policy fragment nodescale relies on. */
export const TAILNET_POLICY = `{
  "tagOwners": {
    "${SERVER_TAG}": ["autogroup:admin"],
    "tag:nodescale-relay": ["autogroup:admin"]
  },
  "grants": [
    // The relay may only reach servers' SSH port...
    { "src": ["tag:nodescale-relay"], "dst": ["${SERVER_TAG}"], "ip": ["tcp:22"] }
  ],
  "ssh": [
    // ...and only as the restricted "nodescale" user.
    { "action": "accept", "src": ["tag:nodescale-relay"], "dst": ["${SERVER_TAG}"], "users": ["nodescale"] }
  ]
}`;
