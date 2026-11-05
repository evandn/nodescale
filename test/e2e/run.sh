#!/bin/sh
# Full-stack end-to-end test: browser (virtual passkey with PRF) → Worker
# (wrangler dev) → relay (dev mode) → `su nodescale` → setgid nodescale-gate →
# Docker. Needs root, Docker, Go, Node 22, `pnpm install`, and Playwright
# with Chromium. Modifies the host like test/integration/server-install.sh.
#
#   sudo -E env "PATH=$PATH" sh test/e2e/run.sh
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
export E2E_OUT="${E2E_OUT:-$WORK}"
export E2E_PERSIST="$WORK/state"
SECRET="e2e-relay-secret-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

cleanup() {
  [ -f "$WORK/relay.pid" ] && kill -TERM "-$(cat "$WORK/relay.pid")" 2>/dev/null || true
  # wrangler runs in its own process group (setsid) so workerd children go too.
  [ -f "$WORK/wrangler.pid" ] && kill -TERM "-$(cat "$WORK/wrangler.pid")" 2>/dev/null || true
  if [ -f "$ROOT/apps/console/.dev.vars.e2e-backup" ]; then
    mv "$ROOT/apps/console/.dev.vars.e2e-backup" "$ROOT/apps/console/.dev.vars"
  else
    rm -f "$ROOT/apps/console/.dev.vars"
  fi
}
trap cleanup EXIT

if curl -s -o /dev/null http://localhost:8787 || curl -s -o /dev/null http://localhost:8080; then
  echo "ports 8787/8080 are in use; stop other dev servers first" >&2
  exit 1
fi

# 1. Server side, exactly as in production.
if ! command -v nodescale-gate >/dev/null 2>&1; then
  sh "$ROOT/test/integration/server-install.sh"
fi
printf '#!/bin/sh\nexec su nodescale -c nodescale-rpc\n' > /usr/local/bin/ns-gate-via-su
chmod 755 /usr/local/bin/ns-gate-via-su

# 2. Relay in dev mode: runs the gate through the nodescale login shell.
(cd "$ROOT/relay" && GOTOOLCHAIN=auto go build -o "$WORK/relay" .)
RELAY_SECRET="$SECRET" RELAY_DEV_GATE=/usr/local/bin/ns-gate-via-su setsid "$WORK/relay" >"$WORK/relay.log" 2>&1 &
echo $! > "$WORK/relay.pid"

# 3. Console, with its local state in $WORK.
cd "$ROOT/apps/console"
[ -f .dev.vars ] && mv .dev.vars .dev.vars.e2e-backup
printf 'RELAY_SECRET=%s\nRELAY_DEV_URL=http://localhost:8080\n' "$SECRET" > .dev.vars
npx wrangler d1 migrations apply nodescale --local --persist-to "$E2E_PERSIST" >/dev/null
npx vite build >/dev/null
setsid npx wrangler dev --port 8787 --enable-containers=false --persist-to "$E2E_PERSIST" >"$WORK/wrangler.log" 2>&1 &
echo $! > "$WORK/wrangler.pid"
for _ in $(seq 1 60); do
  curl -s -o /dev/null -w "%{http_code}" http://localhost:8787/api/me | grep -q 401 && break
  sleep 1
done

# 4. Browser.
node "$ROOT/test/e2e/console.e2e.cjs"
echo "screenshots in $E2E_OUT"
