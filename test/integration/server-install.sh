#!/bin/sh
# Integration test for the server side: generates an install script with the
# console's generator, runs it on this (Debian/Ubuntu, Docker-equipped) host
# with a stubbed `tailscale`, then drives the installed setgid gate through
# `su nodescale -c …` exactly like Tailscale SSH does.
#
#   sudo test/integration/server-install.sh
#
# WARNING: modifies the host (creates the nodescale user, /etc/nodescale,
# /var/lib/nodescale, /usr/local/bin/nodescale-gate). Run it in CI or a VM.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'kill $HTTP_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT
IMAGE="${NODESCALE_TEST_IMAGE:-alpine:3.20}"

echo "==> build gate and serve it from a local mirror"
mkdir -p "$WORK/mirror"
(cd "$ROOT/gate" && CGO_ENABLED=0 go build -trimpath -o "$WORK/mirror/nodescale-gate-linux-amd64" ./cmd/nodescale-gate)
(cd "$WORK/mirror" && sha256sum nodescale-gate-linux-amd64 > SHA256SUMS)
(cd "$WORK/mirror" && exec python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1) &
HTTP_PID=$!
sleep 1

if ! command -v tailscale >/dev/null 2>&1; then
  printf '#!/bin/sh\necho "[stub tailscale] $*"\n' > /usr/local/bin/tailscale
  chmod +x /usr/local/bin/tailscale
fi

echo "==> generate and run the install script"
(cd "$ROOT" && node --experimental-strip-types --no-warnings test/integration/gen-install.ts "$WORK")
sh "$WORK/install.sh"

AUD="$(nodescale-gate id | python3 -c 'import sys,json;print(json.load(sys.stdin)["agent"])')"
sign() { (cd "$ROOT/test/integration" && node --experimental-strip-types --no-warnings sign.ts "$WORK/passkey.json" "$AUD" "$@"); }
call() { sign "$@" | su nodescale -c nodescale-rpc | python3 "$ROOT/test/integration/decode.py"; }
expect() { want="$1"; shift; out="$(call "$@")"; echo "  $* -> $out" | cut -c1-200; case "$out" in "$want"*) ;; *) echo "FAILED: expected $want" >&2; exit 1 ;; esac; }

echo "==> exercise the gate as the nodescale user"
expect ok host.info
expect ok containers.list '{"all":true}'
expect ok stacks.deploy "{\"name\":\"itest\",\"services\":[{\"service\":\"a\",\"image\":\"$IMAGE\",\"cmd\":[\"sleep\",\"600\"]},{\"service\":\"b\",\"image\":\"$IMAGE\",\"cmd\":[\"sleep\",\"600\"],\"env\":[\"TOKEN=s3cret\"]}]}"
expect ok containers.exec '{"id":"itest-b","cmd":["sh","-c","ping -c1 -W2 a >/dev/null && echo reachable"]}'
expect "ERR" containers.create "{\"image\":\"$IMAGE\",\"privileged\":true}"
expect "ERR" containers.create "{\"image\":\"$IMAGE\",\"mounts\":[{\"type\":\"bind\",\"source\":\"/\",\"target\":\"/host\"}]}"
expect "ERR" stacks.remove '{"name":"itest"}' --no-uv
REQ="$(sign signers.list)"
echo "$REQ" | su nodescale -c x | python3 "$ROOT/test/integration/decode.py" | grep -q '^ok'
echo "$REQ" | su nodescale -c x | python3 "$ROOT/test/integration/decode.py" | grep -q 'replay' && echo "  replay rejected"
if call audit.read | grep -q TOKEN=s3cret; then echo "FAILED: secret in audit log" >&2; exit 1; fi

echo "==> the nodescale user itself has no access"
su -s /bin/sh nodescale -c 'test -r /var/lib/nodescale/identity.key' && { echo "FAILED: identity readable" >&2; exit 1; }
su -s /bin/sh nodescale -c 'test -w /var/run/docker.sock' && { echo "FAILED: docker socket writable" >&2; exit 1; }
su -s /bin/sh nodescale -c 'ls /etc/nodescale' 2>/dev/null && { echo "FAILED: config readable" >&2; exit 1; }
script -qc "su nodescale" /dev/null </dev/null | grep -q "Interactive login is disabled" && echo "  interactive login refused"

expect ok stacks.remove '{"name":"itest","volumes":true}'
echo "==> all server integration checks passed"
