# Work log (overnight build)

Resume instructions: read this file, `git log`, then continue with the first
unchecked item. Commit and push after every item
(`git push -u origin claude/server-management-app-7wk5z0`).

## Goal

Complete nodescale with **no daemon on servers**: the relay SSHes (Tailscale
SSH) as user `nodescale`, whose login shell `nodescale-gate` is a short-lived,
setgid-`docker` binary. Each invocation verifies the passkey signature, applies
server policy, calls the Docker Engine API on `/var/run/docker.sock`, signs the
response and exits.

## Decisions

- Raw socket forwarding was rejected: whoever controls the relay would have
  root on every server. The gate keeps verification on the server and runs
  only per request.
- Tailscale SSH (v1.104 source checked): runs `su -l user -c cmd` or execs the
  login shell directly; no `no_new_privs`, so setgid works. Unix-socket
  forwarding is limited to home, /tmp and /run/user/<uid> and runs with the
  user's own groups, so `docker.sock` can't be forwarded.
- Permissions: binary `root:docker 2755`; `/etc/nodescale` and
  `/var/lib/nodescale` `root:docker 2770` (the `nodescale` user can't traverse
  them; only the setgid gate can). The `nodescale` user is in no groups.
- Env-var path overrides only apply when the process is not setgid/setuid
  (dev and tests).
- Replay protection without a daemon: nonce files created with O_EXCL in
  `/var/lib/nodescale/nonces`, pruned opportunistically.
- Gate distribution: GitHub Release binaries (amd64/arm64) plus SHA256SUMS
  and build provenance; the console can pin hashes via vars.
- Server policy (defaults deny): privileged containers, host
  pid/ipc/userns/network, dangerous caps, devices, and binds outside
  allowed prefixes (`/srv`, `/opt/apps`, `/data`, `/mnt`).
- `containers.inspect` redacts env values; the admin op `containers.env`
  reveals them. Audit logs keep env keys only.
- Stacks: compose-like YAML parsed in the browser into a spec;
  `stacks.deploy` / `stacks.remove` run in the gate (labels
  `io.nodescale.stack`, `io.nodescale.service`).

## Plan

- [ ] 1. Rename agent → gate (Go); remove daemon/socket server; gate = one-shot stdin→stdout
- [ ] 2. File-based nonce store, secure-mode path handling, init/install subcommands
- [ ] 3. Extended Docker ops (+ kill/pause/unpause/rename/update/top/exec/env, images prune, networks, volumes, system df, host.info, audit.read)
- [ ] 4. Server policy enforcement for create; stacks deploy/remove
- [ ] 5. Go tests (fake Docker API over unix socket); vectors regenerated
- [ ] 6. Protocol TS ops catalogue sync
- [ ] 7. Relay: dev mode runs the local gate binary; production unchanged
- [ ] 8. Install / upgrade / uninstall script generator (no container), release workflow for gate binaries
- [ ] 9. Console UI: overview with live host stats, server tabs (containers, stacks, images, networks, volumes, access, audit, system), exec, env reveal, stack editor + tunnel routes
- [ ] 10. E2E Playwright run against the real gate binary + local dockerd
- [ ] 11. Docs (architecture/threat model, protocol, deployment), README
- [ ] 12. Final review (security pass), cleanup, remove this worklog or convert to CHANGELOG

## Progress notes

(append below)
