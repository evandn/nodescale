# Stacks (compose files)

A stack is a group of services deployed from a Docker Compose file, converted
in your browser into the gate's stack spec (`apps/console/src/client/lib/compose.ts`).

```yaml
services:
  app:
    image: ghcr.io/acme/app:1.4
    environment:
      DATABASE_URL: postgres://app:${DB_PASSWORD}@db:5432/app   # secret from your vault
      LOG_LEVEL: info
    depends_on: [db]
    healthcheck:
      test: curl -f http://localhost:8080/health
      interval: 30s
    x-nodescale:
      expose: { hostname: app.example.com, port: 8080 }   # Cloudflare Tunnel route
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

## Secrets

- Write `${NAME}` (or `${NAME:-default}`) **only inside `environment`
  values**. Placeholders elsewhere are rejected.
- Values come from your encrypted vault (Settings → Secrets, or prompted at
  deploy time).
- **Every** environment value, secret or not, is sealed to the target
  server's key before the request is signed. The console stores only the
  compose text with placeholders.
- Each teammate keeps their own copies of secret values in their own vault.

## Naming and networking

- Containers are named `<stack>-<service>`. Services reach each other by
  service name on the stack network `<stack>_default`.
- Named volumes become `<stack>_<name>`, unless declared `external: true` or
  given an explicit `name:`.
- Networks declared at the top level become `<stack>_<name>`. The `nodescale`
  network (where cloudflared runs) is used as is.
- `x-nodescale.expose` adds the service to the `nodescale` network. After
  deploy, the console points the hostname at `http://<stack>-<service>:<port>`
  through the server's linked tunnel (Server → Settings) and creates the
  proxied DNS record.

## Updates

Redeploying recreates only services whose definition or image changed.
"Pull & redeploy" pulls every image first, so moving tags such as `:latest`
or `:1` pick up new builds. Services removed from the file are removed from
the server.

## Supported keys

`image`, `command`, `entrypoint`, `environment`, `labels`, `user`,
`working_dir`, `hostname`, `restart`, `pull_policy`, `networks` (list or map
with `aliases`), `network_mode`, `pid`, `ipc`, `volumes` (short and long
syntax: volume, bind, tmpfs), `tmpfs`, `ports`, `mem_limit`, `cpus`,
`deploy.resources.limits`, `read_only`, `privileged`, `init`, `cap_add`,
`cap_drop`, `devices`, `extra_hosts`, `stop_grace_period`, `healthcheck`,
`depends_on` (start order).

Not supported, with an explicit error: `build`, `env_file`, `secrets`,
`configs`, `links`, `volumes_from`, `profiles`, `deploy.replicas`,
anonymous volumes, and relative bind paths.

Server policy still applies. By default the gate refuses privileged
containers, host namespaces, devices, published ports, extra capabilities,
and bind mounts outside `/srv`, `/opt/apps`, `/data` and `/mnt`.
