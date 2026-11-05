import { describe, expect, it } from "vitest";
import { ComposeError, bytesOf, duration, interpolateEnv, parseCompose, splitCommand } from "../src/client/lib/compose.ts";

const COMPOSE = `
services:
  app:
    image: ghcr.io/acme/app:1.4
    command: ["node", "server.js"]
    environment:
      DATABASE_URL: postgres://app:\${DB_PASSWORD}@db:5432/app
      LOG_LEVEL: info
      FEATURE: "\${FEATURE_FLAG:-off}"
    depends_on: [db]
    restart: always
    mem_limit: 512m
    healthcheck:
      test: curl -f http://localhost:8080/health
      interval: 30s
      timeout: 5s
      retries: 3
    x-nodescale:
      expose: { hostname: app.example.com, port: 8080 }
  db:
    image: postgres:17-alpine
    environment:
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
      - /srv/backups:/backups:ro
    stop_grace_period: 1m30s
volumes:
  pgdata:
  shared:
    external: true
`;

describe("compose parser", () => {
  it("converts a typical compose file", () => {
    const r = parseCompose(COMPOSE, "shop");
    expect(r.spec.services.map((s) => s.service)).toEqual(["db", "app"]); // depends_on order
    const [db, app] = r.spec.services;
    expect(app!.cmd).toEqual(["node", "server.js"]);
    expect(app!.memory).toBe(512 * 1024 ** 2);
    expect(app!.restart).toBe("always");
    expect(app!.healthcheck).toEqual({ test: ["CMD-SHELL", "curl -f http://localhost:8080/health"], interval: 30, timeout: 5, startPeriod: undefined, retries: 3 });
    expect(app!.networks).toEqual(["nodescale"]); // joined the edge network for its tunnel route
    expect(db!.mounts).toEqual([
      { type: "volume", source: "shop_pgdata", target: "/var/lib/postgresql/data", readOnly: false },
      { type: "bind", source: "/srv/backups", target: "/backups", readOnly: true },
    ]);
    expect(db!.stopTimeout).toBe(90);
    expect(r.spec.volumes).toEqual(["shop_pgdata"]);
    expect(r.variables).toEqual(["DB_PASSWORD", "FEATURE_FLAG"]);
    expect(r.expose).toEqual([{ service: "app", container: "shop-app", hostname: "app.example.com", port: 8080 }]);
  });

  it("interpolates secrets only into environment values", () => {
    const r = parseCompose(COMPOSE, "shop");
    const out = interpolateEnv(r.spec, { DB_PASSWORD: "p@ss" });
    expect(out.services[1]!.env).toContain("DATABASE_URL=postgres://app:p@ss@db:5432/app");
    expect(out.services[1]!.env).toContain("FEATURE=off");
    expect(() => interpolateEnv(r.spec, {})).toThrow(/DB_PASSWORD/);
    expect(() => parseCompose("services:\n  a:\n    image: x:${TAG}\n", "s")).toThrow(/only supported in environment/);
  });

  it("rejects unsupported or unsafe input clearly", () => {
    const bad = (y: string, re: RegExp) => expect(() => parseCompose(y, "s")).toThrow(re);
    bad("services:\n  a:\n    build: .\n", /build is not supported/);
    bad("services:\n  a:\n    image: x\n    volumes: [./data:/data]\n", /absolute host paths/);
    bad("services:\n  a:\n    image: x\n    volumes: [missing:/data]\n", /not declared/);
    bad("services:\n  a:\n    image: x\n    depends_on: [b]\n  b:\n    image: y\n    depends_on: [a]\n", /cycle/);
    bad("services:\n  a:\n    image: x\n    environment: [PASSTHROUGH]\n", /no value/);
    bad("nope: 1", /services/);
    expect(() => parseCompose("services: {}", "Bad Name")).toThrow(ComposeError);
  });

  it("parses helpers", () => {
    expect(splitCommand(`sh -c "echo 'hi there'" x\\ y`)).toEqual(["sh", "-c", "echo 'hi there'", "x y"]);
    expect(duration("1h2m3s", "d")).toBe(3723);
    expect(bytesOf("1.5g", "m")).toBe(1.5 * 1024 ** 3);
    expect(bytesOf(1024, "m")).toBe(1024);
  });
});
