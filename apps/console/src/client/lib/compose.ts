import { parse } from "yaml";

/**
 * Converts a Docker Compose file into the gate's stack spec. Supports the
 * commonly used subset of the Compose specification; anything unsupported is
 * reported instead of being silently ignored.
 *
 * Secrets: `${NAME}` (or `${NAME:-default}`) may appear only inside
 * `environment` values. They are resolved from the user's encrypted vault at
 * deploy time and every environment value is sealed to the target server, so
 * the console never stores or sees them.
 *
 * nodescale extension, per service:
 *   x-nodescale:
 *     expose: { hostname: app.example.com, port: 8080 }   # Cloudflare Tunnel route
 */

export interface Mount {
  type: "volume" | "bind" | "tmpfs";
  source?: string;
  target: string;
  readOnly?: boolean;
}

export interface ServiceSpec {
  service: string;
  image: string;
  cmd?: string[];
  entrypoint?: string[];
  env?: string[];
  labels?: Record<string, string>;
  user?: string;
  workingDir?: string;
  hostname?: string;
  restart?: string;
  networks?: string[];
  aliases?: string[];
  networkMode?: string;
  pidMode?: string;
  ipcMode?: string;
  mounts?: Mount[];
  ports?: { hostIp?: string; hostPort: number; containerPort: number; protocol?: string }[];
  memory?: number;
  cpus?: number;
  readOnly?: boolean;
  capAdd?: string[];
  capDrop?: string[];
  privileged?: boolean;
  devices?: string[];
  extraHosts?: string[];
  init?: boolean;
  stopTimeout?: number;
  healthcheck?: { test: string[]; interval?: number; timeout?: number; startPeriod?: number; retries?: number };
  pull?: string;
}

export interface StackSpec {
  name: string;
  services: ServiceSpec[];
  volumes?: string[];
  networks?: string[];
  pull?: string;
}

export interface Expose {
  service: string;
  container: string;
  hostname: string;
  port: number;
}

export interface ParsedStack {
  spec: StackSpec;
  /** Placeholder names referenced in environment values. */
  variables: string[];
  expose: Expose[];
  warnings: string[];
}

export class ComposeError extends Error {}

const NAME = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const PLACEHOLDER = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}/g;
/** Networks cloudflared is attached to; exposed services join it. */
export const EDGE_NETWORK = "nodescale";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

function strList(v: unknown, field: string): string[] {
  if (v === undefined || v === null) return [];
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x) => typeof x === "string" || typeof x === "number")) return v.map(String);
  throw new ComposeError(`${field} must be a string or a list of strings`);
}

/** Splits a shell-like command string, honouring simple quotes. */
export function splitCommand(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let has = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === "\\" && quote === '"' && i + 1 < s.length) cur += s[++i];
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (cur || has) out.push(cur);
      cur = "";
      has = false;
    } else if (ch === "\\" && i + 1 < s.length) {
      cur += s[++i];
    } else {
      cur += ch;
    }
  }
  if (quote) throw new ComposeError(`unterminated quote in command: ${s}`);
  if (cur || has) out.push(cur);
  return out;
}

function command(v: unknown, field: string): string[] | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "string") return splitCommand(v);
  return strList(v, field);
}

/** Parses compose durations such as "1m30s", "10s", "500ms" into seconds. */
export function duration(v: unknown, field: string): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "number") return v;
  const s = String(v).trim();
  let total = 0;
  const re = /(\d+(?:\.\d+)?)(ms|us|ns|h|m|s)/g;
  let m: RegExpExecArray | null;
  let consumed = 0;
  while ((m = re.exec(s))) {
    const n = Number(m[1]);
    total += { h: 3600, m: 60, s: 1, ms: 0.001, us: 1e-6, ns: 1e-9 }[m[2] as "h"] * n;
    consumed += m[0].length;
  }
  if (!consumed || consumed !== s.length) throw new ComposeError(`${field}: invalid duration "${s}"`);
  return Math.max(1, Math.round(total));
}

/** Parses "512m", "1g", "1.5GB", 1048576 into bytes. */
export function bytesOf(v: unknown, field: string): number | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === "number") return v;
  const m = /^(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?$/i.exec(String(v).trim());
  if (!m) throw new ComposeError(`${field}: invalid size "${v}"`);
  return Math.round(Number(m[1]) * 1024 ** "_kmgt".indexOf(m[2]!.toLowerCase() || "_"));
}

function env(v: unknown, field: string, vars: Set<string>): string[] {
  let entries: string[] = [];
  if (Array.isArray(v)) entries = strList(v, field);
  else if (isObj(v)) entries = Object.entries(v).map(([k, x]) => (x === null || x === undefined ? k : `${k}=${typeof x === "boolean" ? String(x) : x}`));
  else if (v !== undefined && v !== null) throw new ComposeError(`${field} must be a map or a list`);
  for (const e of entries) {
    if (!e.includes("=")) throw new ComposeError(`${field}: "${e}" has no value (pass-through from the host shell is not supported)`);
    for (const m of e.slice(e.indexOf("=") + 1).matchAll(PLACEHOLDER)) vars.add(m[1]!);
  }
  return entries;
}

function noPlaceholders(v: unknown, path: string) {
  const s = JSON.stringify(v);
  if (s && /\$\{[^}]*\}/.test(s)) throw new ComposeError(`${path}: \${…} placeholders are only supported in environment values`);
}

const UNSUPPORTED = ["build", "env_file", "secrets", "configs", "links", "external_links", "volumes_from", "deploy.replicas", "profiles", "scale"];

/** Parses compose YAML for a stack named `stack`. */
export function parseCompose(text: string, stack: string): ParsedStack {
  if (!NAME.test(stack)) throw new ComposeError("stack name must be lowercase letters, digits, - and _");
  let doc: unknown;
  try {
    doc = parse(text, { maxAliasCount: 50 });
  } catch (e) {
    throw new ComposeError(`YAML: ${(e as Error).message}`);
  }
  if (!isObj(doc) || !isObj(doc.services)) throw new ComposeError("compose file needs a services: map");
  const warnings: string[] = [];
  const vars = new Set<string>();

  // Top-level volumes and networks. Non-external ones are scoped to the stack.
  const volumeNames = new Map<string, string>();
  const externalVolumes = new Set<string>();
  for (const [k, v] of Object.entries(isObj(doc.volumes) ? doc.volumes : {})) {
    const ext = isObj(v) && (v.external === true || isObj(v.external));
    const explicit = isObj(v) && typeof v.name === "string" ? v.name : null;
    const name = explicit ?? (ext ? k : `${stack}_${k}`);
    volumeNames.set(k, name);
    if (ext) externalVolumes.add(name);
  }
  const networkNames = new Map<string, string>();
  for (const [k, v] of Object.entries(isObj(doc.networks) ? doc.networks : {})) {
    const ext = isObj(v) && (v.external === true || isObj(v.external));
    const explicit = isObj(v) && typeof v.name === "string" ? v.name : null;
    networkNames.set(k, explicit ?? (ext || k === EDGE_NETWORK ? k : `${stack}_${k}`));
  }

  const services: ServiceSpec[] = [];
  const expose: Expose[] = [];
  const order = topoSort(doc.services as Obj);

  for (const name of order) {
    const svc = (doc.services as Obj)[name];
    const p = `services.${name}`;
    if (!NAME.test(name)) throw new ComposeError(`${p}: service names must be lowercase letters, digits, - and _`);
    if (!isObj(svc)) throw new ComposeError(`${p} must be a map`);
    for (const key of UNSUPPORTED) {
      const [a, b] = key.split(".");
      if (a! in svc && (!b || (isObj(svc[a!]) && b in (svc[a!] as Obj)))) throw new ComposeError(`${p}.${key} is not supported; use a prebuilt image and environment variables`);
    }
    if (typeof svc.image !== "string" || !svc.image) throw new ComposeError(`${p}.image is required`);
    const { environment, ...rest } = svc;
    noPlaceholders(rest, p);

    const s: ServiceSpec = { service: name, image: svc.image };
    const cmd = command(svc.command, `${p}.command`);
    if (cmd) s.cmd = cmd;
    const ep = command(svc.entrypoint, `${p}.entrypoint`);
    if (ep) s.entrypoint = ep;
    const e = env(environment, `${p}.environment`, vars);
    if (e.length) s.env = e;
    if (svc.labels !== undefined) {
      s.labels = Object.fromEntries(Array.isArray(svc.labels) ? strList(svc.labels, `${p}.labels`).map((l) => [l.split("=")[0]!, l.slice(l.indexOf("=") + 1)]) : Object.entries(svc.labels as Obj).map(([k, v]) => [k, String(v)]));
    }
    if (svc.user !== undefined) s.user = String(svc.user);
    if (typeof svc.working_dir === "string") s.workingDir = svc.working_dir;
    if (typeof svc.hostname === "string") s.hostname = svc.hostname;
    if (svc.restart !== undefined) {
      const r = String(svc.restart).replace(/:\d+$/, "");
      if (!["no", "always", "unless-stopped", "on-failure"].includes(r)) throw new ComposeError(`${p}.restart is invalid`);
      s.restart = r;
    }
    if (typeof svc.pull_policy === "string") {
      const pp = { always: "always", missing: "missing", if_not_present: "missing", never: "never", build: "never" }[svc.pull_policy];
      if (!pp) throw new ComposeError(`${p}.pull_policy is invalid`);
      s.pull = pp;
    }
    if (typeof svc.network_mode === "string") {
      if (!["host", "none", "bridge"].includes(svc.network_mode)) throw new ComposeError(`${p}.network_mode must be host, none or bridge`);
      s.networkMode = svc.network_mode;
    }
    if (typeof svc.pid === "string") s.pidMode = svc.pid;
    if (typeof svc.ipc === "string") s.ipcMode = svc.ipc;

    // Networks: list or map form; "default" is the stack network.
    const nets: string[] = [];
    const aliases: string[] = [];
    const rawNets = svc.networks;
    const netKeys = Array.isArray(rawNets) ? strList(rawNets, `${p}.networks`) : isObj(rawNets) ? Object.keys(rawNets) : [];
    for (const n of netKeys) {
      if (n === "default") continue;
      const mapped = networkNames.get(n) ?? (n === EDGE_NETWORK ? n : null);
      if (!mapped) throw new ComposeError(`${p}.networks: "${n}" is not declared under top-level networks`);
      nets.push(mapped);
      const cfg = isObj(rawNets) ? (rawNets as Obj)[n] : null;
      if (isObj(cfg) && cfg.aliases) aliases.push(...strList(cfg.aliases, `${p}.networks.${n}.aliases`));
    }

    // Mounts.
    const mounts: Mount[] = [];
    for (const v of Array.isArray(svc.volumes) ? svc.volumes : svc.volumes === undefined ? [] : [svc.volumes]) {
      if (typeof v === "string") {
        const parts = v.split(":");
        if (parts.length === 1) {
          mounts.push({ type: "volume", source: undefined, target: parts[0]! });
          warnings.push(`${p}: anonymous volume ${parts[0]} is recreated on every deploy; name it to keep data`);
          continue;
        }
        const [src, target, mode] = parts as [string, string, string?];
        const ro = (mode ?? "").split(",").includes("ro");
        if (src.startsWith("/") || src.startsWith(".") || src.startsWith("~")) {
          if (!src.startsWith("/")) throw new ComposeError(`${p}.volumes: bind sources must be absolute host paths (got ${src})`);
          mounts.push({ type: "bind", source: src, target, readOnly: ro });
        } else {
          const vn = volumeNames.get(src);
          if (!vn) throw new ComposeError(`${p}.volumes: volume "${src}" is not declared under top-level volumes`);
          mounts.push({ type: "volume", source: vn, target, readOnly: ro });
        }
      } else if (isObj(v)) {
        const type = String(v.type ?? "volume");
        const target = String(v.target ?? "");
        if (type === "volume") {
          const src = v.source === undefined ? undefined : String(v.source);
          const vn = src === undefined ? undefined : volumeNames.get(src);
          if (src !== undefined && !vn) throw new ComposeError(`${p}.volumes: volume "${src}" is not declared under top-level volumes`);
          mounts.push({ type: "volume", source: vn, target, readOnly: !!v.read_only });
        } else if (type === "bind" || type === "tmpfs") {
          mounts.push({ type, source: type === "bind" ? String(v.source ?? "") : undefined, target, readOnly: !!v.read_only });
        } else {
          throw new ComposeError(`${p}.volumes: type ${type} is not supported`);
        }
      } else {
        throw new ComposeError(`${p}.volumes entries must be strings or maps`);
      }
    }
    for (const t of strList(svc.tmpfs, `${p}.tmpfs`)) mounts.push({ type: "tmpfs", target: t.split(":")[0]! });
    const anonymous = mounts.filter((m) => m.type === "volume" && !m.source);
    if (anonymous.length) throw new ComposeError(`${p}: anonymous volumes are not supported; declare a named volume`);

    // Ports (published on the host; refused by the default server policy).
    const ports: ServiceSpec["ports"] = [];
    for (const raw of Array.isArray(svc.ports) ? svc.ports : svc.ports === undefined ? [] : [svc.ports]) {
      if (isObj(raw)) {
        ports.push({ containerPort: Number(raw.target), hostPort: Number(raw.published ?? 0), hostIp: raw.host_ip ? String(raw.host_ip) : undefined, protocol: raw.protocol ? String(raw.protocol) : undefined });
        continue;
      }
      const [spec, proto] = String(raw).split("/");
      const parts = spec!.split(":");
      const containerPort = Number(parts.pop());
      const hostPort = Number(parts.pop() ?? 0);
      const hostIp = parts.length ? parts.join(":") : undefined;
      if (!containerPort) throw new ComposeError(`${p}.ports: cannot parse "${raw}" (port ranges are not supported)`);
      ports.push({ containerPort, hostPort, hostIp, protocol: proto });
    }
    if (ports.length) warnings.push(`${p}: published ports are refused by the default server policy; use x-nodescale.expose for HTTP services`);

    // Resources.
    const limits = isObj(svc.deploy) && isObj(svc.deploy.resources) && isObj(svc.deploy.resources.limits) ? svc.deploy.resources.limits : {};
    const memory = bytesOf(svc.mem_limit ?? limits.memory, `${p}.mem_limit`);
    if (memory) s.memory = memory;
    const cpus = svc.cpus ?? limits.cpus;
    if (cpus !== undefined) s.cpus = Number(cpus);
    if (svc.read_only) s.readOnly = true;
    if (svc.privileged) s.privileged = true;
    if (svc.init) s.init = true;
    const capAdd = strList(svc.cap_add, `${p}.cap_add`);
    if (capAdd.length) s.capAdd = capAdd;
    const capDrop = strList(svc.cap_drop, `${p}.cap_drop`);
    if (capDrop.length) s.capDrop = capDrop;
    const devices = strList(svc.devices, `${p}.devices`);
    if (devices.length) s.devices = devices;
    const hosts = Array.isArray(svc.extra_hosts) ? strList(svc.extra_hosts, `${p}.extra_hosts`) : isObj(svc.extra_hosts) ? Object.entries(svc.extra_hosts).map(([k, v]) => `${k}:${v}`) : [];
    if (hosts.length) s.extraHosts = hosts.map((h) => h.replace("=", ":"));
    const stop = duration(svc.stop_grace_period, `${p}.stop_grace_period`);
    if (stop) s.stopTimeout = stop;
    if (isObj(svc.healthcheck)) {
      const h = svc.healthcheck;
      if (h.disable) s.healthcheck = { test: ["NONE"] };
      else {
        const test = typeof h.test === "string" ? ["CMD-SHELL", h.test] : strList(h.test, `${p}.healthcheck.test`);
        s.healthcheck = {
          test,
          interval: duration(h.interval, `${p}.healthcheck.interval`),
          timeout: duration(h.timeout, `${p}.healthcheck.timeout`),
          startPeriod: duration(h.start_period, `${p}.healthcheck.start_period`),
          retries: h.retries === undefined ? undefined : Number(h.retries),
        };
      }
    }

    // nodescale extension: route a public hostname through the tunnel.
    const x = isObj(svc["x-nodescale"]) ? (svc["x-nodescale"] as Obj) : null;
    if (x && isObj(x.expose)) {
      const hostname = String(x.expose.hostname ?? "");
      const port = Number(x.expose.port ?? 0);
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(hostname) || !port) throw new ComposeError(`${p}.x-nodescale.expose needs hostname and port`);
      if (s.networkMode) throw new ComposeError(`${p}: exposed services cannot use network_mode`);
      if (!nets.includes(EDGE_NETWORK)) nets.push(EDGE_NETWORK);
      expose.push({ service: name, container: `${stack}-${name}`, hostname: hostname.toLowerCase(), port });
    }

    if (nets.length) s.networks = nets;
    if (aliases.length) s.aliases = aliases;
    if (mounts.length) s.mounts = mounts;
    if (ports.length) s.ports = ports;
    services.push(s);
  }

  const usedVolumes = new Set(services.flatMap((s) => (s.mounts ?? []).filter((m) => m.type === "volume").map((m) => m.source!)));
  const spec: StackSpec = {
    name: stack,
    services,
    volumes: [...usedVolumes].filter((v) => !externalVolumes.has(v)),
    networks: [...new Set(services.flatMap((s) => s.networks ?? []))],
  };
  return { spec, variables: [...vars].sort(), expose, warnings };
}

/** Orders services so that depends_on targets start first. */
function topoSort(services: Obj): string[] {
  const deps = new Map<string, string[]>();
  for (const [name, svc] of Object.entries(services)) {
    const d = isObj(svc) ? svc.depends_on : undefined;
    deps.set(name, Array.isArray(d) ? d.map(String) : isObj(d) ? Object.keys(d) : []);
  }
  const out: string[] = [];
  const state = new Map<string, number>();
  const visit = (n: string, path: string[]) => {
    if (state.get(n) === 2) return;
    if (state.get(n) === 1) throw new ComposeError(`depends_on cycle: ${[...path, n].join(" → ")}`);
    if (!deps.has(n)) throw new ComposeError(`depends_on refers to unknown service ${n}`);
    state.set(n, 1);
    for (const d of deps.get(n)!) visit(d, [...path, n]);
    state.set(n, 2);
    out.push(n);
  };
  for (const n of deps.keys()) visit(n, []);
  return out;
}

/** Substitutes ${NAME} / ${NAME:-default} in environment values. */
export function interpolateEnv(spec: StackSpec, values: Record<string, string>): StackSpec {
  const missing = new Set<string>();
  const services = spec.services.map((s) => ({
    ...s,
    env: s.env?.map((e) => {
      const i = e.indexOf("=");
      const v = e.slice(i + 1).replace(PLACEHOLDER, (_m, name: string, def?: string) => {
        if (name in values) return values[name]!;
        if (def !== undefined) return def;
        missing.add(name);
        return "";
      });
      return `${e.slice(0, i)}=${v}`;
    }),
  }));
  if (missing.size) throw new ComposeError(`missing values for: ${[...missing].join(", ")}`);
  return { ...spec, services };
}
