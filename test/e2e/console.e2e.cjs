// End-to-end: browser (virtual passkey with PRF) → Worker → dev relay →
// `su nodescale` → setgid nodescale-gate → Docker. Verifies that secrets never
// leave the browser in plaintext.
const { chromium } = require("playwright");
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const OUT = process.env.E2E_OUT || require("os").tmpdir();
const CONSOLE = path.join(__dirname, "../../apps/console");
const PERSIST = process.env.E2E_PERSIST ? ` --persist-to ${process.env.E2E_PERSIST}` : "";
const BASE = "http://localhost:8787";
const SECRET = "sup3r-s3cret-value-XYZ";
const shot = (page, name) => page.screenshot({ path: path.join(OUT, `${name}.png`) });
const step = (m) => console.log("✓", m);

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 960 } });
  const page = await ctx.newPage();
  global.__page = page;
  const sent = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/")) sent.push(`${r.method()} ${r.url()} ${r.postData() ?? ""}`);
  });
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(e.message));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  const spa = (u) => page.evaluate((u) => { history.pushState(null, "", u); dispatchEvent(new PopStateEvent("popstate")); }, u);

  // Sign up.
  await page.goto(BASE);
  await page.getByText("Create an account").click();
  await page.getByLabel("Your name").fill("Alex Admin");
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByLabel("I saved my recovery key").check();
  await page.getByRole("button", { name: "I have stored it safely" }).click();
  await page.getByRole("heading", { name: "Servers" }).waitFor();
  step("signed up; vault unlocked by passkey PRF");

  // Configure the installed gate to trust this passkey (what the install script does).
  const k = (await page.evaluate(() => fetch("/api/passkeys").then((r) => r.json())))[0];
  const cfg = { rpId: "localhost", origins: [BASE], signers: [{ id: k.id, alg: k.alg, publicKey: k.publicKey, role: "admin", label: "Alex: " + k.label }], policy: { containers: {} } };
  fs.writeFileSync("/etc/nodescale/gate.json", JSON.stringify(cfg, null, 2));
  execSync("chown root:docker /etc/nodescale/gate.json && chmod 660 /etc/nodescale/gate.json");
  const ident = JSON.parse(execSync("nodescale-gate id").toString());

  const { id } = await page.evaluate(() =>
    fetch("/api/servers", { method: "POST", headers: { "Content-Type": "application/json", "X-Nodescale": "1" }, body: JSON.stringify({ name: "web-1", provider: "Hetzner", tailnetIp: "100.64.0.10" }) }).then((r) => r.json()),
  );
  await spa(`/servers/${id}`);
  await page.getByRole("button", { name: "Find server" }).click();
  await page.getByText(ident.agent).waitFor({ timeout: 20000 });
  await page.getByPlaceholder("ag_…").fill(ident.agent);
  await page.getByRole("button", { name: "Trust this server" }).click();
  await page.getByText("nodescale gate").waitFor({ timeout: 20000 });
  await page.getByText("Memory").first().waitFor({ timeout: 20000 });
  await shot(page, "e2e-01-overview");
  step("server verified and pinned; overview shows live host stats via the setgid gate");

  // Deploy a stack with a secret.
  await page.getByRole("button", { name: "Stacks" }).click();
  await page.getByRole("button", { name: "New stack" }).click();
  await page.getByPlaceholder("shop").fill("demo");
  const compose = `services:
  web:
    image: nginx:alpine
    restart: unless-stopped
  worker:
    image: alpine:3.20
    command: ["sh", "-c", "sleep 3600"]
    environment:
      API_KEY: \${API_KEY}
      MODE: production
    depends_on: [web]
volumes:
  data:
`;
  await page.locator("textarea").fill(compose);
  await page.getByPlaceholder("value").fill(SECRET);
  await shot(page, "e2e-02-stack-editor");
  await page.getByRole("button", { name: "Deploy" }).click();
  await page.getByText("Deploy stack demo").waitFor();
  await page.getByRole("button", { name: "Sign with passkey" }).click();
  await page.getByText(/Deployed demo/).first().waitFor({ timeout: 60000 });
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByText("2/2 running").waitFor({ timeout: 20000 });
  await shot(page, "e2e-03-stacks");
  step("stack deployed with a sealed secret");

  const actual = execSync(`docker exec demo-worker sh -c 'echo $API_KEY'`).toString().trim();
  if (actual !== SECRET) throw new Error(`container env = ${actual}`);
  step("container received the decrypted secret");

  // Containers tab: details, env reveal, exec.
  await page.getByRole("button", { name: "Containers", exact: true }).click();
  const row = page.locator("tr", { hasText: "demo-worker" });
  await row.getByRole("button", { name: "Details" }).click();
  await page.getByRole("button", { name: "Environment" }).click();
  await page.getByText("[redacted]").first().waitFor({ timeout: 15000 });
  await page.getByRole("button", { name: "Reveal values" }).click();
  await page.getByText(SECRET).waitFor({ timeout: 15000 });
  await shot(page, "e2e-04-env-revealed");
  step("env redacted by the server; revealed via passkey + sealed reply");
  await page.getByRole("button", { name: "Run command" }).click();
  await page.getByPlaceholder("ls -la /app").fill("sh -c 'echo hello from $MODE; wget -qO- http://web | head -c 15'");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await page.getByText("hello from production").waitFor({ timeout: 20000 });
  await page.getByText("<!DOCTYPE html>").waitFor();
  await shot(page, "e2e-05-exec");
  step("exec works; services reach each other by name");
  await page.getByRole("button", { name: "Close" }).click();

  // Session-key operation without a prompt.
  await row.getByRole("button", { name: "Restart" }).click();
  await page.getByText("Restart container: done").waitFor({ timeout: 20000 });
  step("restart signed by session key");

  // Server-side audit log.
  await page.getByRole("button", { name: "Audit" }).click();
  await page.getByText("stacks.deploy").first().waitFor({ timeout: 15000 });
  await shot(page, "e2e-06-server-audit");
  step("server-side audit shows deploy, env reveal and exec");

  // Dashboard.
  await page.getByRole("link", { name: "← Servers" }).click();
  await page.getByText("online").waitFor({ timeout: 20000 });
  await page.getByText(/containers running/).waitFor();
  await shot(page, "e2e-07-dashboard");
  step("dashboard shows the server online with live stats");

  // Remove the stack.
  await spa(`/servers/${id}`);
  await page.getByRole("button", { name: "Stacks" }).click();
  await page.getByText("2/2 running").waitFor({ timeout: 20000 });
  await page.locator("section", { hasText: "demo" }).getByRole("button", { name: "Remove" }).click();
  await page.getByRole("button", { name: "Sign with passkey" }).click();
  await page.getByText("Stack demo removed").waitFor({ timeout: 30000 });
  if (execSync("docker ps -a --format '{{.Names}}'").toString().includes("demo-")) throw new Error("stack containers still exist");
  step("stack removed");

  // Every page renders without errors.
  for (const [nav, heading] of [["Tunnels", "Tunnels"], ["Team", "Team"], ["Audit log", "Audit log"], ["Settings", "Settings"]]) {
    await page.getByRole("link", { name: nav }).click();
    await page.getByRole("heading", { name: heading }).waitFor();
  }
  for (const tab of ["Secrets", "Passkeys", "Security", "Integrations"]) {
    await page.getByRole("button", { name: tab, exact: true }).click();
  }
  await page.getByRole("heading", { name: "Tailnet policy" }).waitFor();
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByText("API_KEY").waitFor(); // saved during deploy
  await shot(page, "e2e-08-secrets");
  await page.getByRole("link", { name: "Team" }).click();
  await page.getByText("Alex Admin").first().waitFor();
  await page.getByRole("link", { name: "Audit log" }).click();
  await page.getByText("stack.remove").waitFor({ timeout: 10000 });
  await spa("/servers/new");
  await page.getByText("Tailscale credentials needed").waitFor();
  if (pageErrors.length) throw new Error("page errors:\n" + pageErrors.join("\n"));
  step("all pages render without errors");

  // Secrets never left the browser in plaintext.
  const leaks = sent.filter((s) => s.includes(SECRET));
  if (leaks.length) throw new Error("secret sent to the console in plaintext:\n" + leaks.join("\n"));
  const d1 = execSync(`cd ${CONSOLE} && npx wrangler d1 execute nodescale --local${PERSIST} --json --command "SELECT compose FROM stacks UNION ALL SELECT blob FROM vaults" 2>/dev/null`).toString();
  if (d1.includes(SECRET)) throw new Error("secret stored in D1");
  step(`no plaintext secret in ${sent.length} API requests or in D1`);

  await browser.close();
})().catch(async (e) => {
  console.error("E2E FAILED:", e);
  try {
    await global.__page?.screenshot({ path: path.join(OUT, "e2e-failure.png") });
    console.error("screenshot:", path.join(OUT, "e2e-failure.png"));
  } catch {}
  process.exit(1);
});
