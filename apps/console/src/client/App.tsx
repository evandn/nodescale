import { useEffect, useState, type ReactNode } from "react";
import { Badge, Button, Callout, CloudIcon, CodeBlock, ConfirmHost, CogIcon, Field, Input, ListIcon, LockIcon, Modal, ServerIcon, ShieldIcon, Spinner, ToastHost, UsersIcon, cx, toastError } from "./components/ui.tsx";
import { app, lock, register, renewSession, sessionValid, setupVault, signIn, signOut, unlockWithRecoveryKey } from "./lib/app.ts";
import { formatDuration, useNow } from "./lib/hooks.ts";
import { Link, matchPath, navigate, useLocation } from "./lib/router.tsx";
import { webauthnSupported } from "./lib/webauthn.ts";
import { AuditPage } from "./pages/Audit.tsx";
import { AddServerPage } from "./pages/AddServer.tsx";
import { ServerPage } from "./pages/server/index.tsx";
import { ServersPage } from "./pages/Servers.tsx";
import { SettingsPage } from "./pages/Settings.tsx";
import { TeamPage } from "./pages/Team.tsx";
import { TunnelsPage } from "./pages/Tunnels.tsx";

export function App() {
  const s = app.use((s) => s);
  let body: ReactNode;
  if (!s.booted) body = <FullScreen><Spinner className="size-6 text-zinc-400" /></FullScreen>;
  else if (!s.me) body = <AuthScreen />;
  else if (!s.session && s.vault.status !== "unlocked") body = <UnlockScreen name={s.me.user.name} />;
  else if (s.vault.status === "missing") body = <VaultSetupScreen />;
  else if (s.vault.status === "locked") body = <RecoveryScreen />;
  else body = <Shell />;
  return (
    <>
      {body}
      <RecoveryKeyDialog />
      <ConfirmHost />
      <ToastHost />
    </>
  );
}

function FullScreen({ children }: { children: ReactNode }) {
  return <div className="flex min-h-dvh items-center justify-center px-4 py-12">{children}</div>;
}

function Logo({ className = "" }: { className?: string }) {
  return (
    <div className={cx("flex items-center gap-2 font-semibold tracking-tight", className)}>
      <span className="grid size-7 place-items-center rounded-lg bg-indigo-600 text-white">
        <ShieldIcon className="size-4" />
      </span>
      nodescale
    </div>
  );
}

function AuthCard({ title, subtitle, children }: { title: string; subtitle?: ReactNode; children: ReactNode }) {
  return (
    <FullScreen>
      <div className="w-full max-w-sm">
        <Logo className="mb-8 justify-center text-lg text-zinc-900 dark:text-zinc-100" />
        <div className="rounded-2xl bg-white p-7 shadow-sm ring-1 ring-zinc-200 dark:bg-zinc-900 dark:ring-zinc-800">
          <h1 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">{subtitle}</p>}
          <div className="mt-6 space-y-4">{children}</div>
        </div>
      </div>
    </FullScreen>
  );
}

function AuthScreen() {
  const loc = useLocation();
  const invite = new URLSearchParams(loc.split("?")[1] ?? "").get("invite");
  const [mode, setMode] = useState<"signin" | "signup">(invite ? "signup" : "signin");
  const [name, setName] = useState("");
  const [label, setLabel] = useState(guessDevice());
  const [busy, setBusy] = useState(false);

  if (!webauthnSupported()) {
    return (
      <AuthCard title="Passkeys required">
        <Callout tone="yellow">This browser does not support passkeys (WebAuthn). Use a current version of Chrome, Safari, Edge or Firefox.</Callout>
      </AuthCard>
    );
  }

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
      navigate("/", true);
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };

  if (mode === "signup") {
    return (
      <AuthCard title={invite ? "Join workspace" : "Create your account"} subtitle="nodescale uses passkeys only. Your passkey signs every action on your servers.">
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => register(name.trim(), label.trim() || "Passkey", invite));
          }}
        >
          <Field label="Your name">
            <Input value={name} onChange={(e) => setName(e.target.value)} required maxLength={80} autoFocus autoComplete="name" />
          </Field>
          <Field label="Passkey name" hint="Helps you tell devices apart, e.g. “MacBook Touch ID” or “YubiKey 5C”.">
            <Input value={label} onChange={(e) => setLabel(e.target.value)} maxLength={80} />
          </Field>
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            Create passkey
          </Button>
        </form>
        <p className="text-center text-sm text-zinc-500">
          Already have an account?{" "}
          <button type="button" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => setMode("signin")}>
            Sign in
          </button>
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Sign in" subtitle="Use the passkey on this device or a security key.">
      <Button variant="primary" className="w-full" loading={busy} onClick={() => void run(() => signIn())}>
        Sign in with passkey
      </Button>
      <p className="text-center text-sm text-zinc-500">
        New here?{" "}
        <button type="button" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => setMode("signup")}>
          Create an account
        </button>
      </p>
    </AuthCard>
  );
}

function guessDevice() {
  const ua = navigator.userAgent;
  if (/iPhone|iPad/.test(ua)) return "iPhone passkey";
  if (/Mac/.test(ua)) return "Mac passkey";
  if (/Android/.test(ua)) return "Android passkey";
  if (/Windows/.test(ua)) return "Windows Hello";
  return "Passkey";
}

function UnlockScreen({ name }: { name: string }) {
  const [busy, setBusy] = useState(false);
  return (
    <AuthCard title={`Welcome back, ${name}`} subtitle="Keys are never stored in the browser. Verify with your passkey to unlock this session.">
      <Button
        variant="primary"
        className="w-full"
        loading={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await signIn();
          } catch (e) {
            toastError(e);
          } finally {
            setBusy(false);
          }
        }}
      >
        <LockIcon /> Unlock with passkey
      </Button>
      <Button variant="ghost" className="w-full" onClick={() => void signOut()}>
        Sign out
      </Button>
    </AuthCard>
  );
}

function VaultSetupScreen() {
  const [busy, setBusy] = useState(false);
  return (
    <AuthCard title="Set up your vault" subtitle="Your Tailscale and Cloudflare credentials will be encrypted in this browser with a key derived from your passkey. The server only ever stores ciphertext.">
      <Button
        variant="primary"
        className="w-full"
        loading={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await setupVault();
          } catch (e) {
            toastError(e);
          } finally {
            setBusy(false);
          }
        }}
      >
        Create encrypted vault
      </Button>
    </AuthCard>
  );
}

function RecoveryScreen() {
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <AuthCard
      title="Unlock your vault"
      subtitle="This passkey cannot unlock the vault on its own (its authenticator may not support the PRF extension, or it was added on another device). Enter your recovery key. This passkey will be able to unlock the vault from now on."
    >
      <form
        className="space-y-4"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          try {
            await unlockWithRecoveryKey(code);
          } catch (err) {
            toastError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <Field label="Recovery key">
          <Input value={code} onChange={(e) => setCode(e.target.value)} placeholder="NSRK-XXXX-XXXX-…" className="font-mono" autoFocus spellCheck={false} autoComplete="off" />
        </Field>
        <Button type="submit" variant="primary" className="w-full" loading={busy}>
          Unlock
        </Button>
      </form>
      <Button variant="ghost" className="w-full" onClick={() => void signIn()}>
        Try a different passkey
      </Button>
    </AuthCard>
  );
}

function RecoveryKeyDialog() {
  const key = app.use((s) => s.pendingRecoveryKey);
  const [ack, setAck] = useState(false);
  return (
    <Modal
      open={!!key}
      onClose={() => {}}
      title="Save your recovery key"
      footer={
        <Button variant="primary" disabled={!ack} onClick={() => app.set({ pendingRecoveryKey: null })}>
          I have stored it safely
        </Button>
      }
    >
      <p className="text-sm text-zinc-600 dark:text-zinc-300">
        This key can unlock your vault if you lose your passkeys or use one that does not support vault unlock. It is shown once and nodescale cannot recover it. Store it in a password manager or print it.
      </p>
      {key && <CodeBlock code={key} />}
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
        I saved my recovery key
      </label>
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Signed-in shell

const NAV = [
  { to: "/servers", label: "Servers", icon: ServerIcon },
  { to: "/tunnels", label: "Tunnels", icon: CloudIcon },
  { to: "/team", label: "Team", icon: UsersIcon },
  { to: "/audit", label: "Audit log", icon: ListIcon },
  { to: "/settings", label: "Settings", icon: CogIcon },
];

/** Forget all keys after this long without interaction. */
const IDLE_LOCK_MS = 30 * 60 * 1000;

function useIdleLock() {
  useEffect(() => {
    let last = Date.now();
    const touch = () => {
      last = Date.now();
    };
    const events = ["pointerdown", "keydown", "wheel", "touchstart"] as const;
    events.forEach((e) => window.addEventListener(e, touch, { passive: true }));
    const t = setInterval(() => {
      if (Date.now() - last > IDLE_LOCK_MS) lock();
    }, 30_000);
    return () => {
      events.forEach((e) => window.removeEventListener(e, touch));
      clearInterval(t);
    };
  }, []);
}

function Shell() {
  useIdleLock();
  const loc = useLocation();
  const path = loc.split("?")[0]!;
  const me = app.use((s) => s.me)!;

  let page: ReactNode;
  let params: Record<string, string> | null;
  if (path === "/" || path === "/servers") page = <ServersPage />;
  else if (path === "/servers/new") page = <AddServerPage />;
  else if ((params = matchPath("/servers/:id", path))) page = <ServerPage id={params.id!} />;
  else if (path === "/tunnels") page = <TunnelsPage />;
  else if (path === "/team") page = <TeamPage />;
  else if (path === "/audit") page = <AuditPage />;
  else if (path === "/settings") page = <SettingsPage />;
  else page = <p className="text-sm text-zinc-500">Page not found.</p>;

  return (
    <div className="flex min-h-dvh">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-zinc-200 bg-white px-3 py-5 md:flex dark:border-zinc-800 dark:bg-zinc-900">
        <Logo className="px-2 text-zinc-900 dark:text-zinc-100" />
        <p className="mt-1 truncate px-2 text-xs text-zinc-500">{me.workspace.name}</p>
        <nav className="mt-6 flex flex-1 flex-col gap-0.5">
          {NAV.map((n) => {
            const active = path === n.to || path.startsWith(n.to + "/") || (n.to === "/servers" && path === "/");
            return (
              <Link
                key={n.to}
                to={n.to}
                className={cx(
                  "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm font-medium transition-colors",
                  active ? "bg-zinc-100 text-zinc-900 dark:bg-zinc-800 dark:text-zinc-50" : "text-zinc-600 hover:bg-zinc-50 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800/60 dark:hover:text-zinc-100",
                )}
              >
                <n.icon className="size-4" />
                {n.label}
              </Link>
            );
          })}
        </nav>
        <SessionPanel />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-zinc-200 bg-white px-4 py-3 md:hidden dark:border-zinc-800 dark:bg-zinc-900">
          <Logo className="text-zinc-900 dark:text-zinc-100" />
          <select className="rounded-md bg-transparent text-sm" value={NAV.find((n) => path.startsWith(n.to))?.to ?? "/servers"} onChange={(e) => navigate(e.target.value)}>
            {NAV.map((n) => (
              <option key={n.to} value={n.to}>
                {n.label}
              </option>
            ))}
          </select>
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-8">{page}</main>
      </div>
    </div>
  );
}

function SessionPanel() {
  const s = app.use((s) => s);
  const now = useNow();
  const valid = sessionValid(s.session, 0);
  const left = s.session ? s.session.exp - now : 0;
  return (
    <div className="space-y-3 rounded-xl bg-zinc-50 p-3 text-xs ring-1 ring-zinc-200 dark:bg-zinc-950 dark:ring-zinc-800">
      <div className="flex items-center justify-between">
        <span className="font-medium text-zinc-700 dark:text-zinc-300">Operations session</span>
        {valid ? <Badge tone="green">{s.session!.scope}</Badge> : <Badge tone="yellow">locked</Badge>}
      </div>
      <p className="text-zinc-500">{valid ? `Expires in ${formatDuration(left)}` : "Read and operate actions will ask for your passkey."}</p>
      <div className="flex gap-1.5">
        <Button size="sm" className="flex-1" onClick={() => void renewSession().catch(toastError)}>
          {valid ? "Renew" : "Unlock"}
        </Button>
        <Button size="sm" variant="ghost" onClick={lock} title="Forget all keys in this tab">
          <LockIcon /> Lock
        </Button>
      </div>
      <div className="flex items-center justify-between border-t border-zinc-200 pt-2.5 dark:border-zinc-800">
        <span className="truncate text-zinc-600 dark:text-zinc-400">{s.me?.user.name}</span>
        <button type="button" className="text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100" onClick={() => void signOut()}>
          Sign out
        </button>
      </div>
    </div>
  );
}
