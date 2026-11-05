import { useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes } from "react";
import { createStore } from "../lib/store.ts";

export function cx(...c: (string | false | null | undefined)[]) {
  return c.filter(Boolean).join(" ");
}

// ---------------------------------------------------------------------------
// Buttons & inputs

type Variant = "primary" | "secondary" | "danger" | "ghost";

const variants: Record<Variant, string> = {
  primary: "bg-indigo-600 text-white hover:bg-indigo-500 shadow-sm disabled:bg-indigo-600/60",
  secondary: "bg-white text-zinc-800 ring-1 ring-inset ring-zinc-300 hover:bg-zinc-50 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700 dark:hover:bg-zinc-800",
  danger: "bg-red-600 text-white hover:bg-red-500 shadow-sm disabled:bg-red-600/60",
  ghost: "text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100",
};

export function Button({ variant = "secondary", size = "md", loading, children, className, disabled, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: "sm" | "md"; loading?: boolean }) {
  return (
    <button
      type="button"
      disabled={disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:cursor-not-allowed",
        size === "sm" ? "px-2.5 py-1.5 text-xs" : "px-3.5 py-2 text-sm",
        variants[variant],
        className,
      )}
      {...rest}
    >
      {loading && <Spinner className="size-4" />}
      {children}
    </button>
  );
}

/** Button that runs an async action, shows progress and reports errors. */
export function ActionButton({ action, children, ...rest }: Omit<Parameters<typeof Button>[0], "onClick"> & { action: () => Promise<unknown> }) {
  const [busy, setBusy] = useState(false);
  return (
    <Button
      {...rest}
      loading={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await action();
        } catch (e) {
          toastError(e);
        } finally {
          setBusy(false);
        }
      }}
    >
      {children}
    </Button>
  );
}

const field = "block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm ring-1 ring-inset ring-zinc-300 placeholder:text-zinc-400 focus:ring-2 focus:ring-inset focus:ring-indigo-500 dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-700";

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cx(field, className)} {...rest} />;
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={cx(field, "pr-8", className)} {...rest}>
      {children}
    </select>
  );
}

export function Textarea({ className, ...rest }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cx(field, "font-mono", className)} {...rest} />;
}

export function Field({ label, hint, children }: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-medium text-zinc-800 dark:text-zinc-200">{label}</span>
      {children}
      {hint && <span className="block text-xs text-zinc-500 dark:text-zinc-400">{hint}</span>}
    </label>
  );
}

// ---------------------------------------------------------------------------
// Layout primitives

export function Card({ title, actions, children, className, padded = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; padded?: boolean }) {
  return (
    <section className={cx("rounded-xl bg-white ring-1 ring-zinc-200 dark:bg-zinc-900 dark:ring-zinc-800", className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-4 border-b border-zinc-200 px-5 py-3.5 dark:border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{title}</h2>
          <div className="flex items-center gap-2">{actions}</div>
        </header>
      )}
      <div className={padded ? "p-5" : ""}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm text-zinc-500 dark:text-zinc-400">{description}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

const tones = {
  gray: "bg-zinc-100 text-zinc-700 ring-zinc-500/20 dark:bg-zinc-800 dark:text-zinc-300",
  green: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-400",
  yellow: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-400",
  red: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-400",
  blue: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/10 dark:text-indigo-300",
};

export function Badge({ tone = "gray", children }: { tone?: keyof typeof tones; children: ReactNode }) {
  return <span className={cx("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset", tones[tone])}>{children}</span>;
}

export function Spinner({ className = "size-5" }: { className?: string }) {
  return (
    <svg className={cx("animate-spin", className)} viewBox="0 0 24 24" fill="none" aria-hidden>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.25" strokeWidth="4" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="4" strokeLinecap="round" />
    </svg>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-zinc-300 px-6 py-14 text-center dark:border-zinc-700">
      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-zinc-500 dark:text-zinc-400">{children}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Callout({ tone = "blue", title, children }: { tone?: "blue" | "yellow" | "red" | "green"; title?: ReactNode; children: ReactNode }) {
  const c = {
    blue: "bg-indigo-50 text-indigo-900 ring-indigo-200 dark:bg-indigo-500/10 dark:text-indigo-200 dark:ring-indigo-500/20",
    yellow: "bg-amber-50 text-amber-900 ring-amber-200 dark:bg-amber-500/10 dark:text-amber-200 dark:ring-amber-500/20",
    red: "bg-red-50 text-red-900 ring-red-200 dark:bg-red-500/10 dark:text-red-200 dark:ring-red-500/20",
    green: "bg-emerald-50 text-emerald-900 ring-emerald-200 dark:bg-emerald-500/10 dark:text-emerald-200 dark:ring-emerald-500/20",
  }[tone];
  return (
    <div className={cx("rounded-lg px-4 py-3 text-sm ring-1 ring-inset", c)}>
      {title && <p className="mb-0.5 font-semibold">{title}</p>}
      <div className="opacity-90">{children}</div>
    </div>
  );
}

export function Code({ children }: { children: ReactNode }) {
  return <code className="rounded bg-zinc-100 px-1.5 py-0.5 font-mono text-[0.8em] text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">{children}</code>;
}

export function CodeBlock({ code, filename, maxHeight = "24rem" }: { code: string; filename?: string; maxHeight?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="overflow-hidden rounded-lg bg-zinc-950 ring-1 ring-zinc-800">
      <div className="flex items-center justify-between border-b border-zinc-800 px-3 py-1.5">
        <span className="font-mono text-xs text-zinc-400">{filename ?? ""}</span>
        <div className="flex gap-1">
          {filename && (
            <button
              type="button"
              className="rounded px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
              onClick={() => {
                const url = URL.createObjectURL(new Blob([code], { type: "text/plain" }));
                const a = document.createElement("a");
                a.href = url;
                a.download = filename;
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              Download
            </button>
          )}
          <button
            type="button"
            className="rounded px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800"
            onClick={async () => {
              await navigator.clipboard.writeText(code);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>
      <pre className="overflow-auto p-4 font-mono text-xs leading-relaxed text-zinc-100" style={{ maxHeight }}>
        {code}
      </pre>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="mb-5 flex gap-1 border-b border-zinc-200 dark:border-zinc-800">
      {tabs.map((t) => (
        <button
          type="button"
          key={t.id}
          onClick={() => onChange(t.id)}
          className={cx(
            "-mb-px border-b-2 px-3 py-2 text-sm font-medium transition-colors",
            value === t.id ? "border-indigo-500 text-indigo-600 dark:text-indigo-400" : "border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Table({ head, children }: { head: ReactNode[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-zinc-200 text-sm dark:divide-zinc-800">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={i} className="whitespace-nowrap px-5 py-2.5 text-left text-xs font-medium uppercase tracking-wide text-zinc-500">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/70">{children}</tbody>
      </table>
    </div>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx("whitespace-nowrap px-5 py-3 text-zinc-700 dark:text-zinc-300", className)}>{children}</td>;
}

// ---------------------------------------------------------------------------
// Modal

export function Modal({ open, onClose, title, children, footer, wide }: { open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      onCancel={onClose}
      className={cx(
        "m-auto w-full rounded-xl bg-white p-0 text-zinc-900 shadow-2xl ring-1 ring-zinc-200 backdrop:bg-zinc-950/50 backdrop:backdrop-blur-sm dark:bg-zinc-900 dark:text-zinc-100 dark:ring-zinc-800",
        wide ? "max-w-3xl" : "max-w-lg",
      )}
    >
      {open && (
        <>
          <header className="border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
            <h2 className="text-base font-semibold">{title}</h2>
          </header>
          <div className="max-h-[70vh] space-y-4 overflow-y-auto px-6 py-5">{children}</div>
          {footer && <footer className="flex justify-end gap-2 border-t border-zinc-200 px-6 py-3.5 dark:border-zinc-800">{footer}</footer>}
        </>
      )}
    </dialog>
  );
}

// ---------------------------------------------------------------------------
// Confirm dialog (promise based)

interface ConfirmRequest {
  title: string;
  body: ReactNode;
  confirm: string;
  danger?: boolean;
  passkey?: boolean;
  resolve: (ok: boolean) => void;
}
const confirmStore = createStore<{ req: ConfirmRequest | null }>({ req: null });

/**
 * Describes an action before the passkey prompt. Browsers cannot show custom
 * text inside the WebAuthn prompt, so this is where the user sees exactly
 * what their touch will authorise.
 */
export function confirmAction(opts: Omit<ConfirmRequest, "resolve">): Promise<boolean> {
  return new Promise((resolve) => confirmStore.set({ req: { ...opts, resolve } }));
}

export function ConfirmHost() {
  const req = confirmStore.use((s) => s.req);
  const close = (ok: boolean) => {
    req?.resolve(ok);
    confirmStore.set({ req: null });
  };
  return (
    <Modal
      open={!!req}
      onClose={() => close(false)}
      title={req?.title}
      footer={
        <>
          <Button onClick={() => close(false)}>Cancel</Button>
          <Button variant={req?.danger ? "danger" : "primary"} onClick={() => close(true)}>
            {req?.passkey && <KeyIcon />}
            {req?.confirm}
          </Button>
        </>
      }
    >
      <div className="text-sm text-zinc-600 dark:text-zinc-300">{req?.body}</div>
      {req?.passkey && <p className="text-xs text-zinc-500">You will be asked to verify with your passkey. The server checks this signature itself.</p>}
    </Modal>
  );
}

// ---------------------------------------------------------------------------
// Toasts

interface Toast {
  id: number;
  tone: "info" | "error" | "success";
  text: string;
}
const toastStore = createStore<{ toasts: Toast[] }>({ toasts: [] });
let toastId = 0;

export function toast(text: string, tone: Toast["tone"] = "info") {
  const id = ++toastId;
  toastStore.set((s) => ({ toasts: [...s.toasts, { id, tone, text }] }));
  setTimeout(() => toastStore.set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), tone === "error" ? 8000 : 4000);
}

export function toastError(e: unknown) {
  if (e instanceof Error && e.name === "PasskeyCancelled") return;
  if (e instanceof Error && e.message === "Passkey prompt was cancelled") return;
  console.error(e);
  toast(e instanceof Error ? e.message : String(e), "error");
}

export function ToastHost() {
  const toasts = toastStore.use((s) => s.toasts);
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          role="status"
          className={cx(
            "pointer-events-auto rounded-lg px-4 py-3 text-sm shadow-lg ring-1",
            t.tone === "error" && "bg-red-600 text-white ring-red-700",
            t.tone === "success" && "bg-emerald-600 text-white ring-emerald-700",
            t.tone === "info" && "bg-zinc-900 text-white ring-zinc-800 dark:bg-zinc-100 dark:text-zinc-900",
          )}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icons (inline to avoid a runtime dependency)

function Icon({ d, className = "size-4" }: { d: string; className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d={d} />
    </svg>
  );
}

export const KeyIcon = (p: { className?: string }) => <Icon {...p} d="M15.5 7.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0ZM12.5 10.5 4 19v2h3v-2h2v-2h2l1.5-1.5" />;
export const ServerIcon = (p: { className?: string }) => <Icon {...p} d="M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01" />;
export const CloudIcon = (p: { className?: string }) => <Icon {...p} d="M7 18a4 4 0 0 1-.5-7.97A6 6 0 0 1 18 9a4.5 4.5 0 0 1-.5 9H7Z" />;
export const UsersIcon = (p: { className?: string }) => <Icon {...p} d="M16 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1M9 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM22 19v-1a4 4 0 0 0-3-3.87M16 4.13a3 3 0 0 1 0 5.74" />;
export const ListIcon = (p: { className?: string }) => <Icon {...p} d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" />;
export const CogIcon = (p: { className?: string }) => <Icon {...p} d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9c.14.38.37.72.6 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />;
export const LockIcon = (p: { className?: string }) => <Icon {...p} d="M6 11h12v10H6zM8 11V7a4 4 0 1 1 8 0v4" />;
export const ShieldIcon = (p: { className?: string }) => <Icon {...p} d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10ZM9 12l2 2 4-4" />;
export const PlusIcon = (p: { className?: string }) => <Icon {...p} d="M12 5v14M5 12h14" />;
export const RefreshIcon = (p: { className?: string }) => <Icon {...p} d="M21 12a9 9 0 1 1-3-6.7L21 8M21 3v5h-5" />;
