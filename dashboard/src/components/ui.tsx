import type { ButtonHTMLAttributes, ReactNode } from "react";

export function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}) {
  const variants: Record<string, string> = {
    primary: "bg-indigo-500 hover:bg-indigo-400 text-white",
    secondary: "bg-slate-700 hover:bg-slate-600 text-slate-100",
    danger: "bg-rose-600 hover:bg-rose-500 text-white",
    ghost: "bg-transparent hover:bg-slate-800 text-slate-300",
  };
  return (
    <button
      className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
    expired: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
    revoked: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
    pending: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
    approved: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
    denied: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
    timed_out: "bg-amber-500/15 text-amber-300 ring-amber-500/30",
  };
  const cls = map[status] ?? "bg-slate-500/15 text-slate-300 ring-slate-500/30";
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${cls}`}>
      {status}
    </span>
  );
}

export function Pill({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex items-center rounded bg-slate-800 px-1.5 py-0.5 text-xs font-mono text-slate-300">
      {children}
    </span>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/50 ${className}`}>
      {children}
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-400">
      <span className="h-3 w-3 animate-spin rounded-full border-2 border-slate-600 border-t-indigo-400" />
      Loading...
    </div>
  );
}

export function ErrorNote({ error }: { error: unknown }) {
  const e = error as { code?: string; message?: string; suggestion?: string };
  return (
    <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
      <div className="font-medium">{e?.message ?? "Something went wrong."}</div>
      {e?.code && <div className="mt-0.5 font-mono text-xs opacity-70">{e.code}</div>}
      {e?.suggestion && <div className="mt-1 text-rose-300/90">{e.suggestion}</div>}
    </div>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
      {children}
    </div>
  );
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  const d = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}
