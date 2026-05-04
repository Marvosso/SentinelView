import type { ReactNode } from "react";

type Variant = "recommended" | "ready" | "next";

const styles: Record<Variant, string> = {
  recommended:
    "border-sv-border-muted bg-sv-app text-sv-text-secondary",
  ready: "border-emerald-900/50 bg-emerald-950/30 text-emerald-200/90",
  next: "border-sv-border-muted bg-sv-border/20 text-sv-text-secondary",
};

export function StatusPill({ children, variant }: { children: ReactNode; variant: Variant }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${styles[variant]}`}
    >
      {children}
    </span>
  );
}
