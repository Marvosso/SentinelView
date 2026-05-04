import type { ReactNode } from "react";

type SectionLabelProps = {
  children: ReactNode;
  className?: string;
};

/** Uppercase eyebrow — use across page for one rhythm. */
export function SectionLabel({ children, className = "" }: SectionLabelProps) {
  return (
    <p
      className={`text-[11px] font-semibold uppercase tracking-[0.14em] text-sv-muted ${className}`}
    >
      {children}
    </p>
  );
}
