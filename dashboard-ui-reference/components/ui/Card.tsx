import type { HTMLAttributes } from "react";

type CardProps = HTMLAttributes<HTMLDivElement>;

export function Card({ className = "", children, ...rest }: CardProps) {
  return (
    <div
      className={`rounded-2xl border border-sv-border bg-sv-card p-6 shadow-sv-card transition-[border-color,box-shadow,transform] duration-200 ease-out hover:border-sv-border-muted hover:shadow-[0_12px_40px_-16px_rgba(0,0,0,0.55)] ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
}
