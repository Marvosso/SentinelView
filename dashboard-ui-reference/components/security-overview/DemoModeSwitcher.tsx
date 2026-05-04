"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { isRichDemo, withDemoParam } from "@/lib/demo-nav";

const base =
  "inline-flex items-center rounded-md px-2.5 py-1 text-[11px] font-medium transition-colors duration-200";
const inactive = `${base} text-sv-muted hover:bg-sv-border/25 hover:text-sv-text-secondary`;
const active = `${base} bg-sv-border/35 text-sv-text`;

export function DemoModeSwitcher() {
  const pathname = usePathname() || "/security-overview";
  const sp = useSearchParams();
  const mode = sp.get("demo");
  const isClient = isRichDemo(mode);

  const emptyHref = pathname;
  const sampleHref = withDemoParam(pathname, mode === "full" ? "full" : "client");

  return (
    <div className="mb-6 flex flex-col gap-2 border-b border-sv-border/60 pb-4 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
      <p className="text-[11px] text-sv-muted">
        <span className="font-medium text-sv-text-secondary">Demo:</span> optional sample data for
        walkthroughs.
      </p>
      <div className="flex shrink-0 gap-1 rounded-md bg-sv-app/80 p-0.5">
        <Link href={emptyHref} className={!isClient ? active : inactive}>
          Empty
        </Link>
        <Link href={sampleHref} className={isClient ? active : inactive}>
          Sample client
        </Link>
      </div>
    </div>
  );
}
