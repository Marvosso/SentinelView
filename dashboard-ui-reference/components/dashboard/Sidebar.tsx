"use client";

import { Suspense } from "react";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { ChevronDown } from "lucide-react";
import { NAV_GROUPS } from "./navConfig";
import { isRichDemo, withDemoParam } from "@/lib/demo-nav";
import { getMockWorkspace } from "@/lib/mock-workspace";

type SidebarProps = {
  onNavigate?: () => void;
  variant?: "default" | "drawer";
};

function SidebarInner({ onNavigate, variant = "default" }: SidebarProps) {
  const pathname = usePathname();
  const sp = useSearchParams();
  const demo = sp.get("demo");
  const rich = isRichDemo(demo);
  const ws = getMockWorkspace(demo);

  const edge = variant === "drawer" ? "" : "border-r border-sv-border";

  return (
    <aside className={`flex h-full min-h-0 w-[280px] shrink-0 flex-col bg-sv-sidebar ${edge}`}>
      <div className="border-b border-sv-border px-5 py-6">
        <div className="text-lg font-semibold tracking-tight text-sv-text">SentinelView</div>
        <p className="mt-1 text-xs font-medium text-sv-muted">
          Governance <span className="text-sv-border-muted">•</span> Risk{" "}
          <span className="text-sv-border-muted">•</span> Compliance
        </p>
      </div>

      <div className="px-4 py-4">
        <label className="mb-2 block text-[10px] font-semibold uppercase tracking-wider text-sv-muted">
          Workspace
        </label>
        <div className="rounded-xl border border-sv-border bg-sv-card p-3 shadow-sv-card">
          <div className="flex items-center gap-2">
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-sv-success shadow-[0_0_0_3px_rgba(34,197,94,0.25)]"
              aria-hidden
            />
            {rich ? (
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium text-sv-text">{ws.workspaceLabel}</p>
                <p className="mt-0.5 text-[11px] text-sv-muted">Sample workspace (demo)</p>
              </div>
            ) : (
              <div className="relative min-w-0 flex-1">
                <select
                  className="w-full cursor-pointer appearance-none truncate rounded-md border border-sv-border-muted bg-sv-app py-1.5 pl-2 pr-7 text-sm font-medium text-sv-text focus:border-sv-accent focus:outline-none focus:ring-1 focus:ring-sv-accent"
                  defaultValue="demo_client"
                  aria-label="Select workspace"
                >
                  <option value="demo_client">demo_client</option>
                </select>
                <ChevronDown
                  className="pointer-events-none absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-sv-muted"
                  aria-hidden
                />
              </div>
            )}
          </div>
          <p className="mt-2 text-[11px] text-sv-muted">Connection active</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 pb-6">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="mb-6">
            <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-wider text-sv-muted">
              {group.title}
            </p>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                const href = withDemoParam(item.href, demo);
                return (
                  <li key={item.href}>
                    <Link
                      href={href}
                      onClick={onNavigate}
                      className={`group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-[background-color,color,border-color,box-shadow] duration-200 ease-out ${
                        active
                          ? "border-l-[3px] border-sv-accent bg-indigo-950/25 text-sv-text shadow-[inset_0_0_0_1px_rgba(79,70,229,0.12)]"
                          : "border-l-[3px] border-transparent text-sv-text-secondary hover:bg-sv-border/25 hover:text-sv-text"
                      }`}
                    >
                      <Icon
                        className={`h-4 w-4 shrink-0 transition-colors duration-200 ${active ? "text-indigo-300" : "text-sv-muted group-hover:text-sv-text-secondary"}`}
                        strokeWidth={1.75}
                      />
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  );
}

function SidebarFallback({ variant = "default" }: Pick<SidebarProps, "variant">) {
  const edge = variant === "drawer" ? "" : "border-r border-sv-border";
  return (
    <aside
      className={`flex h-full min-h-0 w-[280px] shrink-0 flex-col bg-sv-sidebar ${edge}`}
      aria-hidden
    >
      <div className="h-full animate-pulse border-b border-sv-border px-5 py-6">
        <div className="h-5 w-32 rounded bg-sv-border/50" />
      </div>
    </aside>
  );
}

export function Sidebar(props: SidebarProps) {
  return (
    <Suspense fallback={<SidebarFallback variant={props.variant} />}>
      <SidebarInner {...props} />
    </Suspense>
  );
}
