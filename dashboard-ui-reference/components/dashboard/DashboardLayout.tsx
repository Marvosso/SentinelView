"use client";

import { useState, type ReactNode } from "react";
import { Menu, X } from "lucide-react";
import { Sidebar } from "./Sidebar";

export function DashboardLayout({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-sv-app">
      {/* Desktop sidebar */}
      <div className="sticky top-0 hidden h-screen shrink-0 lg:block">
        <Sidebar />
      </div>

      {/* Mobile drawer */}
      <div
        className={`fixed inset-0 z-40 bg-black/60 transition-opacity lg:hidden ${
          mobileOpen ? "opacity-100" : "pointer-events-none opacity-0"
        }`}
        aria-hidden={!mobileOpen}
        onClick={() => setMobileOpen(false)}
      />
      <div
        className={`fixed inset-y-0 left-0 z-50 flex h-screen w-[280px] transform flex-col border-r border-sv-border bg-sv-sidebar shadow-xl transition-transform duration-200 ease-out lg:hidden ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-14 shrink-0 items-center justify-end border-b border-sv-border px-3">
          <button
            type="button"
            className="rounded-lg p-2 text-sv-text-secondary hover:bg-sv-border/40 hover:text-sv-text"
            onClick={() => setMobileOpen(false)}
            aria-label="Close menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">
          <Sidebar variant="drawer" onNavigate={() => setMobileOpen(false)} />
        </div>
      </div>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 items-center gap-3 border-b border-sv-border bg-sv-app px-4 lg:hidden">
          <button
            type="button"
            className="rounded-lg p-2 text-sv-text-secondary hover:bg-sv-border/30 hover:text-sv-text"
            onClick={() => setMobileOpen(true)}
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="text-sm font-semibold text-sv-text">SentinelView</span>
        </header>

        <main className="flex-1">{children}</main>
      </div>
    </div>
  );
}
