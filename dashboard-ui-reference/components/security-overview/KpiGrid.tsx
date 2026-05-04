import { Calendar, ClipboardCheck, ListChecks, Radio } from "lucide-react";
import { Card } from "@/components/ui/Card";
import type { OverviewKpiItem, OverviewKpiTrendTone } from "@/lib/overview-demo-data";

const KPI_ICONS = [ListChecks, Radio, ClipboardCheck, Calendar] as const;

type KpiGridProps = {
  items: OverviewKpiItem[];
};

function trendClass(tone: OverviewKpiTrendTone | undefined): string {
  if (tone === "positive") return "text-emerald-400/90";
  if (tone === "attention") return "text-amber-200/85";
  return "text-sv-muted";
}

function issuesOpenCount(row: OverviewKpiItem): number {
  if (!row.label.includes("Issues")) return 0;
  const n = parseInt(String(row.value).replace(/\D/g, ""), 10);
  return Number.isFinite(n) ? n : 0;
}

export function KpiGrid({ items }: KpiGridProps) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
      {items.map((row, index) => {
        const Icon = KPI_ICONS[index] ?? ListChecks;
        const warn = row.tone === "warn";
        const openIssues = issuesOpenCount(row);
        const emphasizeIssues = openIssues > 0;
        return (
          <Card
            key={row.label}
            className={`group flex min-h-[168px] flex-col p-5 ${
              emphasizeIssues
                ? "border-amber-900/45 bg-amber-950/[0.12] ring-1 ring-amber-900/25"
                : warn
                  ? "border-amber-900/40 ring-1 ring-amber-900/20"
                  : ""
            }`}
          >
            <div className="mb-4 flex h-9 w-9 items-center justify-center rounded-lg border border-sv-border-muted bg-sv-app transition-colors duration-200 group-hover:border-sv-border-muted">
              <Icon className="h-4 w-4 text-sv-muted" strokeWidth={1.75} />
            </div>
            <p className="text-[11px] font-semibold uppercase tracking-wider text-sv-muted">{row.label}</p>
            <div className="mt-2 flex flex-wrap items-end justify-between gap-x-2 gap-y-1">
              <p className="text-2xl font-semibold tabular-nums tracking-tight text-sv-text">{row.value}</p>
              {row.trend ? (
                <p className={`text-[11px] font-medium tabular-nums ${trendClass(row.trendTone)}`}>
                  {row.trend}
                </p>
              ) : null}
            </div>
            <p className="mt-auto border-t border-sv-border/60 pt-3 text-xs leading-relaxed text-sv-muted">
              {row.helper}
            </p>
          </Card>
        );
      })}
    </div>
  );
}
