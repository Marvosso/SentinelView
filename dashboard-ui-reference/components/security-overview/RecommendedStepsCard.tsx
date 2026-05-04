import Link from "next/link";
import { Cable, FileText, UserRound } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import { withDemoParam } from "@/lib/demo-nav";
import type { OverviewRecommendedRow } from "@/lib/overview-demo-data";
import { StatusPill } from "./StatusPill";

const primaryBtn =
  "inline-flex items-center justify-center rounded-lg bg-sv-accent px-3 py-2 text-xs font-semibold text-white shadow-sm transition-[background-color,box-shadow,transform,color] duration-200 ease-out hover:bg-sv-accent-hover hover:shadow-md hover:-translate-y-px focus:outline-none focus:ring-2 focus:ring-sv-accent focus:ring-offset-2 focus:ring-offset-sv-app active:translate-y-0";
const secondaryBtn =
  "inline-flex items-center justify-center rounded-lg border border-sv-border-muted bg-sv-app px-3 py-2 text-xs font-semibold text-sv-text-secondary transition-[border-color,background-color,color,transform] duration-200 ease-out hover:border-sv-border hover:bg-sv-border/20 hover:text-sv-text hover:-translate-y-px active:translate-y-0";

const ICONS = {
  user: UserRound,
  cable: Cable,
  file: FileText,
} as const;

type RecommendedStepsCardProps = {
  intro: string;
  rows: OverviewRecommendedRow[];
  primaryIndex: number;
  demo?: string | null;
};

export function RecommendedStepsCard({ intro, rows, primaryIndex, demo }: RecommendedStepsCardProps) {
  return (
    <Card className="flex flex-col p-6">
      <SectionLabel>Next steps</SectionLabel>
      <h3 className="mt-1 text-base font-semibold text-sv-text">Recommended Next Steps</h3>
      <p className="mt-1 text-sm text-sv-muted">{intro}</p>

      <ul className="mt-6 divide-y divide-sv-border">
        {rows.map((row, index) => {
          const Icon = ICONS[row.icon];
          const isPrimaryRow = index === primaryIndex;
          return (
            <li key={row.title} className="flex flex-col gap-4 py-5 first:pt-0 sm:flex-row sm:items-start">
              <div className="flex shrink-0">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-sv-border-muted bg-sv-app">
                  <Icon className="h-4 w-4 text-sv-text-secondary" strokeWidth={1.75} />
                </div>
              </div>
              <div className="min-w-0 flex-1 space-y-2">
                <p className="text-sm font-semibold text-sv-text">{row.title}</p>
                <p className="text-sm leading-relaxed text-sv-text-secondary">{row.description}</p>
              </div>
              <div className="flex shrink-0 flex-col items-stretch gap-2 sm:items-end">
                <StatusPill variant={row.pill}>{row.pillLabel}</StatusPill>
                <Link href={withDemoParam(row.href, demo)} className={isPrimaryRow ? primaryBtn : secondaryBtn}>
                  {row.action}
                </Link>
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
