import Link from "next/link";
import { Check } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import { withDemoParam } from "@/lib/demo-nav";
import type { OverviewHeroData } from "@/lib/overview-demo-data";

type HeroCardProps = {
  data: OverviewHeroData;
  /** Preserve mock workspace when navigating (pass `searchParams.demo`). */
  demo?: string | null;
};

export function HeroCard({ data, demo }: HeroCardProps) {
  const dotClass =
    data.monitoringTone === "success" ? "bg-sv-success shadow-[0_0_0_3px_rgba(34,197,94,0.2)]" : "bg-sv-warning";

  return (
    <Card className="p-6 lg:p-8">
      <div className="flex flex-col gap-8 lg:flex-row lg:items-start lg:justify-between lg:gap-10">
        <div className="min-w-0 flex-1 space-y-4">
          <SectionLabel>System status</SectionLabel>
          <h2 className="text-2xl font-semibold tracking-tight text-sv-text sm:text-3xl">{data.title}</h2>
          <p className="max-w-xl text-sm leading-relaxed text-sv-text-secondary">{data.body}</p>
          <div>
            <Link
              href={withDemoParam(data.cta.href, demo)}
              className="inline-flex items-center justify-center rounded-lg bg-sv-accent px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition-[background-color,box-shadow,transform] duration-200 ease-out hover:bg-sv-accent-hover hover:shadow-md hover:-translate-y-px focus:outline-none focus:ring-2 focus:ring-sv-accent focus:ring-offset-2 focus:ring-offset-sv-app active:translate-y-0"
            >
              {data.cta.label}
            </Link>
          </div>
        </div>

        <div className="w-full shrink-0 space-y-6 border-t border-sv-border pt-6 lg:w-72 lg:border-l lg:border-t-0 lg:pl-8 lg:pt-0">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-sv-border-muted bg-sv-app px-3 py-1.5 transition-colors duration-200 hover:border-sv-border">
              <span className={`h-2 w-2 rounded-full ${dotClass}`} aria-hidden />
              <span className="text-xs font-medium text-sv-text-secondary">{data.monitoringLabel}</span>
            </div>
          </div>
          <div>
            <SectionLabel className="mb-4 block">Onboarding checklist</SectionLabel>
            <ol className="relative space-y-0">
              {data.checklist.map((item, i) => {
                const isLast = i === data.checklist.length - 1;
                return (
                  <li key={item.text} className="relative flex gap-3 pb-6 last:pb-0">
                    {!isLast ? (
                      <span
                        className="absolute left-[13px] top-8 h-[calc(100%-0.25rem)] w-px bg-sv-border/80"
                        aria-hidden
                      />
                    ) : null}
                    <span
                      className={`relative z-[1] flex h-7 w-7 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold transition-colors duration-200 ${
                        item.done
                          ? "border-emerald-800/50 bg-emerald-950/40 text-emerald-200"
                          : "border-sv-border-muted bg-sv-app text-sv-muted"
                      }`}
                    >
                      {item.done ? <Check className="h-3.5 w-3.5" strokeWidth={2.5} aria-hidden /> : i + 1}
                    </span>
                    <span
                      className={`pt-0.5 text-sm leading-snug transition-colors duration-200 ${
                        item.done ? "text-sv-muted line-through decoration-sv-border/80" : "text-sv-text-secondary"
                      }`}
                    >
                      {item.text}
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      </div>
    </Card>
  );
}
