import { Suspense } from "react";
import { SectionLabel } from "@/components/ui/SectionLabel";
import type { OverviewDemoData } from "@/lib/overview-demo-data";
import { OVERVIEW_DEMO_EMPTY } from "@/lib/overview-demo-data";
import { DemoModeSwitcher } from "./DemoModeSwitcher";
import { HeroCard } from "./HeroCard";
import { WeeklyInsightCard } from "./WeeklyInsightCard";
import { KpiGrid } from "./KpiGrid";
import { RecommendedStepsCard } from "./RecommendedStepsCard";
import { ComplianceReadinessCard } from "./ComplianceReadinessCard";
import { GuidanceCard } from "./GuidanceCard";

export type SecurityOverviewPageProps = {
  /** Populated from mock presets or your API. Defaults to sparse onboarding workspace. */
  data?: OverviewDemoData;
  /** Current URL `demo` param — keeps sidebar + in-page links on the same mock workspace. */
  demo?: string | null;
};

export function SecurityOverviewPage({ data = OVERVIEW_DEMO_EMPTY, demo }: SecurityOverviewPageProps) {
  return (
    <div className="mx-auto max-w-content px-4 py-8 sm:px-8 lg:py-10">
      <Suspense fallback={null}>
        <DemoModeSwitcher />
      </Suspense>

      <header className="mb-10 space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-sv-text sm:text-3xl">
          Security & Compliance Overview
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-sv-text-secondary sm:text-base">
          Understand your business security posture without needing a full IT team.
        </p>
        <p className="text-xs font-medium text-sv-muted">
          Workspace: <span className="text-sv-text-secondary">{data.workspaceLabel}</span>
        </p>
      </header>

      <div className="space-y-8">
        <HeroCard data={data.hero} demo={demo} />
        <WeeklyInsightCard data={data.weeklyInsight} />
        <div className="space-y-3">
          <SectionLabel>At a glance</SectionLabel>
          <KpiGrid items={data.kpis} />
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <RecommendedStepsCard
            intro={data.recommendedIntro}
            rows={data.recommendedRows}
            primaryIndex={data.recommendedPrimaryIndex}
            demo={demo}
          />
          <ComplianceReadinessCard readiness={data.readiness} />
        </div>

        <GuidanceCard />
      </div>
    </div>
  );
}
