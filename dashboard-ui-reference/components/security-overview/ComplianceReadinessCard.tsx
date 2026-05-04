import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import type { OverviewDemoData } from "@/lib/overview-demo-data";
import { FrameworkProgress } from "./FrameworkProgress";

type ComplianceReadinessCardProps = {
  readiness: OverviewDemoData["readiness"];
};

export function ComplianceReadinessCard({ readiness }: ComplianceReadinessCardProps) {
  return (
    <Card className="flex flex-col p-6">
      <SectionLabel className="mb-1">Compliance</SectionLabel>
      <h3 className="text-base font-semibold text-sv-text">Compliance Readiness</h3>
      <p className="mt-1 text-sm text-sv-muted">
        Track progress toward common security frameworks.
      </p>

      <div className="mt-6 space-y-8">
        <FrameworkProgress
          label={readiness.soc2.label}
          status={readiness.soc2.status}
          percent={readiness.soc2.percent}
          helper={readiness.soc2.helper}
        />
        <FrameworkProgress
          label={readiness.iso.label}
          status={readiness.iso.status}
          percent={readiness.iso.percent}
          helper={readiness.iso.helper}
        />
      </div>

      <p className="mt-8 border-t border-sv-border pt-4 text-xs leading-relaxed text-sv-muted">
        Percentages reflect checklist progress inside SentinelView—they are a working guide, not a
        formal certification.
      </p>
    </Card>
  );
}
