import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import type { WeeklyInsightData } from "@/lib/overview-demo-data";

type WeeklyInsightCardProps = {
  data: WeeklyInsightData;
};

export function WeeklyInsightCard({ data }: WeeklyInsightCardProps) {
  return (
    <Card className="border-l-[3px] border-l-sv-accent/50 p-5 sm:p-6">
      <SectionLabel>Weekly snapshot</SectionLabel>
      <h3 className="mt-1 text-base font-semibold tracking-tight text-sv-text">{data.title}</h3>
      <p className="mt-3 max-w-3xl text-sm leading-relaxed text-sv-text-secondary">{data.body}</p>
    </Card>
  );
}
