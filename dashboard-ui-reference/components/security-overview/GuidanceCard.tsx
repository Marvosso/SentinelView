import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";

const bullets = [
  "Monitor security activity",
  "Explain risks in plain English",
  "Recommend practical fixes",
  "Generate compliance evidence",
  "Help prepare audit-ready documentation",
];

export function GuidanceCard() {
  return (
    <Card className="p-6 lg:p-8">
      <SectionLabel>Plain-English guidance</SectionLabel>
      <h3 className="mt-2 text-lg font-semibold tracking-tight text-sv-text">
        What SentinelView will do next
      </h3>
      <p className="mt-3 max-w-2xl text-sm leading-relaxed text-sv-text-secondary">
        Once setup is complete, SentinelView will:
      </p>
      <ul className="mt-5 space-y-2.5 text-sm text-sv-text-secondary">
        {bullets.map((item) => (
          <li key={item} className="flex gap-3">
            <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-sv-accent" aria-hidden />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
