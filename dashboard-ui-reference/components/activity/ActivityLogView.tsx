import { Suspense } from "react";
import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import { DemoModeSwitcher } from "@/components/security-overview/DemoModeSwitcher";
import type { MockActivity, MockWorkspace } from "@/lib/mock-workspace";

type ActivityLogViewProps = {
  workspace: MockWorkspace;
};

function groupByDay(items: MockActivity[]): { day: string; rows: MockActivity[] }[] {
  const order: string[] = [];
  const map = new Map<string, MockActivity[]>();
  for (const row of items) {
    if (!map.has(row.dayLabel)) {
      order.push(row.dayLabel);
      map.set(row.dayLabel, []);
    }
    map.get(row.dayLabel)!.push(row);
  }
  return order.map((day) => ({ day, rows: map.get(day)! }));
}

export function ActivityLogView({ workspace }: ActivityLogViewProps) {
  const groups = groupByDay(workspace.activities);
  const empty = workspace.activities.length === 0;

  return (
    <div className="mx-auto max-w-content px-4 py-8 sm:px-8 lg:py-10">
      <Suspense fallback={null}>
        <DemoModeSwitcher />
      </Suspense>

      <header className="mb-8 space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-sv-text sm:text-3xl">Activity Log</h1>
        <p className="max-w-2xl text-sm leading-relaxed text-sv-text-secondary">
          Recent security-related activity for{" "}
          <span className="font-medium text-sv-text">{workspace.workspaceLabel}</span>. Plain-language
          summaries—no raw system dumps.
        </p>
      </header>

      {empty ? (
        <Card className="p-6">
          <SectionLabel className="mb-2">Nothing to show yet</SectionLabel>
          <p className="text-sm leading-relaxed text-sv-text-secondary">
            When your workspace is connected, sign-ins, sharing, backups, and policy milestones will
            appear here in order. Try{" "}
            <a
              href="/security-overview?demo=client"
              className="font-medium text-sv-accent hover:text-sv-accent-hover"
            >
              Sample client
            </a>{" "}
            on the overview to see mock activity.
          </p>
        </Card>
      ) : (
        <div className="space-y-8">
          {groups.map(({ day, rows }) => (
            <section key={day}>
              <h2 className="mb-4 text-xs font-semibold uppercase tracking-wider text-sv-muted">{day}</h2>
              <ul className="space-y-3">
                {rows.map((row) => (
                  <li key={row.id}>
                    <Card className="p-5">
                      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                        <div className="min-w-0 flex-1 space-y-2">
                          <p className="text-[11px] font-medium uppercase tracking-wide text-sv-muted">
                            {row.timeLabel} · {row.source}
                          </p>
                          <p className="text-sm font-semibold text-sv-text">{row.headline}</p>
                          <p className="text-sm leading-relaxed text-sv-text-secondary">{row.detail}</p>
                        </div>
                      </div>
                    </Card>
                  </li>
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
