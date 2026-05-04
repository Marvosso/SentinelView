import { Suspense } from "react";
import { Card } from "@/components/ui/Card";
import { SectionLabel } from "@/components/ui/SectionLabel";
import { DemoModeSwitcher } from "@/components/security-overview/DemoModeSwitcher";
import type { MockIssue, MockIssueStatus, MockWorkspace } from "@/lib/mock-workspace";

type IssuesFixesViewProps = {
  workspace: MockWorkspace;
};

function statusLabel(s: MockIssueStatus): string {
  if (s === "open") return "Needs owner";
  if (s === "in_progress") return "In progress";
  return "Resolved";
}

function statusStyles(s: MockIssueStatus): string {
  if (s === "open")
    return "border-amber-900/40 bg-amber-950/20 text-amber-100/90";
  if (s === "in_progress")
    return "border-sv-border-muted bg-sv-app text-sv-text-secondary";
  return "border-emerald-900/40 bg-emerald-950/20 text-emerald-100/90";
}

function sortIssues(list: MockIssue[]): MockIssue[] {
  const rank: Record<MockIssueStatus, number> = { open: 0, in_progress: 1, resolved: 2 };
  return [...list].sort((a, b) => rank[a.status] - rank[b.status]);
}

export function IssuesFixesView({ workspace }: IssuesFixesViewProps) {
  const sorted = sortIssues(workspace.issues);
  const empty = sorted.length === 0;
  const openCount = sorted.filter((i) => i.status !== "resolved").length;

  return (
    <div className="mx-auto max-w-content px-4 py-8 sm:px-8 lg:py-10">
      <Suspense fallback={null}>
        <DemoModeSwitcher />
      </Suspense>

      <header className="mb-8 space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-sv-text sm:text-3xl">Issues & Fixes</h1>
        <p className="max-w-2xl text-sm leading-relaxed text-sv-text-secondary">
          Prioritized items for{" "}
          <span className="font-medium text-sv-text">{workspace.workspaceLabel}</span>
          {empty ? "." : ` — ${openCount} open or in progress.`} Each card states a practical next step
          in plain English.
        </p>
      </header>

      {empty ? (
        <Card className="p-6">
          <SectionLabel className="mb-2">Nothing queued</SectionLabel>
          <p className="text-sm leading-relaxed text-sv-text-secondary">
            When findings arrive, they will be listed here with recommended fixes—not jargon-only
            alerts. Use{" "}
            <a
              href="/security-overview?demo=client"
              className="font-medium text-sv-accent hover:text-sv-accent-hover"
            >
              Sample client
            </a>{" "}
            to preview mock issues.
          </p>
        </Card>
      ) : (
        <ul className="space-y-4">
          {sorted.map((issue) => (
            <li key={issue.id}>
              <Card
                className={`p-5 ${issue.status === "resolved" ? "border-l-[3px] border-l-emerald-600/70" : ""}`}
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0 flex-1 space-y-2">
                    <p className="text-sm font-semibold text-sv-text">{issue.title}</p>
                    <p className="text-xs text-sv-muted">{issue.context}</p>
                  </div>
                  <span
                    className={`inline-flex w-fit shrink-0 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${statusStyles(issue.status)}`}
                  >
                    {statusLabel(issue.status)}
                  </span>
                </div>
                <div className="mt-4 border-t border-sv-border pt-4">
                  <p className="text-[11px] font-semibold uppercase tracking-wider text-sv-muted">
                    Recommended next step
                  </p>
                  <p className="mt-1.5 text-sm leading-relaxed text-sv-text-secondary">
                    {issue.recommendedFix}
                  </p>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
