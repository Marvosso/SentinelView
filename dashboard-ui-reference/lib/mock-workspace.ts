import { isRichDemo } from "./demo-nav";

export type MockActivity = {
  id: string;
  /** Short label for the timeline, e.g. "2:14 PM" */
  timeLabel: string;
  /** Calendar day for grouping */
  dayLabel: string;
  headline: string;
  detail: string;
  source: string;
};

export type MockIssueStatus = "open" | "in_progress" | "resolved";

export type MockIssue = {
  id: string;
  title: string;
  status: MockIssueStatus;
  /** Plain-language fix for SMB readers */
  recommendedFix: string;
  /** Shown as secondary line */
  context: string;
};

export type MockWorkspace = {
  workspaceId: string;
  workspaceLabel: string;
  activities: MockActivity[];
  issues: MockIssue[];
};

const ACTIVITIES_CLIENT: MockActivity[] = [
  {
    id: "a1",
    dayLabel: "Today",
    timeLabel: "2:14 PM",
    headline: "Sign-in from a new city for an admin account",
    detail:
      "Someone with admin rights signed in from a location your team has not used before. Often this is travel—sometimes it deserves a quick check.",
    source: "Identity & access",
  },
  {
    id: "a2",
    dayLabel: "Today",
    timeLabel: "11:02 AM",
    headline: "Weekly access review summary posted",
    detail: "Managers were reminded to confirm who still needs access to shared drives.",
    source: "Access governance",
  },
  {
    id: "a3",
    dayLabel: "Today",
    timeLabel: "9:40 AM",
    headline: "Sensitive file shared with an external address",
    detail:
      "A spreadsheet that matches your “restricted” label was shared outside the organization. Review whether the recipient is expected.",
    source: "Data protection",
  },
  {
    id: "a4",
    dayLabel: "Yesterday",
    timeLabel: "4:55 PM",
    headline: "Backup for file servers completed successfully",
    detail: "All scheduled jobs finished within the expected window.",
    source: "Resilience",
  },
  {
    id: "a5",
    dayLabel: "Yesterday",
    timeLabel: "1:20 PM",
    headline: "New laptop enrolled and encryption confirmed",
    detail: "A device for your finance group met your security baseline before joining the network.",
    source: "Devices",
  },
  {
    id: "a6",
    dayLabel: "Yesterday",
    timeLabel: "10:08 AM",
    headline: "Policy acknowledgment recorded",
    detail: "Twelve people in Operations completed the quarterly security awareness reminder.",
    source: "Training & policy",
  },
  {
    id: "a7",
    dayLabel: "Mon, May 1",
    timeLabel: "3:30 PM",
    headline: "Vendor security questionnaire received",
    detail: "A cloud payroll vendor submitted responses for your procurement review.",
    source: "Third parties",
  },
  {
    id: "a8",
    dayLabel: "Mon, May 1",
    timeLabel: "9:00 AM",
    headline: "No high-priority signals overnight",
    detail: "Routine health check—no items crossed your urgent threshold.",
    source: "Monitoring",
  },
];

const ISSUES_CLIENT: MockIssue[] = [
  {
    id: "i1",
    title: "External share on a folder marked “HR – confidential”",
    status: "open",
    context: "Detected this morning · Data protection",
    recommendedFix:
      "Confirm with HR whether the recipient is authorized. If not, revoke the link, ask the employee to use your approved transfer method, and note the decision for your records.",
  },
  {
    id: "i2",
    title: "Admin sign-in from an unusual location",
    status: "in_progress",
    context: "Opened yesterday · Identity & access",
    recommendedFix:
      "Ask the account owner to confirm it was them (travel or remote work). If they say no, reset the password and review recent changes that account could have made.",
  },
  {
    id: "i3",
    title: "Backup window ran 45 minutes longer than usual",
    status: "open",
    context: "Last night · Resilience",
    recommendedFix:
      "Have your IT partner check storage growth and job health. Longer runs can be normal—or an early sign you need more capacity before a busy season.",
  },
  {
    id: "i4",
    title: "Missing acknowledgment for the updated remote-work policy",
    status: "resolved",
    context: "Closed 3 days ago · Policy",
    recommendedFix:
      "You sent a reminder to the remaining managers; acknowledgments are now on file for audit purposes.",
  },
];

export function getMockWorkspace(demo: string | undefined | null): MockWorkspace {
  if (isRichDemo(demo)) {
    return {
      workspaceId: "acme-health",
      workspaceLabel: "Acme Health Group",
      activities: ACTIVITIES_CLIENT,
      issues: ISSUES_CLIENT,
    };
  }
  return {
    workspaceId: "demo_client",
    workspaceLabel: "demo_client",
    activities: [],
    issues: [],
  };
}
