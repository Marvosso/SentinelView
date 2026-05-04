/**
 * Demo / mock payloads for Security & Compliance Overview.
 * Use ?demo=client on /security-overview for a portfolio-ready filled state.
 */

export type HeroChecklistItem = { text: string; done: boolean };

export type OverviewHeroData = {
  title: string;
  body: string;
  cta: { label: string; href: string };
  monitoringLabel: string;
  monitoringTone: "success" | "warning";
  checklist: HeroChecklistItem[];
};

export type OverviewKpiTrendTone = "positive" | "neutral" | "attention";

export type OverviewKpiItem = {
  label: string;
  value: string;
  helper: string;
  tone?: "default" | "warn";
  /** Short trend or context, e.g. "↑ vs last week" or "Within range" */
  trend?: string;
  trendTone?: OverviewKpiTrendTone;
};

/** Plain-English weekly narrative for leadership. */
export type WeeklyInsightData = {
  title: string;
  body: string;
};

export type RecommendedRowIcon = "user" | "cable" | "file";

export type OverviewRecommendedRow = {
  icon: RecommendedRowIcon;
  title: string;
  description: string;
  pill: "recommended" | "ready" | "next";
  pillLabel: string;
  href: string;
  action: string;
};

export type FrameworkRowData = {
  label: string;
  status: string;
  percent: number;
  helper: string;
};

export type OverviewDemoData = {
  workspaceLabel: string;
  hero: OverviewHeroData;
  weeklyInsight: WeeklyInsightData;
  kpis: OverviewKpiItem[];
  recommendedIntro: string;
  recommendedRows: OverviewRecommendedRow[];
  /** Which row (0-based) gets the primary (indigo) action button. */
  recommendedPrimaryIndex: number;
  readiness: {
    soc2: FrameworkRowData;
    iso: FrameworkRowData;
  };
};

/** Onboarding-style workspace (sparse numbers). */
export const OVERVIEW_DEMO_EMPTY: OverviewDemoData = {
  workspaceLabel: "demo_client",
  hero: {
    title: "Turn Security Signals into Board-Ready Clarity",
    body:
      "Give leadership a single place to see risk, accountability, and progress—without waiting on a custom report every quarter. Start by telling us how you operate.",
    cta: { label: "Define your compliance scope", href: "/compliance-setup" },
    monitoringLabel: "Monitoring inactive",
    monitoringTone: "warning",
    checklist: [
      { text: "Complete profile", done: false },
      { text: "Connect data source", done: false },
      { text: "Generate first policy", done: false },
    ],
  },
  weeklyInsight: {
    title: "Summary starts after setup",
    body:
      "Once activity is connected, you will see a concise weekly readout here: what changed, what needs a decision, and what is steady—written for executives, not engineers.",
  },
  kpis: [
    {
      label: "Security Checks Running",
      value: "3",
      helper: "Covers the safeguards we monitor for your profile",
      trend: "Starter set",
      trendTone: "neutral",
    },
    {
      label: "Activity Logged Today",
      value: "0",
      helper: "Connect a source to begin tracking",
      trend: "—",
      trendTone: "neutral",
    },
    {
      label: "Issues You Need to Fix",
      value: "0",
      helper: "Nothing is waiting on you right now",
      tone: "default",
      trend: "Clear",
      trendTone: "positive",
    },
    {
      label: "Last Security Review",
      value: "Not started",
      helper: "Complete setup to create your first review",
      trend: "—",
      trendTone: "neutral",
    },
  ],
  recommendedIntro: "Start here to activate your compliance workspace.",
  recommendedRows: [
    {
      icon: "user",
      title: "Complete your compliance profile",
      description:
        "Helps SentinelView understand your industry, data types, and compliance goals.",
      pill: "recommended",
      pillLabel: "Recommended",
      href: "/compliance-setup",
      action: "Start",
    },
    {
      icon: "cable",
      title: "Connect your first security data source",
      description: "Allows SentinelView to monitor activity and surface business risk.",
      pill: "ready",
      pillLabel: "Ready",
      href: "/activity",
      action: "Connect",
    },
    {
      icon: "file",
      title: "Generate your first policy document",
      description: "Creates an audit-ready starting point for your governance program.",
      pill: "next",
      pillLabel: "Next",
      href: "/policies",
      action: "Generate",
    },
  ],
  recommendedPrimaryIndex: 0,
  readiness: {
    soc2: {
      label: "SOC 2 Readiness",
      status: "Getting Started",
      percent: 0,
      helper: "Trust Services Criteria mapping will activate after setup.",
    },
    iso: {
      label: "ISO 27001 Readiness",
      status: "Not Started",
      percent: 0,
      helper: "Annex A control mapping will activate after setup.",
    },
  },
};

/** Filled workspace for client demos, screenshots, and LinkedIn. */
export const OVERVIEW_DEMO_CLIENT: OverviewDemoData = {
  workspaceLabel: "Acme Health Group",
  hero: {
    title: "Decisions This Week, Not Noise",
    body:
      "You now have continuous visibility into access, sharing, and resilience. The fastest path to value is to close the few items that still need an owner—then keep this rhythm for customers and auditors.",
    cta: { label: "Decide on open items", href: "/issues" },
    monitoringLabel: "Monitoring active",
    monitoringTone: "success",
    checklist: [
      { text: "Complete profile", done: true },
      { text: "Connect data source", done: true },
      { text: "Generate first policy", done: false },
    ],
  },
  weeklyInsight: {
    title: "Sharing and access led the narrative",
    body:
      "Those patterns drove most of the signal volume. Two follow-ups still need an owner; everything else sits within the range we expect for an organization your size. Use Issues & Fixes to assign and record outcomes.",
  },
  kpis: [
    {
      label: "Security Checks Running",
      value: "24",
      helper: "Aligned to your profile and connected systems",
      trend: "+4 vs last month",
      trendTone: "positive",
    },
    {
      label: "Activity Logged Today",
      value: "47",
      helper: "Typical weekday volume for your workspace",
      trend: "Within range",
      trendTone: "neutral",
    },
    {
      label: "Issues You Need to Fix",
      value: "2",
      helper: "Open items are summarized under Issues & Fixes",
      tone: "warn",
      trend: "Needs owners",
      trendTone: "attention",
    },
    {
      label: "Last Security Review",
      value: "12 days",
      helper: "Profile and checklist last updated together",
      trend: "On cadence",
      trendTone: "neutral",
    },
  ],
  recommendedIntro:
    "Your workspace is live. Finish the last onboarding step so exports stay audit-friendly.",
  recommendedRows: [
    {
      icon: "user",
      title: "Complete your compliance profile",
      description: "Industry, data types, and goals are on file—good for tailored guidance.",
      pill: "ready",
      pillLabel: "Complete",
      href: "/compliance-setup",
      action: "Review",
    },
    {
      icon: "cable",
      title: "Connect your first security data source",
      description: "Microsoft 365 and endpoint activity are connected; you can add more anytime.",
      pill: "ready",
      pillLabel: "Connected",
      href: "/activity",
      action: "Manage",
    },
    {
      icon: "file",
      title: "Generate your first policy document",
      description: "Publish a starter pack your team can acknowledge and share with customers.",
      pill: "recommended",
      pillLabel: "Recommended",
      href: "/policies",
      action: "Generate",
    },
  ],
  recommendedPrimaryIndex: 2,
  readiness: {
    soc2: {
      label: "SOC 2 Readiness",
      status: "Building Momentum",
      percent: 42,
      helper: "Access, change management, and vendor review tracks are in progress.",
    },
    iso: {
      label: "ISO 27001 Readiness",
      status: "Getting Started",
      percent: 28,
      helper: "Annex A themes mapped; evidence collection expands as you close tasks.",
    },
  },
};

export function getOverviewDemoFromSearch(demo: string | undefined): OverviewDemoData {
  if (demo === "client" || demo === "full") {
    return OVERVIEW_DEMO_CLIENT;
  }
  return OVERVIEW_DEMO_EMPTY;
}
