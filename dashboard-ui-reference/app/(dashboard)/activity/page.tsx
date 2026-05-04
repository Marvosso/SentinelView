import { ActivityLogView } from "@/components/activity/ActivityLogView";
import { getMockWorkspace } from "@/lib/mock-workspace";

type PageProps = {
  searchParams: Promise<{ demo?: string }>;
};

export default async function ActivityPage({ searchParams }: PageProps) {
  const sp = await searchParams;
  const workspace = getMockWorkspace(sp.demo);

  return <ActivityLogView workspace={workspace} />;
}
