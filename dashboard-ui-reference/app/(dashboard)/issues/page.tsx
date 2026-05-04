import { IssuesFixesView } from "@/components/issues/IssuesFixesView";
import { getMockWorkspace } from "@/lib/mock-workspace";

type PageProps = {
  searchParams: Promise<{ demo?: string }>;
};

export default async function IssuesPage({ searchParams }: PageProps) {
  const sp = await searchParams;
  const workspace = getMockWorkspace(sp.demo);

  return <IssuesFixesView workspace={workspace} />;
}
