import { SecurityOverviewPage } from "@/components/security-overview/SecurityOverviewPage";
import { getOverviewDemoFromSearch } from "@/lib/overview-demo-data";

type PageProps = {
  searchParams: Promise<{ demo?: string }>;
};

export default async function SecurityOverviewRoute({ searchParams }: PageProps) {
  const sp = await searchParams;
  const data = getOverviewDemoFromSearch(sp.demo);

  return <SecurityOverviewPage data={data} demo={sp.demo} />;
}
