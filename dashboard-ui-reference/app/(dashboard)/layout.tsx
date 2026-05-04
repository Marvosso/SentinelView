import { DashboardLayout } from "@/components/dashboard/DashboardLayout";

export default function DashboardSectionLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <DashboardLayout>{children}</DashboardLayout>;
}
