import {
  Activity,
  ClipboardList,
  FileText,
  FolderOpen,
  Settings,
  Shield,
  Users,
  Wrench,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
};

export type NavGroup = { title: string; items: NavItem[] };

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Operations",
    items: [
      { label: "Security Overview", href: "/security-overview", icon: Shield },
      { label: "Issues & Fixes", href: "/issues", icon: Wrench },
      { label: "Activity Log", href: "/activity", icon: Activity },
    ],
  },
  {
    title: "Compliance",
    items: [
      { label: "Compliance Setup", href: "/compliance-setup", icon: ClipboardList },
      { label: "Policies", href: "/policies", icon: FileText },
      { label: "Reports", href: "/reports", icon: FolderOpen },
    ],
  },
  {
    title: "Admin",
    items: [
      { label: "Clients", href: "/clients", icon: Users },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];
