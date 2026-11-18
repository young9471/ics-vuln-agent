import {
  Bot,
  Brain,
  Bug,
  FolderOpen,
  type LucideIcon,
  LayoutDashboard,
  MessageSquare,
  Plug,
  Radio,
  ScrollText,
  Sparkles,
  Target,
  Terminal,
  Users,
  ShieldCheck,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
  adminOnly?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "总览",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard },
    ],
  },
  {
    id: 2,
    label: "协议逆向",
    items: [
      { id: "protocol-cases", title: "逆向案例", url: "/protocol/cases", icon: Target },
      { id: "protocol-findings", title: "协议发现", url: "/protocol/findings", icon: Bug },
      { id: "protocol-tools", title: "工具链", url: "/protocol/tools", icon: Terminal },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare },
      { id: "workspace", title: "工作空间", url: "/function/workspace", icon: FolderOpen },
      { id: "llm-records", title: "LLM 录制", url: "/function/llm-records", icon: Radio },
    ],
  },
  {
    id: 3,
    label: "系统",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "工具", url: "/system/tools", icon: Wrench },
      { id: "users", title: "用户", url: "/system/users", icon: Users, adminOnly: true },
      { id: "audit", title: "审计", url: "/system/audit", icon: ShieldCheck, adminOnly: true },
      { id: "logs", title: "日志", url: "/system/logs", icon: ScrollText },
    ],
  },
];
