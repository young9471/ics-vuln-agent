"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter } from "next/navigation";

import {
  AlertTriangleIcon,
  BugIcon,
  FileCode2Icon,
  Loader2Icon,
  RefreshCwIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  SwordsIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  fmtProtocolTime,
  protocolApi,
  type VulnDashboard,
} from "@/lib/protocol-api";

const VCLASS_NAMES: Record<string, string> = {
  "1": "信息泄露", "2": "协议认证", "3": "远程启停", "4": "内存读写", "5": "逻辑篡改",
  "6": "保护破解", "7": "拒绝服务", "8": "固件与组件", "9": "次要攻击面",
  "10": "重放与欺骗", "11": "加密与降级", "12": "发现协议滥用", "13": "物理I/O操纵", "14": "工程侧客户端",
};

const STATE_STYLES: Record<string, string> = {
  confirmed: "bg-green-100 text-green-800",
  falsified: "bg-gray-200 text-gray-600",
  enforced: "bg-blue-100 text-blue-800",
  inconclusive: "bg-orange-100 text-orange-800",
  pending: "bg-yellow-100 text-yellow-800",
};

const PHASE_STYLES: Record<string, string> = {
  pass: "bg-green-100 text-green-800",
  running: "bg-blue-100 text-blue-800",
  fail: "bg-red-100 text-red-800",
  pending: "bg-yellow-100 text-yellow-800",
  not_started: "bg-gray-100 text-gray-500",
};

function MetricCard({
  title,
  value,
  sub,
  icon: Icon,
  tone,
}: {
  title: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: React.ComponentType<{ className?: string }>;
  tone?: "default" | "warn" | "danger";
}) {
  const toneCls =
    tone === "danger" ? "text-red-600" : tone === "warn" ? "text-orange-600" : "text-foreground";
  return (
    <Card>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between">
          <div>
            <div className="text-xs text-muted-foreground">{title}</div>
            <div className={`mt-1 text-2xl font-semibold tabular-nums ${toneCls}`}>{value}</div>
            {sub ? <div className="mt-1 text-xs text-muted-foreground">{sub}</div> : null}
          </div>
          <Icon className="size-4 shrink-0 text-muted-foreground" />
        </div>
      </CardContent>
    </Card>
  );
}

function PhaseCell({ label, status }: { label: string; status: string }) {
  const s = status || "not_started";
  return (
    <span
      className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${PHASE_STYLES[s] ?? "bg-muted text-muted-foreground"}`}
      title={`${label}: ${s}`}
    >
      {label}
    </span>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [data, setData] = React.useState<VulnDashboard | null>(null);
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await protocolApi.vulnDashboard());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const h = data?.hypotheses;
  const confirmed = h?.by_state?.confirmed ?? 0;
  const pending = h?.by_state?.pending ?? 0;
  const inconclusive = h?.by_state?.inconclusive ?? 0;
  const falsified = h?.by_state?.falsified ?? 0;
  const kbCover = data?.knowledge.rows
    ? Math.round((data.knowledge.vclass_covered / data.knowledge.rows) * 1000) / 10
    : 0;
  const vclassRows = Object.entries(h?.by_vclass ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const maxVclass = vclassRows.length ? vclassRows[0][1] : 1;

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">工控系统脆弱性分析与利用 · 总览</h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            协议逆向（P1-P6）→ 漏洞面测绘（P7）→ 验证与 Fuzz（P8）→ EXP 与报告（P9）的全局态势
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          {loading ? (
            <Loader2Icon className="mr-1.5 size-4 animate-spin" />
          ) : (
            <RefreshCwIcon className="mr-1.5 size-4" />
          )}
          刷新
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          title="分析案例"
          value={data?.cases.total ?? "–"}
          sub={`${data?.cases.running ?? 0} 运行中 · ${data?.cases.vuln_enabled ?? 0} 启用漏洞挖掘`}
          icon={SwordsIcon}
        />
        <MetricCard
          title="已确认漏洞"
          value={confirmed}
          tone={confirmed > 0 ? "danger" : "default"}
          sub={`共 ${h?.total ?? 0} 假设 · 待验证 ${pending} · 存疑 ${inconclusive} · 证伪 ${falsified}`}
          icon={BugIcon}
        />
        <MetricCard
          title="EXP 资产"
          value={data?.exploits.total ?? "–"}
          sub={
            data
              ? ["replay", "poc", "chain"]
                  .filter((t) => data.exploits.by_tier?.[t])
                  .map((t) => `${t} ${data.exploits.by_tier[t]}`)
                  .join(" · ") || "尚无"
              : ""
          }
          icon={FileCode2Icon}
        />
        <MetricCard
          title="待审批 destructive"
          value={data?.approvals.pending ?? "–"}
          tone={(data?.approvals.pending ?? 0) > 0 ? "warn" : "default"}
          sub={`campaign 已执行 ${data?.campaigns.total ?? 0}（verify ${data?.campaigns.by_mode?.verify ?? 0} / fuzz ${data?.campaigns.by_mode?.fuzz ?? 0}）`}
          icon={AlertTriangleIcon}
        />
        <MetricCard
          title="漏洞知识库"
          value={data ? (data.knowledge.cves > 10000 ? `${(data.knowledge.cves / 1000).toFixed(1)}K` : data.knowledge.cves) : "–"}
          sub={`${data?.knowledge.rows ?? 0} 条 · 14 类标注覆盖 ${kbCover}%`}
          icon={ShieldAlertIcon}
        />
      </div>

      <div className="grid gap-3 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">漏洞类别分布（假设数 · 前 8 类）</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {vclassRows.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted-foreground">
                尚无假设——启用漏洞挖掘的案例跑完 P7 后出现
              </p>
            ) : null}
            {vclassRows.map(([v, n]) => (
              <div key={v} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate text-xs text-muted-foreground">
                  {v}·{VCLASS_NAMES[v] ?? "?"}
                </span>
                <div className="h-4 flex-1 overflow-hidden rounded bg-muted">
                  <div
                    className="h-full rounded bg-red-400/80"
                    style={{ width: `${Math.max(4, (n / maxVclass) * 100)}%` }}
                  />
                </div>
                <span className="w-8 shrink-0 text-right text-xs tabular-nums">{n}</span>
              </div>
            ))}
            {h && h.total > 0 ? (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {Object.entries(h.by_state)
                  .sort((a, b) => b[1] - a[1])
                  .map(([s, n]) => (
                    <span key={s} className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] ${STATE_STYLES[s] ?? "bg-muted text-muted-foreground"}`}>
                      {s} {n}
                    </span>
                  ))}
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">destructive 审批队列</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>#</TableHead>
                  <TableHead>假设</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(data?.approvals.recent ?? []).length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">
                      暂无审批记录
                    </TableCell>
                  </TableRow>
                ) : null}
                {(data?.approvals.recent ?? []).map((a) => (
                  <TableRow key={a.id} className="cursor-pointer" onClick={() => router.push(`/protocol/cases/detail?id=${a.case_id}`)}>
                    <TableCell className="text-xs">#{a.id}</TableCell>
                    <TableCell className="max-w-[140px] truncate font-mono text-xs" title={a.hypothesis}>
                      {a.hypothesis || a.kind}
                    </TableCell>
                    <TableCell>
                      {a.status === "approved" ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-700"><ShieldCheckIcon className="size-3.5" />approved</span>
                      ) : a.status === "rejected" ? (
                        <span className="inline-flex items-center gap-1 text-xs text-red-700"><ShieldAlertIcon className="size-3.5" />rejected</span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded bg-yellow-100 px-1.5 py-0.5 text-[11px] text-yellow-800">pending</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">{fmtProtocolTime(a.created_at)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">最近流水</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ScrollArea className="h-[260px]">
              <div className="divide-y">
                {(data?.events ?? []).length === 0 ? (
                  <p className="py-6 text-center text-xs text-muted-foreground">暂无事件</p>
                ) : null}
                {(data?.events ?? []).map((e) => (
                  <div
                    key={e.id}
                    className="flex cursor-pointer items-start gap-2 px-3 py-2 hover:bg-muted/50"
                    onClick={() => router.push(`/protocol/cases/detail?id=${e.case_id}`)}
                  >
                    <Badge variant={e.kind === "error" ? "destructive" : e.kind === "gate" ? "outline" : "secondary"} className="mt-0.5 shrink-0 text-[10px]">
                      {e.phase || e.kind}
                    </Badge>
                    <div className="min-w-0">
                      <p className="truncate text-xs" title={e.message}>{e.message}</p>
                      <p className="text-[11px] text-muted-foreground">{fmtProtocolTime(e.created_at)}</p>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">各案例挖掘态势</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>案例</TableHead>
                <TableHead>模式</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>漏洞挖掘</TableHead>
                <TableHead>P7</TableHead>
                <TableHead>P8</TableHead>
                <TableHead>P9</TableHead>
                <TableHead>已确认</TableHead>
                <TableHead>EXP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.case_rows ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="py-6 text-center text-xs text-muted-foreground">
                    暂无案例
                  </TableCell>
                </TableRow>
              ) : null}
              {(data?.case_rows ?? []).map((c) => (
                <TableRow key={c.case_id} className="cursor-pointer" onClick={() => router.push(`/protocol/cases/detail?id=${c.case_id}`)}>
                  <TableCell className="max-w-[220px] truncate text-xs font-medium">
                    #{c.case_id} {c.name}
                  </TableCell>
                  <TableCell className="text-xs">{c.mode}</TableCell>
                  <TableCell className="text-xs">{c.status}</TableCell>
                  <TableCell>
                    {c.vuln_enabled ? (
                      <Badge className="text-[11px]">启用</Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell><PhaseCell label="P7" status={c.p7} /></TableCell>
                  <TableCell><PhaseCell label="P8" status={c.p8} /></TableCell>
                  <TableCell><PhaseCell label="P9" status={c.p9} /></TableCell>
                  <TableCell className={`text-xs tabular-nums ${c.confirmed > 0 ? "font-semibold text-red-600" : ""}`}>
                    {c.confirmed}/{c.hypotheses}
                  </TableCell>
                  <TableCell className="text-xs tabular-nums">{c.exploits}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <p className="text-[11px] text-muted-foreground">
        流水线：P1 资产侦察 → P2 流量获取 → P3 流量分析 → P4 静态分析 → P5 交叉验证 → P6
        文档交付 → <span className="font-medium text-foreground">P7 漏洞面测绘（门 G）→ P8 验证与
        Fuzz（门 H）→ P9 EXP 与报告（门 I）</span>；destructive 操作全程审批硬闸。{" "}
        <Link href="/protocol/cases" className="underline underline-offset-2">进入案例列表 →</Link>
      </p>
    </div>
  );
}
