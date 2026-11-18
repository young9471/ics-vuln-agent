"use client";

import * as React from "react";

import { CopyIcon, EyeIcon, Loader2Icon, ShieldCheckIcon, ShieldXIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
  type ApplicabilityItem,
  type CampaignRecord,
  type DeviceProfile,
  type ExploitAsset,
  type IntelHit,
  type VulnHypothesis,
  type VulnSurface,
  type ProtocolApproval,
} from "@/lib/protocol-api";

const VCLASS_NAMES: Record<number, string> = {
  1: "信息泄露", 2: "协议认证", 3: "远程启停", 4: "内存读写", 5: "逻辑篡改",
  6: "保护破解", 7: "拒绝服务", 8: "固件与组件", 9: "次要攻击面",
  10: "重放与欺骗", 11: "加密与降级", 12: "发现协议滥用", 13: "物理I/O操纵", 14: "工程侧客户端",
};

function HypothesisStateBadge({ state }: { state?: string }) {
  const s = state ?? "pending";
  const map: Record<string, string> = {
    confirmed: "bg-green-100 text-green-800",
    falsified: "bg-gray-100 text-gray-600",
    enforced: "bg-blue-100 text-blue-800",
    inconclusive: "bg-orange-100 text-orange-800",
    pending: "bg-yellow-100 text-yellow-800",
  };
  return <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${map[s] ?? "bg-muted text-muted-foreground"}`}>{s}</span>;
}

function RiskBadge({ risk }: { risk?: string }) {
  if (!risk) return <span>-</span>;
  const map: Record<string, "secondary" | "outline" | "destructive"> = {
    read: "secondary",
    write: "outline",
    destructive: "destructive",
  };
  return <Badge variant={map[risk] ?? "secondary"} className="text-[11px]">{risk}</Badge>;
}

function ApplicabilityBadge({ state }: { state?: string }) {
  const map: Record<string, string> = {
    applicable: "bg-green-100 text-green-800",
    not_applicable: "bg-gray-200 text-gray-600",
    unknown: "bg-orange-100 text-orange-800",
  };
  const label: Record<string, string> = {
    applicable: "适用",
    not_applicable: "不适用",
    unknown: "待探测",
  };
  const s = state ?? "unknown";
  return <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${map[s] ?? "bg-muted text-muted-foreground"}`}>{label[s] ?? s}</span>;
}

function ModeBadge({ mode }: { mode?: string }) {
  const m = mode ?? "fuzz";
  const map: Record<string, string> = {
    verify: "bg-blue-100 text-blue-800",
    fuzz: "bg-purple-100 text-purple-800",
  };
  const label: Record<string, string> = { verify: "确定性验证", fuzz: "灰盒Fuzz" };
  return <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${map[m] ?? "bg-muted text-muted-foreground"}`}>{label[m] ?? m}</span>;
}

function vclassLabel(v?: number) {
  return v ? `${v}·${VCLASS_NAMES[v] ?? "?"}` : "-";
}

export function ProtocolVulnView({
  caseId,
  raw,
  vulnEnabled,
  onChanged,
}: {
  caseId: number;
  raw?: unknown;
  vulnEnabled: boolean;
  onChanged: () => void | Promise<void>;
}) {
  const [approvals, setApprovals] = React.useState<ProtocolApproval[]>([]);
  const [approvalsLoading, setApprovalsLoading] = React.useState(false);
  const [note, setNote] = React.useState("");
  const [decision, setDecision] = React.useState<"approve" | "reject">("approve");
  const [busyId, setBusyId] = React.useState<number | null>(null);
  const [scriptOpen, setScriptOpen] = React.useState(false);
  const [scriptLoading, setScriptLoading] = React.useState(false);
  const [scriptData, setScriptData] = React.useState<{ name: string; size: number; sha?: string; content: string } | null>(null);
  const [expandedHyp, setExpandedHyp] = React.useState<string | null>(null);

  const parsed = React.useMemo(() => {
    const empty = {
      profile: undefined as DeviceProfile | undefined,
      surface: undefined as VulnSurface | undefined,
      hypotheses: [] as VulnHypothesis[],
      exploits: [] as ExploitAsset[],
      campaigns: [] as CampaignRecord[],
    };
    if (!raw) return empty;
    try {
      const obj = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, unknown>;
      return {
        profile: obj.device_profile as DeviceProfile | undefined,
        surface: obj.vuln_surface as VulnSurface | undefined,
        hypotheses: (obj.vuln_hypotheses as VulnHypothesis[] | undefined) ?? [],
        exploits: (obj.exploit_assets as ExploitAsset[] | undefined) ?? [],
        campaigns: (obj.campaigns as CampaignRecord[] | undefined) ?? [],
      };
    } catch {
      return empty;
    }
  }, [raw]);

  const loadApprovals = React.useCallback(async () => {
    setApprovalsLoading(true);
    try {
      setApprovals(await protocolApi.approvals(caseId));
    } catch {
      /* 列表失败不打断页面 */
    } finally {
      setApprovalsLoading(false);
    }
  }, [caseId]);

  React.useEffect(() => {
    void loadApprovals();
  }, [loadApprovals]);

  const decide = async (id: number) => {
    setBusyId(id);
    try {
      await protocolApi.decideApproval(id, decision, note);
      toast.success(`审批 #${id} 已${decision === "approve" ? "批准" : "拒绝"}`);
      setNote("");
      await loadApprovals();
      await onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "裁决失败（仅 admin 可裁决）");
    } finally {
      setBusyId(null);
    }
  };

  const openScript = async (x: ExploitAsset) => {
    setScriptData(null);
    setScriptOpen(true);
    if (!x.path) {
      setScriptData(null);
      return;
    }
    setScriptLoading(true);
    try {
      // 端点同时接受 findings 登记的绝对路径与 workdir 相对路径。
      const r = await protocolApi.exploitScript(caseId, x.path);
      setScriptData({ name: r.name, size: r.size, sha: x.sha256_16, content: r.content });
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "脚本读取失败");
      setScriptOpen(false);
    } finally {
      setScriptLoading(false);
    }
  };

  const openScriptForHypothesis = (hypId: string) => {
    const x = (parsed.exploits ?? []).find((e) => e.hypothesis === hypId);
    if (!x) {
      toast.info("该假设暂无 EXP（仅 write/destructive 类 confirmed 假设生成）");
      return;
    }
    void openScript(x);
  };

  const evidenceLines = (ev: unknown): string[] => {
    if (!Array.isArray(ev)) return [];
    return ev
      .map((e) => {
        if (typeof e === "string") return e;
        if (e && typeof e === "object") {
          const o = e as Record<string, unknown>;
          return [o.ref, o.note, o.grade ? `[${o.grade}]` : ""].filter(Boolean).join(" ");
        }
        return "";
      })
      .filter(Boolean);
  };

  const confirmed = (parsed.hypotheses ?? []).filter((h) => h.state === "confirmed");
  const others = (parsed.hypotheses ?? []).filter((h) => h.state !== "confirmed");
  const exploitsByHyp = new Map((parsed.exploits ?? []).map((e) => [e.hypothesis ?? "", e]));

  const matrix = parsed.profile?.matrix ?? {};
  const matrixRows = Object.entries(matrix);
  const facts = parsed.profile?.facts ?? {};

  return (
    <div className="space-y-3">
      {!vulnEnabled ? (
        <Card>
          <CardContent className="py-3 text-xs text-muted-foreground">
            本案例未启用漏洞挖掘阶段（config.vuln_enabled=false）。编辑案例配置开启后，P7–P9
            阶段与漏洞视图才会激活。
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">
            设备画像（{facts.vendor || "厂商未知"} {facts.model || ""} {facts.firmware ? `· 固件 ${facts.firmware}` : ""}）
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>能力</TableHead>
                <TableHead>协议内</TableHead>
                <TableHead>专用服务</TableHead>
                <TableHead>物理接口</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {matrixRows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">
                    尚无画像（P7 运行 device_profile.py 后写入）
                  </TableCell>
                </TableRow>
              ) : null}
              {matrixRows.map(([cap, row]) => (
                <TableRow key={cap}>
                  <TableCell className="font-mono text-xs">{cap}</TableCell>
                  {(["protocol", "service", "physical"] as const).map((via) => {
                    const ev = row?.[via] ?? [];
                    return (
                      <TableCell key={via} className="text-xs">
                        {ev.length > 0 ? (
                          <span className="inline-flex items-center gap-1">
                            <span className="rounded bg-green-100 px-1 text-[11px] text-green-800">{ev.length}</span>
                            <span className="text-muted-foreground">{ev[0]?.ref ?? ""}</span>
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    );
                  })}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="px-3 pb-2 text-[11px] text-muted-foreground">
            固件获取：{parsed.profile?.firmware_obtainable ?? "未知"} · 轨道：
            {(parsed.profile?.tracks ?? ["protocol"]).join(" / ")}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">
            适用性判定（
            {(parsed.surface?.applicability?.items ?? []).length} 模板 ·
            适用 {parsed.surface?.applicability?.summary?.applicable ?? 0} ·
            不适用 {parsed.surface?.applicability?.summary?.not_applicable ?? 0} ·
            待探测 {parsed.surface?.applicability?.summary?.unknown ?? 0}）
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>模板</TableHead>
                <TableHead>漏洞类别</TableHead>
                <TableHead>风险</TableHead>
                <TableHead>检测</TableHead>
                <TableHead>判定</TableHead>
                <TableHead>说明</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(parsed.surface?.applicability?.items ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-6 text-center text-xs text-muted-foreground">
                    尚无判定（P7 applicability.py 按 47 子模板三态评估）
                  </TableCell>
                </TableRow>
              ) : null}
              {(parsed.surface?.applicability?.items ?? []).map((it: ApplicabilityItem) => (
                <TableRow key={it.template_id ?? it.name}>
                  <TableCell className="font-mono text-xs">{it.template_id ?? "-"}</TableCell>
                  <TableCell className="text-xs">{vclassLabel(it.vclass)}</TableCell>
                  <TableCell><RiskBadge risk={it.risk} /></TableCell>
                  <TableCell className="text-xs">{it.detection ?? "-"}</TableCell>
                  <TableCell><ApplicabilityBadge state={it.state} /></TableCell>
                  <TableCell className="max-w-[280px] text-xs text-muted-foreground">
                    {it.state === "unknown" && (it.missing_caps?.length ?? 0) > 0
                      ? `缺能力画像：${(it.missing_caps ?? []).join("、")}（P7a 探测补全）`
                      : it.reason ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {(parsed.surface?.applicability?.posture_tasks ?? []).length > 0 ? (
            <p className="px-3 pb-2 text-[11px] text-muted-foreground">
              待探测任务：{(parsed.surface?.applicability?.posture_tasks ?? [])
                .map((t) => `${t.capability}（${t.hint ?? "主动探测"}）`)
                .join("；")}
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">
            CVE 情报匹配（{(parsed.surface?.intel_matches?.merged ?? []).length} 条）
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="flex flex-wrap gap-1.5 px-3 pb-2 pt-2">
            {Object.entries(parsed.surface?.intel_matches?.sources_ok ?? {}).map(([src, ok]) => (
              <span
                key={src}
                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] ${
                  ok ? "bg-green-100 text-green-800" : "bg-gray-100 text-gray-500"
                }`}
              >
                {ok ? "●" : "○"} {src}
              </span>
            ))}
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>CVE</TableHead>
                <TableHead>映射类别</TableHead>
                <TableHead>摘要</TableHead>
                <TableHead>来源</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(parsed.surface?.intel_matches?.merged ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-xs text-muted-foreground">
                    尚无匹配（P7 vuln_intel.py 查 plc-intel / icsvuln / 平台语义层）
                  </TableCell>
                </TableRow>
              ) : null}
              {(parsed.surface?.intel_matches?.merged ?? []).slice(0, 12).map((h: IntelHit, i: number) => (
                <TableRow key={`${h.cve_id ?? i}-${i}`}>
                  <TableCell className="font-mono text-xs">{h.cve_id ?? "-"}</TableCell>
                  <TableCell className="text-xs">{vclassLabel(h.vclass ?? h.vclass_guess)}</TableCell>
                  <TableCell className="max-w-[420px] text-xs text-muted-foreground">
                    <span className="line-clamp-2">{h.summary ?? "-"}</span>
                  </TableCell>
                  <TableCell className="text-xs">{h.source ?? "-"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {(parsed.surface?.intel_matches?.merged ?? []).length > 12 ? (
            <p className="px-3 pb-2 text-[11px] text-muted-foreground">
              仅展示前 12 条，共 {parsed.surface?.intel_matches?.merged?.length ?? 0} 条（findings.vuln_surface.intel_matches）
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card className="border-red-200">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <span className="inline-flex items-center gap-1 rounded bg-red-100 px-1.5 py-0.5 text-[11px] font-semibold text-red-800">
              已确认漏洞 {confirmed.length}
            </span>
            <span className="text-muted-foreground font-normal">
              验证成立 · 点击展开证据与利用代码
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {confirmed.length === 0 ? (
            <p className="py-4 text-center text-xs text-muted-foreground">
              尚无已确认漏洞（P8 验证 confirmed 的假设在此展示）
            </p>
          ) : null}
          {confirmed.map((h) => {
            const exp = exploitsByHyp.get(h.id);
            return (
              <div key={h.id} className="rounded-md border p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] text-muted-foreground">{h.id}</span>
                  <span className="text-sm font-medium">{h.name}</span>
                  <Badge variant={h.risk === "destructive" ? "destructive" : h.risk === "write" ? "outline" : "secondary"} className="text-[11px]">
                    {h.risk ?? "read"}
                  </Badge>
                  <span className="text-[11px] text-muted-foreground">{vclassLabel(h.vclass)}</span>
                  {h.verdict ? (
                    <span className="rounded bg-green-50 px-1.5 py-0.5 font-mono text-[10px] text-green-700">{h.verdict}</span>
                  ) : null}
                </div>
                {h.verdict_reason ? (
                  <p className="mt-1.5 text-xs leading-relaxed">{h.verdict_reason}</p>
                ) : null}
                {evidenceLines(h.evidence).length > 0 ? (
                  <div className="mt-1.5 space-y-0.5">
                    {evidenceLines(h.evidence).slice(0, 4).map((e, i) => (
                      <p key={i} className="font-mono text-[11px] text-muted-foreground">· {e}</p>
                    ))}
                  </div>
                ) : null}
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {exp ? (
                    <>
                      <Button size="sm" className="h-7 px-2 text-[11px]" onClick={() => void openScript(exp)}>
                        <EyeIcon className="mr-1 size-3" /> 查看 EXP 脚本（{exp.tier ?? "replay"}）
                      </Button>
                      <span className="font-mono text-[10px] text-muted-foreground">sha16: {exp.sha256_16}</span>
                    </>
                  ) : (
                    <span className="text-[11px] text-muted-foreground">
                      {h.risk === "read" ? "只读类（无 EXP）" : "EXP 待 P9 生成"}
                    </span>
                  )}
                  {h.plan ? (
                    <span className="text-[11px] text-muted-foreground" title={h.plan}>
                      验证方案：{h.plan.slice(0, 60)}{h.plan.length > 60 ? "…" : ""}
                    </span>
                  ) : null}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">全部假设（{(parsed.hypotheses ?? []).length}）</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>假设</TableHead>
                <TableHead>类</TableHead>
                <TableHead>风险</TableHead>
                <TableHead>检测</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>审批</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(parsed.hypotheses ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-6 text-center text-xs text-muted-foreground">
                    尚无假设（P7 applicability.py 生成）
                  </TableCell>
                </TableRow>
              ) : null}
              {[...confirmed, ...others].map((h) => (
                <TableRow key={h.id} className="cursor-pointer" onClick={() => setExpandedHyp(expandedHyp === h.id ? null : h.id)}>
                  <TableCell className="max-w-[320px] text-xs">
                    <span className="font-mono text-[11px] text-muted-foreground">{h.id}</span>
                    <br />
                    {h.name}
                  </TableCell>
                  <TableCell className="text-xs">
                    {h.vclass ? `${h.vclass}·${VCLASS_NAMES[h.vclass] ?? "?"}` : "-"}
                  </TableCell>
                  <TableCell><RiskBadge risk={h.risk} /></TableCell>
                  <TableCell className="text-xs">{h.detection ?? "-"}</TableCell>
                  <TableCell><HypothesisStateBadge state={h.state} /></TableCell>
                  <TableCell className="text-xs">
                    {h.requires_approval ? <Badge variant="destructive" className="text-[11px]">需要</Badge> : "—"}
                  </TableCell>
                </TableRow>
              ))}
              {expandedHyp && (() => {
                const h = (parsed.hypotheses ?? []).find((x) => x.id === expandedHyp);
                if (!h) return null;
                return (
                  <TableRow>
                    <TableCell colSpan={6} className="bg-muted/40 p-3">
                      <div className="space-y-1.5 text-xs">
                        <p><span className="text-muted-foreground">判定规则：</span>{h.verdict_rule || h.plan || "—"}</p>
                        {h.verdict_reason ? <p><span className="text-muted-foreground">判定结论：</span>{h.verdict_reason}</p> : null}
                        {evidenceLines(h.evidence).length > 0 ? (
                          <div>
                            <span className="text-muted-foreground">证据：</span>
                            {evidenceLines(h.evidence).map((e, i) => (
                              <p key={i} className="ml-2 font-mono text-[11px]">· {e}</p>
                            ))}
                          </div>
                        ) : null}
                        <div className="flex items-center gap-2 pt-1">
                          {exploitsByHyp.has(h.id) ? (
                            <Button size="sm" variant="outline" className="h-7 px-2 text-[11px]" onClick={() => openScriptForHypothesis(h.id)}>
                              <EyeIcon className="mr-1 size-3" /> EXP 脚本
                            </Button>
                          ) : null}
                          <span className="text-[11px] text-muted-foreground">模板 {h.template_id ?? "-"} · 更新 {h.ts ? fmtProtocolTime(h.ts) : "-"}</span>
                        </div>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })()}
            </TableBody>
          </Table>
          <p className="px-3 pb-2 text-[11px] text-muted-foreground">点击任意行展开判定依据与证据。</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">campaign 执行记录（{parsed.campaigns.length}）</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>campaign</TableHead>
                <TableHead>假设</TableHead>
                <TableHead>模式</TableHead>
                <TableHead>风险</TableHead>
                <TableHead>审批</TableHead>
                <TableHead>发包</TableHead>
                <TableHead>结果</TableHead>
                <TableHead>时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {parsed.campaigns.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="py-6 text-center text-xs text-muted-foreground">
                    尚无执行记录（P8 campaign_runner.py：verify 确定性验证 / fuzz 灰盒变异）
                  </TableCell>
                </TableRow>
              ) : null}
              {parsed.campaigns.map((cp) => {
                const crashN = cp.crashes?.length ?? 0;
                const verdictOk = (cp.verify_verdicts ?? []).filter((v) => v.verdict === "confirmed").length;
                const result =
                  cp.result ??
                  (cp.mode === "verify"
                    ? `${verdictOk}/${cp.verify_verdicts?.length ?? 0} 项确认`
                    : `${cp.packets_sent ?? 0} 包 · ${crashN} 崩溃样本${cp.new_classes?.length ? ` · 新响应类 ${cp.new_classes.length}` : ""}`);
                return (
                  <TableRow key={cp.campaign_id ?? cp.started}>
                    <TableCell className="font-mono text-xs">{cp.campaign_id ?? "-"}</TableCell>
                    <TableCell className="font-mono text-xs">{cp.hypothesis ?? "-"}</TableCell>
                    <TableCell><ModeBadge mode={cp.mode} /></TableCell>
                    <TableCell><RiskBadge risk={cp.risk} /></TableCell>
                    <TableCell className="max-w-[120px] truncate font-mono text-xs" title={cp.approval}>
                      {cp.approval && cp.approval !== "-" ? cp.approval : "—"}
                    </TableCell>
                    <TableCell className="text-xs">{cp.packets_sent ?? "-"}</TableCell>
                    <TableCell className="text-xs">
                      <span className="inline-flex flex-wrap items-center gap-1">
                        {cp._redline || cp.guardian?.red_line ? (
                          <span className="rounded bg-red-100 px-1 text-[11px] text-red-800">红线终止</span>
                        ) : null}
                        {cp.circuit_breaker ? (
                          <span className="rounded bg-orange-100 px-1 text-[11px] text-orange-800">熔断</span>
                        ) : null}
                        {crashN > 0 ? (
                          <span className="rounded bg-red-50 px-1 text-[11px] text-red-700">{crashN} crash</span>
                        ) : null}
                        <span className="text-muted-foreground">{result}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-xs">{cp.started ? fmtProtocolTime(cp.started) : "-"}</TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">destructive 审批（operator 创建 · admin 裁决）</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>#</TableHead>
                <TableHead>类型</TableHead>
                <TableHead>风险</TableHead>
                <TableHead>状态</TableHead>
                <TableHead>申请人</TableHead>
                <TableHead>裁决人</TableHead>
                <TableHead>创建时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {approvalsLoading ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-6 text-center">
                    <Loader2Icon className="mx-auto size-4 animate-spin" />
                  </TableCell>
                </TableRow>
              ) : null}
              {!approvalsLoading && approvals.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">
                    暂无审批记录（P8 对 destructive campaign 自动发起；campaign_runner 无批准会拒绝执行）
                  </TableCell>
                </TableRow>
              ) : null}
              {approvals.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="text-xs">{a.id}</TableCell>
                  <TableCell className="text-xs">{a.kind}</TableCell>
                  <TableCell className="text-xs">{a.risk}</TableCell>
                  <TableCell>
                    {a.status === "approved" ? (
                      <span className="inline-flex items-center gap-1 text-xs text-green-700"><ShieldCheckIcon className="size-3.5" />approved</span>
                    ) : a.status === "rejected" ? (
                      <span className="inline-flex items-center gap-1 text-xs text-red-700"><ShieldXIcon className="size-3.5" />rejected</span>
                    ) : (
                      <HypothesisStateBadge state="pending" />
                    )}
                  </TableCell>
                  <TableCell className="text-xs">{a.requested_by || "-"}</TableCell>
                  <TableCell className="text-xs">{a.decided_by || "-"}</TableCell>
                  <TableCell className="text-xs">{fmtProtocolTime(a.created_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <div className="flex flex-wrap items-end gap-2">
            <div className="w-64">
              <Label className="text-xs">裁决意见（可选）</Label>
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="lab 批准 / 风险说明" className="text-xs" />
            </div>
            <Select value={decision} onValueChange={(v) => setDecision(v as "approve" | "reject")}>
              <SelectTrigger className="w-28"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="approve">批准</SelectItem>
                <SelectItem value="reject">拒绝</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={String(busyId ?? "")}
              onValueChange={(v) => setBusyId(Number(v))}
            >
              <SelectTrigger className="w-36"><SelectValue placeholder="选择待裁决项" /></SelectTrigger>
              <SelectContent>
                {approvals.filter((a) => a.status === "pending").map((a) => (
                  <SelectItem key={a.id} value={String(a.id)}>审批 #{a.id}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              disabled={busyId === null}
              onClick={() => busyId !== null && void decide(busyId)}
            >
              提交裁决
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">EXP 资产（{(parsed.exploits ?? []).length}）</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>EXP</TableHead>
                <TableHead>假设</TableHead>
                <TableHead>级别</TableHead>
                <TableHead>风险</TableHead>
                <TableHead>路径</TableHead>
                <TableHead>SHA16</TableHead>
                <TableHead className="w-20">脚本</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(parsed.exploits ?? []).length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="py-6 text-center text-xs text-muted-foreground">
                    尚无 EXP（P9 exp_gen.py 对 confirmed 假设生成）
                  </TableCell>
                </TableRow>
              ) : null}
              {(parsed.exploits ?? []).map((x) => (
                <TableRow key={x.id}>
                  <TableCell className="font-mono text-xs">{x.id}</TableCell>
                  <TableCell className="font-mono text-xs">{x.hypothesis ?? "-"}</TableCell>
                  <TableCell className="text-xs">
                    {x.tier === "chain" ? (
                      <Badge variant="destructive" className="text-[11px]">chain</Badge>
                    ) : x.tier === "poc" ? (
                      <Badge variant="outline" className="text-[11px]">poc</Badge>
                    ) : (
                      <Badge variant="secondary" className="text-[11px]">{x.tier ?? "replay"}</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-xs">{x.risk ?? "-"}</TableCell>
                  <TableCell className="max-w-[240px] truncate font-mono text-xs" title={x.path}>{x.path ?? "-"}</TableCell>
                  <TableCell className="font-mono text-xs">{x.sha256_16 ?? "-"}</TableCell>
                  <TableCell>
                    <Button size="sm" variant="outline" className="h-7 px-2 text-[11px]" onClick={() => void openScript(x)}>
                      <EyeIcon className="mr-1 size-3" /> 查看
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <p className="px-3 pb-2 text-[11px] text-muted-foreground">
            级别：replay 重放帧 → poc 概念验证 → chain 多步利用链；脚本零依赖、自带 --dry-run 安全模式。
          </p>
        </CardContent>
      </Card>

      <Dialog open={scriptOpen} onOpenChange={setScriptOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono text-sm">
              {scriptData?.name ?? "EXP 脚本"}
              {scriptData?.sha ? <span className="text-[11px] font-normal text-muted-foreground">sha16: {scriptData.sha}</span> : null}
            </DialogTitle>
            <DialogDescription>
              独立可执行 PoC（{scriptData ? `${scriptData.size} 字节` : "加载中"}）· 运行需 --target 指定实验室设备
            </DialogDescription>
          </DialogHeader>
          {scriptLoading ? (
            <div className="flex justify-center py-8"><Loader2Icon className="size-5 animate-spin" /></div>
          ) : scriptData ? (
            <>
              <div className="flex justify-end">
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 px-2 text-[11px]"
                  onClick={() => {
                    void navigator.clipboard.writeText(scriptData.content).then(
                      () => toast.success("脚本已复制"),
                      () => toast.error("复制失败"),
                    );
                  }}
                >
                  <CopyIcon className="mr-1 size-3" /> 复制
                </Button>
              </div>
              <ScrollArea className="h-[420px] rounded border bg-muted/40">
                <pre className="p-3 font-mono text-[11px] leading-relaxed">{scriptData.content}</pre>
              </ScrollArea>
            </>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
