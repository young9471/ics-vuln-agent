"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import {
  ArrowLeftIcon,
  BotIcon,
  CircleCheckIcon,
  CircleXIcon,
  ClockIcon,
  FileTextIcon,
  Loader2Icon,
  PackagePlusIcon,
  PencilIcon,
  RadioIcon,
  RefreshCwIcon,
  SquareIcon,
  UploadIcon,
} from "lucide-react";
import { toast } from "sonner";

import { useCurrentUser } from "@/hooks/use-current-user";

import { Markdown } from "@/components/markdown";
import { ProtocolVulnView } from "@/components/protocol-vuln-view";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  fmtProtocolTime,
  codeDisplay,
  GRADE_META,
  hexCode,
  isLiveVerified,
  PHASES,
  PHASE_META,
  V2_PHASES,
  protocolApi,
  protocolEventStreamUrl,
  type ProtocolAuthorization,
  type ProtocolCase,
  type ProtocolCaseDetail,
  type ProtocolCaptureStatus,
  type ProtocolEvent,
  type ProtocolReportVersion,
  type ProtocolPcapQuality,
  type ProtocolPhaseMetric,
  type ProtocolAgentUsage,
  type ProtocolField,
  type ProtocolFieldMap,
  type ProtocolFunctionCode,
  type ProtocolNote,
  type ProtocolPhase,
  type ProtocolProbe,
} from "@/lib/protocol-api";
import {
  fieldValuesText,
  findingMeta,
  reconciliationItems,
  scalarText,
  unwrapNotePayload,
} from "@/lib/findings-format";

const STATUS_LABEL: Record<string, string> = {
  draft: "草稿",
  queued: "排队中",
  running: "运行中",
  paused: "已暂停",
  done: "已完成",
  failed: "失败",
};

const PHASE_CLASS: Record<string, string> = {
  pass: "border-emerald-500/40 bg-emerald-500/5",
  fail: "border-red-500/40 bg-red-500/5",
  running: "border-blue-500/40 bg-blue-500/5",
  skip: "border-border bg-muted/30",
};

const GRADE_CLASS: Record<string, string> = {
  traffic: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-400",
  live: "bg-blue-500/15 text-blue-700 dark:text-blue-400",
  static: "bg-amber-500/15 text-amber-700 dark:text-amber-400",
  inferred: "bg-zinc-500/15 text-zinc-600 dark:text-zinc-400",
};

function GradeBadge({ grade }: { grade: string }) {
  return (
    <span
      title={GRADE_META[grade]?.title}
      className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${GRADE_CLASS[grade] ?? "bg-muted text-muted-foreground"}`}
    >
      {grade || "-"}
    </span>
  );
}

const VERDICT_CLASS: Record<string, string> = {
  matched: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  conflicting: "bg-red-500/15 text-red-600 dark:text-red-400",
  "traffic-only": "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  "static-only": "bg-violet-500/15 text-violet-600 dark:text-violet-400",
};

function VerdictBadge({ verdict }: { verdict?: string }) {
  if (!verdict) return <span className="text-xs text-muted-foreground">-</span>;
  return (
    <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${VERDICT_CLASS[verdict] ?? "bg-muted text-muted-foreground"}`}>
      {verdict}
    </span>
  );
}

function SessionModelPanels({ notes }: { notes: ProtocolNote[] }) {
  const finalModels = notes.filter((n) => n.kind === "session-model-final");
  const models = finalModels.length > 0 ? finalModels : notes.filter((n) => n.kind === "session-model");
  if (models.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center text-sm text-muted-foreground">
          尚无会话状态机记录。P3 运行 session_model.py 后写入，P5 交叉验证后产出最终状态机。
        </CardContent>
      </Card>
    );
  }
  return (
    <div className="space-y-3">
      {models.map((note) => {
        // P5 agents have written both flat and double-nested payloads; the
        // helper unwraps one extra level so both forms render.
        const p = unwrapNotePayload(note);
        const isFinal = note.kind === "session-model-final";
        const transitions = Array.isArray(p.transitions) ? (p.transitions as Array<Record<string, unknown>>) : [];
        const verifiedTransitions = Array.isArray(p.verified_transitions)
          ? (p.verified_transitions as Array<Record<string, unknown>>)
          : [];
        const rows = verifiedTransitions.length > 0 ? verifiedTransitions : transitions;
        const rowsWithEvidence = rows.some((t) => t.verified !== undefined || t.evidence !== undefined);
        const transitionText = (t: Record<string, unknown>) =>
          scalarText(t.transition ?? (t.from !== undefined || t.to !== undefined ? `${scalarText(t.from)} → ${scalarText(t.to)}` : undefined));
        const states = Array.isArray(p.states) ? p.states.map((s) => scalarText(s)) : [];
        const sequence = Array.isArray(p.minimal_sequence) ? (p.minimal_sequence as Array<Record<string, unknown>>) : [];
        const countText = (v: unknown) => (Array.isArray(v) ? String(v.length) : scalarText(v));
        const fragments = p.fragments && typeof p.fragments === "object" && !Array.isArray(p.fragments)
          ? (p.fragments as Record<string, unknown>)
          : null;
        const summary = typeof p.summary === "string" ? p.summary : "";
        const closeNote = typeof p.close === "string"
          ? p.close
          : p.close && typeof p.close === "object"
            ? scalarText((p.close as Record<string, unknown>).note)
            : "";
        const seqP2 = typeof p.observed_sequence_p2 === "string" ? p.observed_sequence_p2 : "";
        const seqP5 = typeof p.observed_sequence_p5 === "string" ? p.observed_sequence_p5 : "";
        const hasStats = ["messages", "requests", "responses"].some((k) => p[k] !== undefined) ||
          p.retries !== undefined || p.timeouts !== undefined || p.fragments !== undefined;
        return (
          <Card key={note.id}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 font-mono text-sm">
                {scalarText(p.stream ?? `note ${note.id}`)}
                {isFinal ? <Badge variant="outline" className="text-[10px]">P5 最终</Badge> : null}
              </CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3">
              {summary ? <p className="text-xs text-muted-foreground">{summary}</p> : null}
              {states.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {states.map((s) => (
                    <Badge key={s} variant="outline" className="font-mono text-[10px]">{s}</Badge>
                  ))}
                </div>
              ) : null}
              {hasStats ? (
                <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
                  <div><div className="text-muted-foreground">消息</div><div className="font-semibold">{scalarText(p.messages)}</div></div>
                  <div><div className="text-muted-foreground">请求/响应</div><div className="font-semibold">{scalarText(p.requests)}/{scalarText(p.responses)}</div></div>
                  <div><div className="text-muted-foreground">重试/超时</div><div className="font-semibold">{countText(p.retries)}/{countText(p.timeouts)}</div></div>
                  <div><div className="text-muted-foreground">TCP 空洞/重叠</div><div className="font-semibold">{fragments ? `${scalarText(fragments.gaps)}/${scalarText(fragments.overlaps)}` : scalarText(p.fragments)}</div></div>
                </div>
              ) : null}
              {rows.length > 0 ? (
                <div className="overflow-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>状态迁移</TableHead>
                        <TableHead>{rowsWithEvidence ? "验证" : "次数"}</TableHead>
                        {rowsWithEvidence ? <TableHead>证据</TableHead> : null}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rows.slice(0, 30).map((t, i) => (
                        <TableRow key={`${transitionText(t)}-${i}`}>
                          <TableCell className="font-mono text-xs">{transitionText(t)}</TableCell>
                          <TableCell className="text-xs">
                            {rowsWithEvidence
                              ? t.verified === true
                                ? <Badge>是</Badge>
                                : <span className="text-muted-foreground">否</span>
                              : scalarText(t.count)}
                          </TableCell>
                          {rowsWithEvidence ? (
                            <TableCell className="max-w-[320px] break-all text-xs text-muted-foreground">{scalarText(t.evidence)}</TableCell>
                          ) : null}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : null}
              {sequence.length > 0 ? (
                <div className="overflow-auto">
                  <Table>
                    <TableHeader><TableRow><TableHead>最小会话序列</TableHead><TableHead>请求帧</TableHead><TableHead>响应帧</TableHead></TableRow></TableHeader>
                    <TableBody>
                      {sequence.map((s, i) => (
                        <TableRow key={`${String(s.request)}-${String(s.response)}-${i}`}>
                          <TableCell className="font-mono text-xs">{scalarText(s.request)} → {scalarText(s.response)}</TableCell>
                          <TableCell className="text-xs">{scalarText(s.request_frame)}</TableCell>
                          <TableCell className="text-xs">{scalarText(s.response_frame)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : null}
              {seqP2 || seqP5 ? (
                <div className="grid gap-1.5 text-xs">
                  {seqP2 ? <div><span className="text-muted-foreground">P2 观测序列：</span><span className="break-all font-mono text-[11px]">{seqP2}</span></div> : null}
                  {seqP5 ? <div><span className="text-muted-foreground">P5 验证序列：</span><span className="break-all font-mono text-[11px]">{seqP5}</span></div> : null}
                </div>
              ) : null}
              {closeNote ? <p className="text-xs text-muted-foreground">关闭语义：{closeNote}</p> : null}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

function CodeEditDialog({
  caseId,
  code,
  open,
  onOpenChange,
  onSaved,
}: {
  caseId: number;
  code: ProtocolFunctionCode | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
}) {
  const [label, setLabel] = React.useState("");
  const [grade, setGrade] = React.useState("traffic");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open || !code) return;
    setLabel(code.label || "");
    setGrade(code.grade || "traffic");
  }, [open, code]);

  async function save() {
    if (!code) return;
    if (!label.trim()) {
      toast.error("请填写语义标签");
      return;
    }
    setSaving(true);
    try {
      await protocolApi.updateCode(caseId, code.id, { label: label.trim(), grade });
      toast.success("功能码已更新");
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>编辑功能码</DialogTitle>
          <DialogDescription>{code ? `${codeDisplay(code)} · ${code.layer || "-"}` : ""}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label>语义标签</Label>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label>证据等级</Label>
            <Select value={grade} onValueChange={setGrade}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="traffic">traffic</SelectItem>
                <SelectItem value="live">live</SelectItem>
                <SelectItem value="static">static</SelectItem>
                <SelectItem value="inferred">inferred</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={() => void save()} disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ReconciliationPanel({ notes }: { notes: ProtocolNote[] }) {
  const items = reconciliationItems(notes);
  const [verdict, setVerdict] = React.useState("all");
  if (items.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-muted-foreground">
          P5 尚未产出交叉佐证（notes kind=code-reconciliation）
        </CardContent>
      </Card>
    );
  }
  const filtered = verdict === "all" ? items : items.filter((item) => (typeof item.verdict === "string" ? item.verdict : "none") === verdict);
  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center gap-2 pb-2">
        <CardTitle className="mr-auto text-sm">P3 流量 × P4 静态 交叉佐证（{filtered.length}/{items.length}）</CardTitle>
        <Select value={verdict} onValueChange={setVerdict}>
          <SelectTrigger className="h-7 w-[150px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部结论</SelectItem>
            <SelectItem value="matched">matched</SelectItem>
            <SelectItem value="conflicting">conflicting</SelectItem>
            <SelectItem value="traffic-only">traffic-only</SelectItem>
            <SelectItem value="static-only">static-only</SelectItem>
            <SelectItem value="none">未标 verdict</SelectItem>
          </SelectContent>
        </Select>
      </CardHeader>
      <CardContent className="overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>功能码</TableHead>
              <TableHead>流量语义</TableHead>
              <TableHead>静态语义</TableHead>
              <TableHead>结论</TableHead>
              <TableHead>备注</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 ? <EmptyRow colSpan={5} text="没有符合筛选的佐证" /> : null}
            {filtered.map((item, i) => (
              <TableRow key={`${String(item.code)}-${i}`}>
                <TableCell className="font-mono text-xs">{scalarText(item.code)}</TableCell>
                <TableCell className="max-w-[280px] break-all text-xs">{scalarText(item.traffic ?? item.traffic_label)}</TableCell>
                <TableCell className="max-w-[280px] break-all text-xs">{scalarText(item.static ?? item.static_label)}</TableCell>
                <TableCell>
                  <VerdictBadge verdict={typeof item.verdict === "string" ? item.verdict : undefined} />
                </TableCell>
                <TableCell className="max-w-[260px] break-all text-xs text-muted-foreground">{scalarText(item.note)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

function PhaseIcon({ status }: { status: string }) {
  if (status === "pass") return <CircleCheckIcon className="size-4 text-emerald-500" />;
  if (status === "fail") return <CircleXIcon className="size-4 text-red-500" />;
  if (status === "running") return <Loader2Icon className="size-4 animate-spin text-blue-500" />;
  return <ClockIcon className="size-4 text-muted-foreground" />;
}

function PhaseCard({ phase, onCancel }: { phase: ProtocolPhase; onCancel?: () => void }) {
  const meta = PHASE_META[phase.phase];
  return (
    <Card className={`${PHASE_CLASS[phase.status] ?? ""}`}>
      <CardHeader className="flex-row items-start justify-between gap-2 pb-2">
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2 text-sm">
            <PhaseIcon status={phase.status} />
            {meta?.title ?? phase.phase}
            <Badge variant="outline" className="ml-1 text-[10px]">
              门 {phase.gate}
            </Badge>
          </CardTitle>
          <p className="mt-1 text-xs text-muted-foreground">{meta?.desc}</p>
        </div>
        {phase.status === "running" && onCancel ? (
          <Button size="sm" variant="ghost" onClick={onCancel} title="只取消这个阶段">
            <SquareIcon className="size-3.5" />
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-1 pt-0">
        <div className="text-xs">
          <span className="text-muted-foreground">状态：</span>
          <span className="font-medium">{phase.status}</span>
        </div>
        {phase.detail ? <p className="break-words text-xs text-muted-foreground">{phase.detail}</p> : null}
        {phase.finished_at ? (
          <p className="text-[11px] text-muted-foreground">完成于 {fmtProtocolTime(phase.finished_at)}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function EmptyRow({ colSpan, text }: { colSpan: number; text: string }) {
  return (
    <TableRow>
      <TableCell colSpan={colSpan} className="h-24 text-center text-sm text-muted-foreground">
        {text}
      </TableCell>
    </TableRow>
  );
}

function FieldMapCard({ map }: { map: ProtocolFieldMap }) {
  const fields = Array.isArray(map.fields) ? map.fields : [];
  const tail = map.tail && typeof map.tail === "object" ? map.tail : null;
  const lenRange = tail && Array.isArray(tail.len_range) ? tail.len_range : [];
  const meta = findingMeta(map);
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          {map.map_key || "-"}
          <Badge variant="outline">{map.direction || "?"}</Badge>
          <GradeBadge grade={map.grade} />
          <VerdictBadge verdict={meta.verdict} />
          <span className="text-xs font-normal text-muted-foreground">
            {map.samples} 样本 · 帧长 {map.frame_len_min}~{map.frame_len_max}B
            {meta.source ? ` · ${meta.source}` : ""}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>字段</TableHead>
              <TableHead>偏移</TableHead>
              <TableHead>长度</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>分类</TableHead>
              <TableHead>值/样本</TableHead>
              <TableHead>判据</TableHead>
              <TableHead>证据</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {fields.length === 0 ? <EmptyRow colSpan={8} text="无字段" /> : null}
            {fields.map((f, i) => (
              <TableRow key={`${map.map_key}-${i}`}>
                <TableCell className="font-mono text-xs">{scalarText(f.name || f.kind || f.class)}</TableCell>
                <TableCell className="font-mono text-xs">{scalarText(f.off ?? f.offset)}</TableCell>
                <TableCell className="font-mono text-xs">{scalarText(f.size ?? f.width)}</TableCell>
                <TableCell className="text-xs">{scalarText(f.type)}</TableCell>
                <TableCell className="text-xs">{scalarText(f.class || f.kind)}</TableCell>
                <TableCell className="max-w-[220px] truncate font-mono text-xs">{fieldValuesText(f)}</TableCell>
                <TableCell className="max-w-[220px] truncate text-xs">{scalarText(f.note)}</TableCell>
                <TableCell className="max-w-[220px] truncate text-xs">{scalarText(f.evidence)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {tail ? (
          <p className="mt-2 text-xs text-muted-foreground">
            变长尾部：从偏移 {scalarText(tail.from_off)} 起，长度范围 {scalarText(lenRange[0])}~{scalarText(lenRange[1])}B
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function LogView({ caseId, active }: { caseId: number; active: boolean }) {
  const [events, setEvents] = React.useState<ProtocolEvent[]>([]);
  const [connected, setConnected] = React.useState(false);
  const endRef = React.useRef<HTMLDivElement | null>(null);
  const sinceRef = React.useRef(0);

  React.useEffect(() => {
    if (!active || !caseId) return;
    let closed = false;
    setEvents([]);
    sinceRef.current = 0;
    const es = new EventSource(protocolEventStreamUrl(caseId, 0));
    es.onopen = () => setConnected(true);
    es.onmessage = (ev) => {
      try {
        const e = JSON.parse(ev.data) as ProtocolEvent;
        sinceRef.current = Math.max(sinceRef.current, e.id);
        setEvents((prev) => (prev.some((x) => x.id === e.id) ? prev : [...prev, e].slice(-800)));
      } catch {
        // ignore malformed frame
      }
    };
    es.onerror = () => {
      setConnected(false);
      if (closed) es.close();
    };
    return () => {
      closed = true;
      es.close();
    };
  }, [active, caseId]);

  React.useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [events]);

  return (
    <div className="rounded-lg border bg-black/90 text-zinc-100">
      <div className="flex items-center justify-between border-b border-white/10 px-3 py-1.5 text-[11px] text-zinc-400">
        <span>执行日志（SSE 实时）</span>
        <span className={connected ? "text-emerald-400" : "text-zinc-500"}>{connected ? "已连接" : "未连接"}</span>
      </div>
      <ScrollArea className="h-[520px]">
        <div className="space-y-0.5 p-3 font-mono text-[11px] leading-relaxed">
          {events.length === 0 ? <div className="text-zinc-500">等待事件…</div> : null}
          {events.map((e) => (
            <div
              key={e.id}
              className={
                e.kind === "stderr" || e.kind === "error"
                  ? "text-red-400"
                  : e.kind === "gate"
                    ? "text-amber-300"
                    : e.kind === "phase" || e.kind === "status"
                      ? "text-sky-300"
                      : "text-zinc-300"
              }
            >
              <span className="mr-2 text-zinc-600">{e.phase || "-"}</span>
              <span className="mr-2 text-zinc-500">[{e.kind}]</span>
              {e.message}
            </div>
          ))}
          <div ref={endRef} />
        </div>
      </ScrollArea>
    </div>
  );
}

function CaptureDialog({
  caseId,
  deviceIP,
  open,
  onOpenChange,
  onCaptured,
}: {
  caseId: number;
  deviceIP: string;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onCaptured: () => void;
}) {
  const [interfaces, setInterfaces] = React.useState<{ id: string; name: string }[]>([]);
  const [iface, setIface] = React.useState("");
  const [filter, setFilter] = React.useState("");
  const [duration, setDuration] = React.useState("300");
  const [status, setStatus] = React.useState<ProtocolCaptureStatus | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const refreshStatus = React.useCallback(async () => {
    try { setStatus(await protocolApi.captureStatus(caseId)); }
    catch { /* keep last status */ }
  }, [caseId]);

  React.useEffect(() => {
    if (!open) return;
    setError("");
    protocolApi.captureInterfaces()
      .then((list) => {
        setInterfaces(list);
        if (!iface && list.length > 0) setIface(list[0].id);
      })
      .catch((e) => setError((e as Error).message));
    void refreshStatus();
  }, [open, caseId, iface, refreshStatus]);

  React.useEffect(() => {
    if (!open || !status?.running) return;
    const t = window.setInterval(() => {
      void protocolApi.captureStatus(caseId).then((s) => {
        setStatus(s);
        if (!s.running) onCaptured();
      }).catch(() => {});
    }, 2000);
    return () => window.clearInterval(t);
  }, [open, status?.running, caseId, onCaptured]);

  async function start() {
    if (!iface) { toast.error("请选择网卡"); return; }
    setBusy(true); setError("");
    try {
      const s = await protocolApi.startCapture(caseId, {
        interface: iface, filter: filter.trim() || undefined,
        duration_seconds: Math.max(1, Number(duration) || 300),
      });
      setStatus(s);
      toast.success("后台抓包已启动");
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  async function stop() {
    setBusy(true);
    try {
      await protocolApi.stopCapture(caseId);
      await refreshStatus();
      toast.success("已请求停止抓包");
      onCaptured();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><RadioIcon className="size-4" /> 后台抓包</DialogTitle>
          <DialogDescription>
            选择网卡后启动 tshark。抓包期间请打开上位机软件、连接 PLC，并执行至少 3 种不同操作。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label>网卡</Label>
            <Select value={iface} onValueChange={setIface}>
              <SelectTrigger><SelectValue placeholder="选择网卡" /></SelectTrigger>
              <SelectContent>
                {interfaces.map((it) => <SelectItem key={it.id} value={it.id}>{it.id} · {it.name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>设备 IP / 捕获过滤（可选）</Label>
              <Input value={filter} onChange={(e) => setFilter(e.target.value)}
                placeholder={deviceIP ? `host ${deviceIP} and not arp and not icmp` : "not arp and not icmp"} />
              <p className="text-muted-foreground text-xs">
                可直接填设备 IP（自动转为 host 过滤），或填完整 BPF 表达式；留空则使用案例设备 IP。
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label>最长时长（秒）</Label>
              <Input type="number" min={1} max={3600} value={duration} onChange={(e) => setDuration(e.target.value)} />
            </div>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          {status && status.status !== "idle" && (
            <div className="grid gap-1 rounded-md border p-3 text-xs">
              <div>状态：<span className="font-medium">{status.status}</span></div>
              {status.path && <div className="break-all font-mono">文件：{status.path}</div>}
              {typeof status.bytes === "number" && <div>大小：{status.bytes} bytes</div>}
              {status.error && <div className="text-destructive">{status.error}</div>}
            </div>
          )}
          <p className="text-muted-foreground text-xs">
            操作提示：打开软件 → 打开工程 → 连接/登录 → 在线停留 → 读取/写入/刷新 → 登出。
            报错也没关系，握手流量在报错前已经发出。
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>关闭</Button>
          {status?.running ? (
            <Button variant="destructive" onClick={() => void stop()} disabled={busy}>停止抓包</Button>
          ) : (
            <Button onClick={() => void start()} disabled={busy || !iface}>{busy ? "启动中…" : "开始抓包"}</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function EditCaseDialog({
  c,
  open,
  onOpenChange,
  onSaved,
}: {
  c: ProtocolCase;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
}) {
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [installRoot, setInstallRoot] = React.useState("");
  const [deviceIP, setDeviceIP] = React.useState("");
  const [mode, setMode] = React.useState<"live" | "static">("static");
  const [authorization, setAuthorization] = React.useState<ProtocolAuthorization>("read-only");
  const [pcapPath, setPcapPath] = React.useState("");
  const [dll, setDll] = React.useState("");
  const [vulnEnabled, setVulnEnabled] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setName(c.name);
    setDescription(c.description || "");
    setInstallRoot(c.install_root || "");
    setDeviceIP(c.device_ip || "");
    setMode(c.mode === "live" ? "live" : "static");
    setAuthorization((c.authorization as ProtocolAuthorization) || "read-only");
    const cfg = (c.config || {}) as Record<string, unknown>;
    const gold = (cfg.golden_artifacts || {}) as Record<string, unknown>;
    setPcapPath(typeof gold.pcap_codesys === "string" ? gold.pcap_codesys : "");
    setDll(typeof gold.comm_dll === "string" ? gold.comm_dll : "");
    setVulnEnabled(Boolean(cfg.vuln_enabled));
  }, [open, c]);

  async function save() {
    if (!name.trim()) {
      toast.error("请填写案例名称");
      return;
    }
    if (mode === "live" && !deviceIP.trim()) {
      toast.error("live 模式必须填写设备 IP");
      return;
    }
    if (mode === "static" && !pcapPath.trim()) {
      toast.error("static 模式必须填写抓包文件路径");
      return;
    }
    setSaving(true);
    try {
      const cfg = { ...((c.config || {}) as Record<string, unknown>) };
      const gold = { ...(((cfg.golden_artifacts || {}) as Record<string, unknown>)) };
      if (pcapPath.trim()) gold.pcap_codesys = pcapPath.trim();
      else delete gold.pcap_codesys;
      if (dll.trim()) gold.comm_dll = dll.trim();
      else delete gold.comm_dll;
      if (Object.keys(gold).length) cfg.golden_artifacts = gold;
      else delete cfg.golden_artifacts;
      if (vulnEnabled) cfg.vuln_enabled = true;
      else delete cfg.vuln_enabled;
      await protocolApi.updateCase(c.id, {
        name: name.trim(),
        description: description.trim(),
        install_root: installRoot.trim(),
        device_ip: deviceIP.trim(),
        authorization,
        mode,
        config: cfg,
      });
      toast.success("案例已更新");
      onOpenChange(false);
      onSaved();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>编辑案例</DialogTitle>
          <DialogDescription>分析运行中不建议修改输入；安装目录、模式、pcap、DLL 会直接影响后续阶段。</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid gap-1.5">
            <Label>案例名称</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label>描述</Label>
            <Textarea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>安装目录</Label>
              <Input value={installRoot} onChange={(e) => setInstallRoot(e.target.value)} />
            </div>
            <div className="grid gap-1.5">
              <Label>设备 IP（live 必填）</Label>
              <Input value={deviceIP} onChange={(e) => setDeviceIP(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>案例模式</Label>
              <Select value={mode} onValueChange={(v) => setMode(v as "live" | "static")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="live">live（在线验证，需设备 IP）</SelectItem>
                  <SelectItem value="static">static（离线分析，需 pcap）</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>授权级别</Label>
              <Select value={authorization} onValueChange={(v) => setAuthorization(v as ProtocolAuthorization)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="read-only">只读</SelectItem>
                  <SelectItem value="write">允许写变量/参数</SelectItem>
                  <SelectItem value="destructive">允许复位/破坏类</SelectItem>
                  <SelectItem value="full">完整授权（测试设备）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label>抓包文件（static 必填）</Label>
            <Input value={pcapPath} onChange={(e) => setPcapPath(e.target.value)} placeholder="D:\\captures\\session1.pcapng" />
          </div>
          <div className="grid gap-1.5">
            <Label>通信 DLL 路径（可选）</Label>
            <Input value={dll} onChange={(e) => setDll(e.target.value)} placeholder="上传 .dll 后会自动填入，也可手动修改" />
          </div>
          <div className="flex items-start gap-3 rounded-md border p-3">
            <Switch
              id="ec-vuln"
              checked={vulnEnabled}
              onCheckedChange={setVulnEnabled}
              className="mt-0.5"
            />
            <div className="space-y-0.5">
              <Label htmlFor="ec-vuln" className="cursor-pointer">启用漏洞挖掘（P7-P9）</Label>
              <p className="text-muted-foreground text-xs">
                开启后本案例在 P1-P6 逆向通过后继续 P7 漏洞面测绘 → P8 验证与 Fuzz →
                P9 EXP 与报告；关闭则只做协议逆向。运行中修改不影响已完成的阶段。
              </p>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={() => void save()} disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function probeCode(p: ProtocolProbe): number | null {
  if (p.payload && typeof p.payload === "object") {
    const code = (p.payload as Record<string, unknown>).code;
    if (typeof code === "number") return code;
    if (typeof code === "string") {
      const n = Number(code);
      if (Number.isFinite(n)) return n;
    }
  }
  const m = /0x([0-9a-f]+)/i.exec(p.action || "");
  return m ? Number.parseInt(m[1], 16) : null;
}

function CaseDetailInner() {
  const currentUser = useCurrentUser();
  const searchParams = useSearchParams();
  const router = useRouter();
  const id = Number(searchParams.get("id") ?? 0);
  const [detail, setDetail] = React.useState<ProtocolCaseDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [agentBusy, setAgentBusy] = React.useState(false);
  const [tab, setTab] = React.useState("pipeline");
  const [reportKey, setReportKey] = React.useState("");
  const [versionsOpen, setVersionsOpen] = React.useState(false);
  const [metrics, setMetrics] = React.useState<{ phases: ProtocolPhaseMetric[]; agents: ProtocolAgentUsage[] }>({ phases: [], agents: [] });
  const [pcaps, setPcaps] = React.useState<ProtocolPcapQuality[]>([]);
  const [pcapLoading, setPcapLoading] = React.useState(false);
  const [versions, setVersions] = React.useState<ProtocolReportVersion[]>([]);
  const [versionDoc, setVersionDoc] = React.useState("");
  const [versionA, setVersionA] = React.useState("");
  const [versionB, setVersionB] = React.useState("");
  const [editOpen, setEditOpen] = React.useState(false);
  const [editCode, setEditCode] = React.useState<ProtocolFunctionCode | null>(null);
  const [codeVerdict, setCodeVerdict] = React.useState("all");
  const [captureOpen, setCaptureOpen] = React.useState(false);
  const [uploadingArtifact, setUploadingArtifact] = React.useState(false);
  const fileRef = React.useRef<HTMLInputElement | null>(null);
  const artifactRef = React.useRef<HTMLInputElement | null>(null);

  const load = React.useCallback(async () => {
    if (!id) {
      setLoading(false);
      return;
    }
    try {
      const d = await protocolApi.getCase(id);
      setDetail(d);
      if (!reportKey && d.reports && d.reports.length > 0) {
        setReportKey(d.reports[0].doc_type);
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [id, reportKey]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // While the pipeline is running, refresh phases/findings every 3 s so the
  // static page stays useful even if the SSE tab is closed.
  React.useEffect(() => {
    if (!detail?.running) return;
    const t = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(t);
  }, [detail?.running, load]);

  React.useEffect(() => {
    if (tab !== "pcap" || !id) return;
    setPcapLoading(true);
    protocolApi.pcapQuality(id)
      .then(setPcaps)
      .catch((e) => toast.error(`pcap 检查失败：${(e as Error).message}`))
      .finally(() => setPcapLoading(false));
  }, [tab, id]);

  React.useEffect(() => {
    if (tab !== "pipeline" || !id) return;
    protocolApi.metrics(id)
      .then((r) => setMetrics({ phases: r.phases ?? [], agents: r.agents ?? [] }))
      .catch(() => {});
  }, [tab, id]);

  const runAgent = async () => {
    setAgentBusy(true);
    try {
      const r = await protocolApi.agentRun(id);
      toast.success("协议主控已启动，正在打开对话…");
      router.push(`/chat?c=${r.conversation_id}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "启动 Agent 失败（请先在系统 → LLM 配置可用模型）");
    } finally {
      setAgentBusy(false);
    }
  };

  const upload = async (file: File | null) => {
    if (!file) return;
    try {
      await protocolApi.uploadPcap(id, file);
      toast.success("pcap 已上传");
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "上传失败");
    } finally {
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const openVersions = async (report: { doc_type: string; version: number }) => {
    try {
      const items = await protocolApi.reportVersions(id, report.doc_type);
      setVersions(items);
      setVersionDoc(report.doc_type);
      setVersionA(String(items[0]?.version ?? ""));
      setVersionB(String(items[1]?.version ?? items[0]?.version ?? ""));
      setVersionsOpen(true);
    } catch (e) {
      toast.error(`读取版本失败：${(e as Error).message}`);
    }
  };

  const approveReport = async (report: { doc_type: string }) => {
    try {
      await protocolApi.approveReport(id, report.doc_type);
      toast.success("报告已批准为当前交付版本");
      await load();
    } catch (e) {
      toast.error(`批准失败：${(e as Error).message}`);
    }
  };

  const cancelPhase = async (phase: string) => {
    try {
      await protocolApi.cancelPhaseJob(id, phase);
      toast.success(`已请求取消 ${phase}`);
      await load();
    } catch (e) {
      toast.error(`取消失败：${(e as Error).message}`);
    }
  };

  const downloadReports = async () => {
    try {
      const blob = await protocolApi.exportReports(id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case-${id}-reports.zip`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      toast.error((e as Error).message);
    }
  };

  const uploadArtifact = async (file: File | null) => {
    if (!file) return;
    setUploadingArtifact(true);
    try {
      const r = await protocolApi.uploadArtifact(id, file);
      toast.success(`工件已上传：${r.name}`);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "工件上传失败");
    } finally {
      setUploadingArtifact(false);
      if (artifactRef.current) artifactRef.current.value = "";
    }
  };

  if (loading && !detail) {
    return (
      <div className="flex h-60 items-center justify-center gap-2 text-sm text-muted-foreground">
        <Loader2Icon className="size-4 animate-spin" /> 加载案例…
      </div>
    );
  }
  if (!detail) {
    return <div className="p-6 text-sm text-muted-foreground">案例不存在或已删除。</div>;
  }

  const c = detail.case;
  const findings = detail.findings;
  const phases = detail.phases ?? [];
  const reports = detail.reports ?? [];
  const selectedReport = reports.find((r) => r.doc_type === reportKey) ?? reports[0];
  const versionAObj = versions.find((v) => String(v.version) === versionA);
  const versionBObj = versions.find((v) => String(v.version) === versionB);
  const codeTotal = findings.function_codes?.length ?? 0;
  const verifiedCodes = new Set<number>();
  for (const p of findings.probes ?? []) {
    if (!["ok", "success", "pass", "passed", "verified", "done"].includes((p.status || "").toLowerCase())) continue;
    const code = probeCode(p);
    if (code !== null) verifiedCodes.add(code);
  }
  const codeCoverage = codeTotal > 0 ? Math.round((verifiedCodes.size / codeTotal) * 100) : 0;
  const functionCodes = findings.function_codes ?? [];
  const filteredCodes = codeVerdict === "all"
    ? functionCodes
    : functionCodes.filter((code) => (findingMeta(code).verdict ?? "none") === codeVerdict);

  // Evidence visibility: count live-verified and documented-degradation probes
  // so static/live differences are explicit in the header.
  let liveProbeCount = 0;
  let degradedProbeCount = 0;
  for (const p of findings.probes ?? []) {
    const status = (p.status || "").toLowerCase();
    const grade = (p.grade || "").toLowerCase();
    const kind = (p.kind || "").toLowerCase();
    if (["ok", "success", "pass", "passed", "verified", "done"].includes(status) && grade === "live") {
      liveProbeCount++;
    }
    if (kind.includes("degraded") && (status === "offline" || status === "skipped")) {
      const payload = (p.payload ?? {}) as Record<string, unknown>;
      const reason = typeof p.reason === "string" ? p.reason : typeof payload.reason === "string" ? payload.reason : "";
      if (reason.trim()) degradedProbeCount++;
    }
  }

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Button size="sm" variant="ghost" asChild>
              <Link href="/protocol/cases">
                <ArrowLeftIcon className="size-4" />
              </Link>
            </Button>
            <h1 className="truncate text-xl font-semibold tracking-tight">{c.name}</h1>
            <Badge variant={c.mode === "live" ? "default" : "secondary"}>
              {c.mode === "live" ? "live（在线验证）" : "static（离线分析）"}
            </Badge>
            <Badge variant="outline">{c.authorization}</Badge>
            <Badge variant="outline" className="text-emerald-600">live 验证 {liveProbeCount}</Badge>
            {degradedProbeCount > 0 ? (
              <Badge variant="outline" className="text-amber-600">降级 {degradedProbeCount}</Badge>
            ) : null}
          </div>
          <p className="mt-1 text-sm text-muted-foreground">{c.description || "—"}</p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">
            {c.install_root || "无安装目录"} · {c.device_ip || "无设备"} · {STATUS_LABEL[c.status] ?? c.status}
          </p>
          {c.error ? <p className="mt-1 text-xs text-red-500">{c.error}</p> : null}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <input
            ref={fileRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => void upload(e.target.files?.[0] ?? null)}
          />
          <input
            ref={artifactRef}
            type="file"
            className="hidden"
            onChange={(e) => void uploadArtifact(e.target.files?.[0] ?? null)}
          />
          <Button size="sm" variant="outline" onClick={() => fileRef.current?.click()} disabled={detail.running}>
            <UploadIcon className="mr-1.5 size-4" /> 上传 pcap
          </Button>
          <Button size="sm" variant="outline" onClick={() => artifactRef.current?.click()} disabled={detail.running || uploadingArtifact}>
            {uploadingArtifact ? <Loader2Icon className="mr-1.5 size-4 animate-spin" /> : <PackagePlusIcon className="mr-1.5 size-4" />}
            上传工件
          </Button>
          <Button size="sm" variant="outline" onClick={() => setEditOpen(true)} disabled={detail.running}>
            <PencilIcon className="mr-1.5 size-4" /> 编辑
          </Button>
          <Button size="sm" variant="outline" onClick={() => setCaptureOpen(true)} disabled={detail.running}>
            <RadioIcon className="mr-1.5 size-4" /> 抓包
          </Button>
          <Button size="sm" variant="outline" onClick={() => void load()}>
            <RefreshCwIcon className="mr-1.5 size-4" /> 刷新
          </Button>
          <Button size="sm" onClick={() => void runAgent()} disabled={agentBusy || detail.running}>
            {agentBusy || detail.running ? (
              <Loader2Icon className="mr-1.5 size-4 animate-spin" />
            ) : (
              <BotIcon className="mr-1.5 size-4" />
            )}
            {detail.running ? "Agent 分析中…" : "启动 Agent 分析"}
          </Button>
        </div>
      </div>

      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="flex items-start gap-3 pt-4 text-sm">
          <BotIcon className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="space-y-1">
            <p className="font-medium">分析由智能体主控全程驱动</p>
            <p className="text-muted-foreground text-xs">
              上传或确认 pcap 后，点击「启动 Agent 分析」。主控按阶段数据依赖并行或串行
              下发任务（P1-P6 协议逆向；启用漏洞挖掘后继续 P7 测绘 → P8 验证与 Fuzz →
              P9 EXP 与报告），各阶段子 Agent 自选工具与方法，平台只按 findings 做门
              判定。进度实时写入本页，详细过程在自动打开的对话中查看。
            </p>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardContent className="pt-4">
            <div className="text-xs text-muted-foreground">通信资产</div>
            <div className="text-2xl font-semibold">{findings.comm_assets?.length ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-xs text-muted-foreground">帧格式</div>
            <div className="text-2xl font-semibold">{findings.frame_formats?.length ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-xs text-muted-foreground">功能码</div>
            <div className="text-2xl font-semibold">{findings.function_codes?.length ?? 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="text-xs text-muted-foreground">交付文档</div>
            <div className="text-2xl font-semibold">{reports.length}</div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="flex w-full flex-wrap justify-start">
          <TabsTrigger value="pipeline">阶段进度</TabsTrigger>
          <TabsTrigger value="pcap">pcap 质量</TabsTrigger>
          <TabsTrigger value="assets">通信资产</TabsTrigger>
          <TabsTrigger value="frames">帧格式</TabsTrigger>
          <TabsTrigger value="fields">字段划分</TabsTrigger>
          <TabsTrigger value="codes">功能码</TabsTrigger>
          <TabsTrigger value="recon">交叉佐证</TabsTrigger>
          <TabsTrigger value="probes">探针</TabsTrigger>
          <TabsTrigger value="states">会话状态机</TabsTrigger>
          <TabsTrigger value="vuln">漏洞挖掘</TabsTrigger>
          <TabsTrigger value="reports">报告</TabsTrigger>
          <TabsTrigger value="logs">日志</TabsTrigger>
        </TabsList>

        <TabsContent value="pipeline" className="mt-4">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {(c.config?.vuln_enabled ? V2_PHASES : PHASES).map((p) => {
              const phase = phases.find((x) => x.phase === p) ?? {
                case_id: id,
                phase: p,
                gate: PHASE_META[p].gate,
                status: "pending",
                detail: "",
                updated_at: "",
              };
              return <PhaseCard key={p} phase={phase as ProtocolPhase} onCancel={() => void cancelPhase(p)} />;
            })}
          </div>
          <p className="mt-3 text-xs text-muted-foreground">
            阶段由子 Agent 执行，门由平台判定：A 有得分资产；B 有非空 pcap；C 有确认帧且至少 1 个 traffic 功能码或 1 条会话状态机；D 静态功能码带指令级出处的占比 ≥60%；E live 验证或带原因降级，且每个最终码都有 verdict 一致的佐证、最终记录 ≥1；F 01–04 文档齐全、章节与有效证据（ID 或业务键）引用通过，02 覆盖最终功能码 ≥60%、live 码引用 probe、冲突标注待验证、降级注明原因。
          </p>
          <Card className="mt-3">
            <CardHeader className="pb-2"><CardTitle className="text-sm">运行统计</CardTitle></CardHeader>
            <CardContent className="grid gap-3 lg:grid-cols-2">
              <div className="overflow-auto">
                <Table>
                  <TableHeader><TableRow><TableHead>阶段</TableHead><TableHead>状态</TableHead><TableHead>次数</TableHead><TableHead>平均耗时</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {metrics.phases.length === 0 ? <EmptyRow colSpan={4} text="尚无阶段运行记录" /> : null}
                    {metrics.phases.map((m) => (
                      <TableRow key={`${m.phase}-${m.status}`}>
                        <TableCell className="text-xs">{m.phase}</TableCell>
                        <TableCell className="text-xs">{m.status}</TableCell>
                        <TableCell className="text-xs">{m.runs}</TableCell>
                        <TableCell className="text-xs">{m.avg_duration_ms ? `${(m.avg_duration_ms / 1000).toFixed(1)}s` : "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="overflow-auto">
                <Table>
                  <TableHeader><TableRow><TableHead>Agent</TableHead><TableHead>调用</TableHead><TableHead>输入</TableHead><TableHead>输出</TableHead><TableHead>缓存读</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {metrics.agents.length === 0 ? <EmptyRow colSpan={5} text="尚无阶段 LLM 用量" /> : null}
                    {metrics.agents.map((a) => (
                      <TableRow key={a.agent}>
                        <TableCell className="font-mono text-xs">{a.agent || "-"}</TableCell>
                        <TableCell className="text-xs">{a.calls}</TableCell>
                        <TableCell className="text-xs">{a.input_tokens}</TableCell>
                        <TableCell className="text-xs">{a.output_tokens}</TableCell>
                        <TableCell className="text-xs">{a.cache_read}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pcap" className="mt-4">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>文件</TableHead>
                    <TableHead>包数</TableHead>
                    <TableHead>时长</TableHead>
                    <TableHead>端点</TableHead>
                    <TableHead>协议</TableHead>
                    <TableHead>提示</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pcapLoading ? <EmptyRow colSpan={6} text="检查 pcap…" /> : null}
                  {!pcapLoading && pcaps.length === 0 ? <EmptyRow colSpan={6} text="没有可检查的 pcap" /> : null}
                  {pcaps.map((p) => (
                    <TableRow key={p.path}>
                      <TableCell className="max-w-[280px] break-all font-mono text-xs">{p.name}</TableCell>
                      <TableCell className="text-xs">{p.packets}</TableCell>
                      <TableCell className="text-xs">{p.duration_seconds.toFixed(1)}s</TableCell>
                      <TableCell className="text-xs">{p.endpoints}</TableCell>
                      <TableCell className="text-xs">{p.protocols.join(", ") || "-"}</TableCell>
                      <TableCell className="text-xs text-amber-600">
                        {p.error || (p.warnings.length ? p.warnings.join("；") : "OK")}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="assets" className="mt-4">
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>路径</TableHead>
                  <TableHead>得分</TableHead>
                  <TableHead>通信导出</TableHead>
                  <TableHead>架构</TableHead>
                  <TableHead>MD5</TableHead>
                  <TableHead>证据</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(findings.comm_assets ?? []).length === 0 ? <EmptyRow colSpan={6} text="P1 尚未产出通信资产" /> : null}
                {(findings.comm_assets ?? []).map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="max-w-[520px] break-all font-mono text-xs">{a.path}</TableCell>
                    <TableCell>{a.score}</TableCell>
                    <TableCell>{a.comm_exports}</TableCell>
                    <TableCell className="text-xs">{a.machine || "-"}</TableCell>
                    <TableCell className="font-mono text-xs">{a.md5 ? a.md5.slice(0, 12) : "-"}</TableCell>
                    <TableCell><GradeBadge grade={a.grade} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="frames" className="mt-4">
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>流</TableHead>
                  <TableHead>协议 / 载体</TableHead>
                  <TableHead>魔数</TableHead>
                  <TableHead>头长</TableHead>
                  <TableHead>长度字段</TableHead>
                  <TableHead>端序</TableHead>
                  <TableHead>帧/字节</TableHead>
                  <TableHead>证据</TableHead>
                  <TableHead>佐证</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(findings.frame_formats ?? []).length === 0 ? <EmptyRow colSpan={9} text="P5 交叉验证后产出最终帧格式" /> : null}
                {(findings.frame_formats ?? []).map((f) => {
                  const meta = findingMeta(f);
                  return (
                    <TableRow key={f.id}>
                    <TableCell>{f.stream}</TableCell>
                    <TableCell className="text-xs">
                      <div>{f.protocol || "-"}</div>
                      {f.carrier ? <div className="text-muted-foreground">{f.carrier}</div> : null}
                      {f.inner_layout ? <div className="text-muted-foreground">{f.inner_layout}</div> : null}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {f.magic || "无"}
                      {f.alt_magic ? <span className="text-muted-foreground"> / {f.alt_magic}</span> : null}
                    </TableCell>
                    <TableCell>{f.header_size}</TableCell>
                    <TableCell className="text-xs">off {f.len_offset} × {f.len_size}</TableCell>
                    <TableCell className="text-xs">{f.endian} / bias {f.len_bias}</TableCell>
                    <TableCell className="text-xs">{f.frames} / {f.bytes}</TableCell>
                    <TableCell><GradeBadge grade={f.grade} /></TableCell>
                    <TableCell className="text-xs">
                      <VerdictBadge verdict={meta.verdict} />
                      {meta.source ? <div className="mt-0.5 text-muted-foreground">{meta.source}</div> : null}
                    </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="fields" className="mt-4 space-y-3">
          {(findings.field_maps ?? []).length === 0 ? <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">P5 交叉验证后产出最终字段划分</CardContent></Card> : null}
          {(findings.field_maps ?? []).map((m) => <FieldMapCard key={m.id} map={m} />)}
        </TabsContent>

        <TabsContent value="codes" className="mt-4">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">佐证筛选</span>
            <Select value={codeVerdict} onValueChange={setCodeVerdict}>
              <SelectTrigger className="h-7 w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部</SelectItem>
                <SelectItem value="matched">matched</SelectItem>
                <SelectItem value="conflicting">conflicting</SelectItem>
                <SelectItem value="traffic-only">traffic-only</SelectItem>
                <SelectItem value="static-only">static-only</SelectItem>
                <SelectItem value="none">未标 verdict</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-xs text-muted-foreground">{filteredCodes.length}/{functionCodes.length}</span>
          </div>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>层</TableHead>
                  <TableHead>功能码</TableHead>
                  <TableHead>标签</TableHead>
                  <TableHead>证据等级</TableHead>
                  <TableHead>佐证</TableHead>
                  <TableHead>出处</TableHead>
                  <TableHead>已验证</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(filteredCodes).length === 0 ? <EmptyRow colSpan={8} text={codeVerdict === "all" ? "P5 交叉验证后产出最终功能码" : "没有符合筛选的功能码"} /> : null}
                {filteredCodes.map((c) => {
                  const meta = findingMeta(c);
                  return (
                    <TableRow key={c.id}>
                    <TableCell className="text-xs">{c.layer}</TableCell>
                    <TableCell className="font-mono text-xs">{codeDisplay(c)}</TableCell>
                    <TableCell className="max-w-[420px] break-all text-xs">
                      {c.label || "-"}
                      {c.semantic ? <Badge variant="outline" className="ml-1.5 text-[10px]">已定名</Badge> : null}
                    </TableCell>
                    <TableCell><GradeBadge grade={c.grade} /></TableCell>
                    <TableCell className="text-xs">
                      <VerdictBadge verdict={meta.verdict} />
                      {meta.source ? <div className="mt-0.5 text-muted-foreground">{meta.source}</div> : null}
                    </TableCell>
                    <TableCell className="max-w-[280px] break-all font-mono text-[11px] text-muted-foreground">{c.evidence || c.source || "-"}</TableCell>
                    <TableCell>{isLiveVerified(c) ? <Badge>是</Badge> : <span className="text-xs text-muted-foreground">否</span>}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="ghost" className="h-7 text-xs" onClick={() => setEditCode(c)}>
                        编辑
                      </Button>
                    </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="recon" className="mt-4">
          <ReconciliationPanel notes={findings.notes ?? []} />
        </TabsContent>

        <TabsContent value="probes" className="mt-4 space-y-3">
          <Card>
            <CardContent className="flex flex-wrap items-center gap-4 pt-4 text-sm">
              <div><span className="text-muted-foreground">功能码覆盖：</span><span className="font-medium">{verifiedCodes.size} / {codeTotal}</span></div>
              <div><span className="text-muted-foreground">覆盖率：</span><span className="font-medium">{codeCoverage}%</span></div>
              <div className="text-muted-foreground text-xs">P5 探针需在 payload 或 action 中记录功能码，才会计入覆盖。</div>
            </CardContent>
          </Card>
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>时间</TableHead>
                  <TableHead>类型</TableHead>
                  <TableHead>目标</TableHead>
                  <TableHead>功能码</TableHead>
                  <TableHead>动作</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>等级</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(findings.probes ?? []).length === 0 ? <EmptyRow colSpan={7} text="P5 尚未执行 live 探针" /> : null}
                {(findings.probes ?? []).map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="text-xs">{fmtProtocolTime(p.created_at)}</TableCell>
                    <TableCell className="text-xs">{p.kind || "-"}</TableCell>
                    <TableCell className="font-mono text-xs">{p.host}{p.port ? `:${p.port}` : ""}</TableCell>
                    <TableCell className="font-mono text-xs">{probeCode(p) !== null ? hexCode(probeCode(p) as number) : "-"}</TableCell>
                    <TableCell className="text-xs">{p.action || p.spec || "-"}</TableCell>
                    <TableCell className="text-xs">{p.status || "-"}</TableCell>
                    <TableCell><GradeBadge grade={p.grade} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        <TabsContent value="states" className="mt-4">
          <SessionModelPanels notes={findings.notes ?? []} />
        </TabsContent>

        <TabsContent value="vuln" className="mt-4">
          <ProtocolVulnView
            caseId={id}
            raw={findings.raw}
            vulnEnabled={Boolean(c.config?.vuln_enabled)}
            onChanged={() => void load()}
          />
        </TabsContent>

        <TabsContent value="reports" className="mt-4">
          {reports.length === 0 ? (
            <Card><CardContent className="py-10 text-center text-sm text-muted-foreground">P6 尚未生成交付文档</CardContent></Card>
          ) : (
            <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
              <Card className="h-fit">
                <CardHeader className="flex-row items-center justify-between pb-2">
                  <CardTitle className="text-sm">交付文档</CardTitle>
                  <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => void downloadReports()}>
                    导出 zip
                  </Button>
                </CardHeader>
                <CardContent className="space-y-1 p-2">
                  {reports.map((r) => (
                    <button
                      key={r.doc_type}
                      type="button"
                      onClick={() => setReportKey(r.doc_type)}
                      className={`flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-xs ${
                        selectedReport?.doc_type === r.doc_type ? "bg-primary/10 text-primary" : "hover:bg-muted"
                      }`}
                    >
                      <FileTextIcon className="size-3.5" />
                      <span className="truncate">{r.title || r.doc_type}</span>
                    </button>
                  ))}
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="flex-wrap items-center gap-2 pb-2">
                  <CardTitle className="mr-auto text-sm">{selectedReport?.title || "报告"}</CardTitle>
                  {selectedReport && <Badge variant="outline">v{selectedReport.version}</Badge>}
                  {selectedReport?.approved_version === selectedReport?.version ? (
                    <Badge variant="secondary" className="text-emerald-600">
                      已批准 · {selectedReport.approved_by}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="text-muted-foreground">未批准</Badge>
                  )}
                  <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => selectedReport && void openVersions(selectedReport)}>
                    版本
                  </Button>
                  <Button
                    size="sm"
                    className="h-7 text-xs"
                    disabled={!selectedReport || selectedReport.approved_version === selectedReport.version || currentUser.role === "viewer"}
                    onClick={() => selectedReport && void approveReport(selectedReport)}
                  >
                    批准当前版本
                  </Button>
                </CardHeader>
                <CardContent>
                  <Separator className="mb-3" />
                  <div className="max-h-[620px] overflow-auto text-sm">
                    <Markdown text={selectedReport?.content || ""} />
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="logs" className="mt-4">
          <LogView caseId={id} active={tab === "logs"} />
        </TabsContent>
      </Tabs>

      <Dialog open={versionsOpen} onOpenChange={setVersionsOpen}>
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <DialogTitle>报告版本对比：{versionDoc}</DialogTitle>
            <DialogDescription>选择两个版本并排查看；批准后该版本标记为当前交付版本。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>左侧版本</Label>
              <Select value={versionA} onValueChange={setVersionA}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {versions.map((v) => <SelectItem key={v.version} value={String(v.version)}>v{v.version} · {v.created_at}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>右侧版本</Label>
              <Select value={versionB} onValueChange={setVersionB}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {versions.map((v) => <SelectItem key={v.version} value={String(v.version)}>v{v.version} · {v.created_at}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid max-h-[60vh] gap-3 overflow-auto sm:grid-cols-2">
            <pre className="min-h-40 overflow-auto rounded-md border p-3 font-mono text-xs whitespace-pre-wrap">{versionAObj?.content || "（无内容）"}</pre>
            <pre className="min-h-40 overflow-auto rounded-md border p-3 font-mono text-xs whitespace-pre-wrap">{versionBObj?.content || "（无内容）"}</pre>
          </div>
        </DialogContent>
      </Dialog>

      <EditCaseDialog c={c} open={editOpen} onOpenChange={setEditOpen} onSaved={() => void load()} />
      <CaptureDialog caseId={c.id} deviceIP={c.device_ip} open={captureOpen} onOpenChange={setCaptureOpen} onCaptured={() => void load()} />
      <CodeEditDialog
        caseId={c.id}
        code={editCode}
        open={!!editCode}
        onOpenChange={(o) => {
          if (!o) setEditCode(null);
        }}
        onSaved={() => {
          setEditCode(null);
          void load();
        }}
      />
    </div>
  );
}

export default function ProtocolCaseDetailPage() {
  return (
    <React.Suspense
      fallback={
        <div className="flex h-60 items-center justify-center gap-2 text-sm text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> 加载…
        </div>
      }
    >
      <CaseDetailInner />
    </React.Suspense>
  );
}