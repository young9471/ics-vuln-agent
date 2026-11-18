"use client";

import * as React from "react";

import Link from "next/link";

import { Loader2Icon, RefreshCwIcon, SearchIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { codeDisplay, isLiveVerified, protocolApi, GRADE_META, type ProtocolCodeView, type ProtocolStats } from "@/lib/protocol-api";

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

export default function ProtocolFindingsPage() {
  const [items, setItems] = React.useState<ProtocolCodeView[]>([]);
  const [stats, setStats] = React.useState<ProtocolStats | null>(null);
  const [q, setQ] = React.useState("");
  const [grade, setGrade] = React.useState("all");
  const [layer, setLayer] = React.useState("all");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [list, st] = await Promise.all([
        protocolApi.listFindings({
          q: q.trim() || undefined,
          grade: grade === "all" ? undefined : grade,
          layer: layer === "all" ? undefined : layer,
          limit: 1000,
        }),
        protocolApi.stats(),
      ]);
      setItems(list.items ?? []);
      setStats(st);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [q, grade, layer]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const layers = React.useMemo(() => {
    const set = new Set(items.map((x) => x.layer).filter(Boolean));
    return Array.from(set).sort();
  }, [items]);

  return (
    <div className="flex flex-col gap-5 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">协议发现库</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            跨案例汇总功能码与证据等级。所有结论按 traffic &gt; live &gt; static &gt; inferred 分级。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={`mr-1.5 size-4 ${loading ? "animate-spin" : ""}`} />
          刷新
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Card><CardContent className="pt-4"><div className="text-xs text-muted-foreground">功能码总数</div><div className="text-2xl font-semibold">{stats?.codes ?? 0}</div></CardContent></Card>
        <Card><CardContent className="pt-4"><div className="text-xs text-muted-foreground">live 验证</div><div className="text-2xl font-semibold">{stats?.verified_codes ?? 0}</div></CardContent></Card>
        <Card><CardContent className="pt-4"><div className="text-xs text-muted-foreground">帧格式</div><div className="text-2xl font-semibold">{stats?.frames ?? 0}</div></CardContent></Card>
        <Card><CardContent className="pt-4"><div className="text-xs text-muted-foreground">字段图</div><div className="text-2xl font-semibold">{stats?.field_maps ?? 0}</div></CardContent></Card>
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 py-3">
          <div className="relative min-w-[240px] flex-1">
            <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="搜索标签 / 出处 / 层 / 案例名" className="h-8 pl-8" />
          </div>
          <Select value={grade} onValueChange={setGrade}>
            <SelectTrigger className="h-8 w-[130px]"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部等级</SelectItem>
              <SelectItem value="traffic">traffic</SelectItem>
              <SelectItem value="live">live</SelectItem>
              <SelectItem value="static">static</SelectItem>
              <SelectItem value="inferred">inferred</SelectItem>
            </SelectContent>
          </Select>
          <Select value={layer} onValueChange={setLayer}>
            <SelectTrigger className="h-8 w-[170px]"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部层</SelectItem>
              {layers.map((l) => <SelectItem key={l} value={l}>{l}</SelectItem>)}
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground">共 {items.length} 条</span>
        </CardContent>
      </Card>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>案例</TableHead>
              <TableHead>层</TableHead>
              <TableHead>功能码</TableHead>
              <TableHead>标签</TableHead>
              <TableHead>等级</TableHead>
              <TableHead>出处</TableHead>
              <TableHead>验证</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-32 text-center text-sm text-muted-foreground">
                  还没有功能码。先运行案例的 P4。
                </TableCell>
              </TableRow>
            ) : null}
            {items.map((c) => (
              <TableRow key={`${c.case_id}-${c.id}`}>
                <TableCell className="max-w-[220px] truncate text-xs">
                  <Link href={`/protocol/cases/detail?id=${c.case_id}`} className="hover:underline">
                    {c.case_name}
                  </Link>
                </TableCell>
                <TableCell className="text-xs">{c.layer}</TableCell>
                <TableCell className="font-mono text-xs">{codeDisplay(c)}</TableCell>
                <TableCell className="max-w-[380px] break-all text-xs">
                  {c.label || "-"}
                  {c.semantic ? <Badge variant="outline" className="ml-1.5 text-[10px]">已定名</Badge> : null}
                </TableCell>
                <TableCell><GradeBadge grade={c.grade} /></TableCell>
                <TableCell className="max-w-[260px] break-all font-mono text-[11px] text-muted-foreground">{c.evidence || c.source || "-"}</TableCell>
                <TableCell>{isLiveVerified(c) ? <Badge>是</Badge> : <span className="text-xs text-muted-foreground">否</span>}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      {loading ? (
        <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> 加载…
        </div>
      ) : null}
    </div>
  );
}