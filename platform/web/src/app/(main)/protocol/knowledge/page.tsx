"use client";

import * as React from "react";

import {
  ChevronDownIcon,
  ChevronRightIcon,
  DatabaseIcon,
  Loader2Icon,
  RefreshCwIcon,
  SearchIcon,
  SwordsIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { protocolApi, type KnowledgeItem } from "@/lib/protocol-api";

const VCLASS_NAMES: Record<number, string> = {
  1: "信息泄露", 2: "协议认证", 3: "远程启停", 4: "内存读写", 5: "逻辑篡改",
  6: "保护破解", 7: "拒绝服务", 8: "固件与组件", 9: "次要攻击面",
  10: "重放与欺骗", 11: "加密与降级", 12: "发现协议滥用", 13: "物理I/O操纵", 14: "工程侧客户端",
};

const SOURCE_META: Record<string, { label: string; cls: string }> = {
  plcsts: { label: "设备载荷", cls: "bg-red-100 text-red-800" },
  icssploit: { label: "通用载荷", cls: "bg-orange-100 text-orange-800" },
  icsvuln: { label: "icsvuln", cls: "bg-blue-100 text-blue-800" },
  "plc-intel": { label: "plc-intel", cls: "bg-green-100 text-green-800" },
};

const RISK_CLS: Record<string, string> = {
  read: "bg-gray-100 text-gray-700",
  write: "bg-yellow-100 text-yellow-800",
  destructive: "bg-red-100 text-red-800",
};

function isPayload(it: KnowledgeItem) {
  return it.source === "plcsts" || it.source === "icssploit";
}

export default function KnowledgePage() {
  const [items, setItems] = React.useState<KnowledgeItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [bySource, setBySource] = React.useState<Record<string, number>>({});
  const [loading, setLoading] = React.useState(false);
  const [source, setSource] = React.useState("all");
  const [vclass, setVclass] = React.useState("all");
  const [vendor, setVendor] = React.useState("");
  const [q, setQ] = React.useState("");
  const [page, setPage] = React.useState(1);
  const [expanded, setExpanded] = React.useState<number | null>(null);
  const pageSize = 50;

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await protocolApi.knowledge({
        source: source === "all" ? undefined : source,
        vclass: vclass === "all" ? undefined : Number(vclass),
        vendor: vendor.trim() || undefined,
        q: q.trim() || undefined,
        page,
        page_size: pageSize,
      });
      setItems(r.items ?? []);
      setTotal(r.total);
      setBySource(r.by_source ?? {});
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [source, vclass, vendor, q, page]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const payloadTotal = (bySource.plcsts ?? 0) + (bySource.icssploit ?? 0);
  const vendorCount = new Set(items.map((i) => i.vendor).filter(Boolean)).size;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <DatabaseIcon className="size-5" /> 验证 EXP 载荷库
          </h1>
          <p className="mt-0.5 text-xs text-muted-foreground">
            已验证的 PLC 利用载荷（plcsts 设备专属 / icssploit 通用），含真实协议帧。
            P7 测绘优先匹配载荷，P9 可引用载荷帧生成 EXP。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="mr-1.5 size-4 animate-spin" /> : <RefreshCwIcon className="mr-1.5 size-4" />}
          刷新
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-4">
        <Card className="border-red-200"><CardContent className="pt-4">
          <div className="flex items-center gap-1 text-xs text-muted-foreground"><SwordsIcon className="size-3.5" /> 验证 EXP</div>
          <div className="text-2xl font-semibold tabular-nums text-red-600">{total}</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4">
          <div className="text-xs text-muted-foreground">设备专属载荷</div>
          <div className="text-2xl font-semibold tabular-nums">{bySource.plcsts ?? 0}</div>
          <div className="text-[11px] text-muted-foreground">plcsts · 按厂商/型号</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4">
          <div className="text-xs text-muted-foreground">通用载荷</div>
          <div className="text-2xl font-semibold tabular-nums">{bySource.icssploit ?? 0}</div>
          <div className="text-[11px] text-muted-foreground">icssploit</div>
        </CardContent></Card>
        <Card><CardContent className="pt-4">
          <div className="text-xs text-muted-foreground">覆盖厂商</div>
          <div className="text-2xl font-semibold tabular-nums">{vendorCount}</div>
          <div className="text-[11px] text-muted-foreground">含五基准设备 + 国产</div>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center gap-2">
            <Select value={source} onValueChange={(v) => { setSource(v); setPage(1); }}>
              <SelectTrigger className="w-36"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部来源</SelectItem>
                <SelectItem value="plcsts">设备载荷 (plcsts)</SelectItem>
                <SelectItem value="icssploit">通用载荷 (icssploit)</SelectItem>
              </SelectContent>
            </Select>
            <Select value={vclass} onValueChange={(v) => { setVclass(v); setPage(1); }}>
              <SelectTrigger className="w-40"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部类别</SelectItem>
                {Object.entries(VCLASS_NAMES).map(([k, v]) => (
                  <SelectItem key={k} value={k}>{k}·{v}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Input className="w-36" placeholder="厂商（如 siemens）" value={vendor}
              onChange={(e) => { setVendor(e.target.value); setPage(1); }} />
            <div className="relative flex-1 min-w-48">
              <SearchIcon className="absolute left-2 top-2.5 size-4 text-muted-foreground" />
              <Input className="pl-8" placeholder="搜索 CVE / 型号 / 描述…" value={q}
                onChange={(e) => { setQ(e.target.value); setPage(1); }} />
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead>标识</TableHead>
                <TableHead>来源</TableHead>
                <TableHead>类别</TableHead>
                <TableHead>厂商 / 型号</TableHead>
                <TableHead>协议</TableHead>
                <TableHead>描述</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="py-8 text-center text-xs text-muted-foreground">
                  {loading ? "加载中…" : "无匹配条目"}
                </TableCell></TableRow>
              ) : null}
              {items.map((it) => {
                const payload = isPayload(it);
                const open = expanded === it.id;
                const frames = it.refs?.frames ?? {};
                const frameNames = Object.keys(frames);
                return (
                  <React.Fragment key={it.id}>
                    <TableRow className={payload ? "cursor-pointer bg-red-50/40" : "cursor-pointer"}
                      onClick={() => setExpanded(open ? null : it.id)}>
                      <TableCell>
                        {payload || it.refs ? (open ? <ChevronDownIcon className="size-4" /> : <ChevronRightIcon className="size-4" />) : null}
                      </TableCell>
                      <TableCell className="max-w-[220px] truncate font-mono text-[11px]" title={it.cve_id}>
                        {it.cve_id.replace(/^(PLCSTS|ICSSPLOIT):/, "")}
                      </TableCell>
                      <TableCell>
                        <span className={`inline-flex rounded px-1.5 py-0.5 text-[11px] ${SOURCE_META[it.source]?.cls ?? "bg-muted text-muted-foreground"}`}>
                          {SOURCE_META[it.source]?.label ?? it.source}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs">{it.vclass ? `${it.vclass}·${VCLASS_NAMES[it.vclass] ?? "?"}` : "-"}</TableCell>
                      <TableCell className="text-xs">
                        {it.vendor || "-"}
                        {it.refs?.model ? <span className="text-muted-foreground"> / {it.refs.model}</span> : null}
                      </TableCell>
                      <TableCell className="text-xs">{it.protocol || "-"}</TableCell>
                      <TableCell className="max-w-[320px] truncate text-xs text-muted-foreground" title={it.summary}>{it.summary}</TableCell>
                    </TableRow>
                    {open ? (
                      <TableRow>
                        <TableCell colSpan={7} className="bg-muted/40 p-3">
                          <div className="space-y-2 text-xs">
                            <p className="text-muted-foreground">{it.summary}</p>
                            {payload ? (
                              <div className="flex flex-wrap gap-2">
                                {it.refs?.risk ? (
                                  <span className={`rounded px-1.5 py-0.5 text-[11px] ${RISK_CLS[it.refs.risk] ?? "bg-muted"}`}>风险: {it.refs.risk}</span>
                                ) : null}
                                {it.refs?.port ? <span className="rounded bg-muted px-1.5 py-0.5 text-[11px]">端口: {it.refs.port}</span> : null}
                                {it.refs?.category ? <span className="rounded bg-muted px-1.5 py-0.5 text-[11px]">类别: {it.refs.category}</span> : null}
                                {it.refs?.module ? <span className="font-mono text-[11px] text-muted-foreground">{it.refs.module}</span> : null}
                              </div>
                            ) : null}
                            {frameNames.length > 0 ? (
                              <div>
                                <p className="mb-1 font-medium">协议帧（{frameNames.length}）：</p>
                                <div className="space-y-1">
                                  {frameNames.map((fn) => (
                                    <div key={fn} className="flex items-start gap-2">
                                      <span className="w-40 shrink-0 font-mono text-[11px] text-muted-foreground">{fn}</span>
                                      <code className="break-all rounded bg-background px-1.5 py-0.5 font-mono text-[11px]">{frames[fn]}</code>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : payload ? (
                              <p className="text-[11px] text-muted-foreground">（该载荷帧在运行时动态构造，见模块源码）</p>
                            ) : null}
                            {it.refs?.references?.length ? (
                              <p className="text-[11px] text-muted-foreground">参考: {it.refs.references.join(" ; ")}</p>
                            ) : null}
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </React.Fragment>
                );
              })}
            </TableBody>
          </Table>
          <div className="flex items-center justify-between px-3 py-2 text-xs text-muted-foreground">
            <span>共 {total} 条 · 第 {page}/{totalPages} 页</span>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" className="h-7" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>上一页</Button>
              <Button size="sm" variant="outline" className="h-7" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>下一页</Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
