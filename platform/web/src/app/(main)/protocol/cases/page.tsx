"use client";

import * as React from "react";

import Link from "next/link";

import {
  ArrowRightIcon,
  BugIcon,
  Loader2Icon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

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
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  fmtProtocolTime,
  protocolApi,
  type ProtocolAuthorization,
  type ProtocolCase,
  type ProtocolCaseInput,
  type ProtocolStats,
} from "@/lib/protocol-api";

const STATUS_LABEL: Record<string, string> = {
  draft: "草稿",
  queued: "排队中",
  running: "运行中",
  paused: "已暂停",
  done: "已完成",
  failed: "失败",
};

const STATUS_CLASS: Record<string, string> = {
  running: "bg-blue-500/15 text-blue-600 dark:text-blue-400",
  done: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
  failed: "bg-red-500/15 text-red-600 dark:text-red-400",
  paused: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
  queued: "bg-violet-500/15 text-violet-600 dark:text-violet-400",
};

const AUTH_LABEL: Record<string, string> = {
  "read-only": "只读",
  write: "写操作",
  destructive: "破坏类",
  full: "完整授权",
};

function StatCard({ title, value, hint }: { title: string; value: number | string; hint?: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
        {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}

function CreateCaseDialog({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [installRoot, setInstallRoot] = React.useState("");
  const [deviceIP, setDeviceIP] = React.useState("");
  const [authorization, setAuthorization] = React.useState<ProtocolAuthorization>("read-only");
  const [mode, setMode] = React.useState<"live" | "static">("live");
  const [pcap, setPcap] = React.useState("");
  const [dll, setDll] = React.useState("");
  const [vulnEnabled, setVulnEnabled] = React.useState(false);

  const reset = () => {
    setName("");
    setDescription("");
    setInstallRoot("");
    setDeviceIP("");
    setAuthorization("read-only");
    setMode("live");
    setPcap("");
    setDll("");
    setVulnEnabled(false);
  };

  const create = async () => {
    if (!name.trim()) {
      toast.error("请填写案例名称");
      return;
    }
    if (mode === "live" && !deviceIP.trim()) {
      toast.error("live 模式必须填写设备 IP");
      return;
    }
    if (mode === "static" && !pcap.trim()) {
      toast.error("static 模式必须填写抓包文件路径");
      return;
    }
    const golden: Record<string, string> = {};
    if (pcap.trim()) golden.pcap_codesys = pcap.trim();
    if (dll.trim()) golden.comm_dll = dll.trim();
    const config: Record<string, unknown> = { golden_artifacts: golden };
    if (vulnEnabled) config.vuln_enabled = true;
    const body: ProtocolCaseInput = {
      name: name.trim(),
      description: description.trim(),
      install_root: installRoot.trim(),
      device_ip: deviceIP.trim(),
      authorization,
      mode,
      config,
    };
    setSaving(true);
    try {
      await protocolApi.createCase(body);
      toast.success("案例已创建");
      setOpen(false);
      reset();
      onCreated();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "创建失败");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon className="mr-1.5 size-4" />
          新建案例
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>新建分析案例</DialogTitle>
          <DialogDescription>
            填写上位机安装目录与可选设备/IP；已有 pcap 或通信 DLL 可直接填入，后续也可上传。
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid gap-2">
            <Label htmlFor="pc-name">案例名称</Label>
            <Input id="pc-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="WAGO 750-8202 + CODESYS V2.3" />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pc-desc">描述</Label>
            <Textarea
              id="pc-desc"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="靶标范围、交付要求、已知线索……"
              rows={3}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="pc-root">安装目录</Label>
              <Input id="pc-root" value={installRoot} onChange={(e) => setInstallRoot(e.target.value)} placeholder="C:\\Program Files\\某上位机" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pc-ip">设备 IP（live 模式必填）</Label>
              <Input id="pc-ip" value={deviceIP} onChange={(e) => setDeviceIP(e.target.value)} placeholder="192.168.1.20" />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
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
            <div className="grid gap-2">
              <Label>授权级别</Label>
              <Select value={authorization} onValueChange={(v) => setAuthorization(v as ProtocolAuthorization)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="read-only">只读（默认）</SelectItem>
                  <SelectItem value="write">允许写变量/参数</SelectItem>
                  <SelectItem value="destructive">允许复位/破坏类</SelectItem>
                  <SelectItem value="full">完整授权（测试设备）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <p className="-mt-2 text-muted-foreground text-xs">
            live 模式必须填写设备 IP：P2 可直接在线抓包，P5 做在线验证；static 模式只做离线
            分析，必须提供 pcap。授权级别会由平台在工具层强制执行：只读仅允许分析和只读探针；
            写变量需要 write；复位/擦除/刷写等破坏性操作需要 destructive 或 full。
          </p>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="pc-pcap">既有 pcap（static 模式必填）</Label>
              <Input id="pc-pcap" value={pcap} onChange={(e) => setPcap(e.target.value)} placeholder="D:\\captures\\session1.pcapng" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pc-dll">通信 DLL（可选）</Label>
              <Input id="pc-dll" value={dll} onChange={(e) => setDll(e.target.value)} placeholder="...\\WBCComm.dll" />
            </div>
          </div>
          <div className="flex items-start gap-3 rounded-md border p-3">
            <Switch
              id="pc-vuln"
              checked={vulnEnabled}
              onCheckedChange={setVulnEnabled}
              className="mt-0.5"
            />
            <div className="space-y-0.5">
              <Label htmlFor="pc-vuln" className="cursor-pointer">启用漏洞挖掘（P7-P9）</Label>
              <p className="text-muted-foreground text-xs">
                逆向六阶段（P1-P6）完成后继续：P7 漏洞面测绘 → P8 验证与 Fuzz → P9 EXP
                与报告；destructive 操作全部走审批硬闸。不开启则只做协议逆向。
              </p>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)} disabled={saving}>
            取消
          </Button>
          <Button onClick={create} disabled={saving}>
            {saving ? <Loader2Icon className="mr-1.5 size-4 animate-spin" /> : null}
            创建
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ProtocolCasesPage() {
  const [items, setItems] = React.useState<ProtocolCase[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<ProtocolStats | null>(null);
  const [q, setQ] = React.useState("");
  const [status, setStatus] = React.useState("all");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [list, st] = await Promise.all([
        protocolApi.listCases({ q: q.trim() || undefined, status: status === "all" ? undefined : status }),
        protocolApi.stats(),
      ]);
      setItems(list.items ?? []);
      setTotal(list.total);
      setStats(st);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "加载失败");
    } finally {
      setLoading(false);
    }
  }, [q, status]);

  React.useEffect(() => {
    void load();
  }, [load]);

  const remove = async (id: number) => {
    if (!window.confirm("删除案例及其全部 findings / pcap 索引？此操作不可恢复。")) return;
    try {
      await protocolApi.deleteCase(id);
      toast.success("已删除");
      void load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "删除失败");
    }
  };

  return (
    <div className="flex flex-col gap-5 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">分析案例</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            九阶段流水线：P1-P6 私有协议逆向（资产/流量/静态/交叉验证/交付）→ P7
            漏洞面测绘 → P8 验证与 Fuzz → P9 EXP 与报告。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCwIcon className={`mr-1.5 size-4 ${loading ? "animate-spin" : ""}`} />
            刷新
          </Button>
          <CreateCaseDialog onCreated={() => void load()} />
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="案例总数" value={stats?.cases ?? 0} hint={`运行中 ${stats?.running ?? 0} · 失败 ${stats?.failed ?? 0}`} />
        <StatCard title="通信资产" value={stats?.assets ?? 0} hint={`帧格式 ${stats?.frames ?? 0} · 字段图 ${stats?.field_maps ?? 0}`} />
        <StatCard title="功能码" value={stats?.codes ?? 0} hint={`已验证 ${stats?.verified_codes ?? 0}`} />
        <StatCard
          title="证据等级"
          value={Object.entries(stats?.codes_by_grade ?? {})
            .map(([k, v]) => `${k}:${v}`)
            .join(" · ") || "-"}
          hint="traffic > live > static > inferred"
        />
      </div>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 py-3">
          <div className="relative min-w-[220px] flex-1">
            <SearchIcon className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="搜索名称 / 安装目录 / 设备 IP"
              className="h-8 pl-8"
            />
          </div>
          <Select value={status} onValueChange={setStatus}>
            <SelectTrigger className="h-8 w-[130px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部状态</SelectItem>
              <SelectItem value="draft">草稿</SelectItem>
              <SelectItem value="running">运行中</SelectItem>
              <SelectItem value="done">已完成</SelectItem>
              <SelectItem value="failed">失败</SelectItem>
            </SelectContent>
          </Select>
          <span className="text-xs text-muted-foreground">共 {total} 个</span>
        </CardContent>
      </Card>

      <Card className="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>案例</TableHead>
              <TableHead>安装目录 / 设备</TableHead>
              <TableHead>授权</TableHead>
              <TableHead>模式</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>创建时间</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 && !loading ? (
              <TableRow>
                <TableCell colSpan={7} className="h-40 text-center text-sm text-muted-foreground">
                  <BugIcon className="mx-auto mb-2 size-8 opacity-40" />
                  还没有案例。点右上角「新建案例」开始。
                </TableCell>
              </TableRow>
            ) : null}
            {items.map((c) => (
              <TableRow key={c.id}>
                <TableCell className="max-w-[320px]">
                  <Link href={`/protocol/cases/detail?id=${c.id}`} className="font-medium hover:underline">
                    {c.name}
                  </Link>
                  <div className="mt-0.5 truncate text-xs text-muted-foreground">{c.description || "—"}</div>
                </TableCell>
                <TableCell className="max-w-[300px]">
                  <div className="truncate font-mono text-xs">{c.install_root || "—"}</div>
                  <div className="mt-0.5 text-xs text-muted-foreground">{c.device_ip || "无设备（静态模式）"}</div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline">{AUTH_LABEL[c.authorization] ?? c.authorization}</Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={c.mode === "live" ? "default" : "secondary"}>{c.mode === "live" ? "live" : "static"}</Badge>
                </TableCell>
                <TableCell>
                  <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_CLASS[c.status] ?? "bg-muted text-muted-foreground"}`}>
                    {STATUS_LABEL[c.status] ?? c.status}
                  </span>
                  {c.error ? <div className="mt-1 max-w-[220px] truncate text-xs text-red-500">{c.error}</div> : null}
                </TableCell>
                <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{fmtProtocolTime(c.created_at)}</TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-1">
                    <Button size="sm" variant="ghost" asChild>
                      <Link href={`/protocol/cases/detail?id=${c.id}`}>
                        <ArrowRightIcon className="size-4" />
                      </Link>
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => void remove(c.id)}>
                      <Trash2Icon className="size-4 text-red-500" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}