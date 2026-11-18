"use client";

import * as React from "react";
import { RefreshCwIcon, ShieldCheckIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";

function fmt(ts: string) {
  return new Date(ts).toLocaleString("zh-CN");
}

export default function AuditPage() {
  const [items, setItems] = React.useState<AuditEntry[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const r = await api.auditLog(300, 0);
      setItems(r.items ?? []);
      setTotal(r.total);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 font-semibold text-xl tracking-tight">
            <ShieldCheckIcon className="size-5" /> 审计日志
          </h1>
          <p className="text-muted-foreground text-sm">
            记录登录、配置、案例、用户等写操作。共 {total} 条，显示最近 {items.length} 条。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={loading ? "animate-spin" : ""} /> 刷新
        </Button>
      </div>

      {error && <Card className="border-destructive/40 p-4 text-sm text-destructive">{error}</Card>}

      <Card className="overflow-hidden py-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[160px]">时间</TableHead>
              <TableHead>用户</TableHead>
              <TableHead>角色</TableHead>
              <TableHead>方法</TableHead>
              <TableHead>路径</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>IP</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                  暂无审计记录
                </TableCell>
              </TableRow>
            ) : (
              items.map((e) => (
                <TableRow key={e.id}>
                  <TableCell className="text-xs text-muted-foreground">{fmt(e.ts)}</TableCell>
                  <TableCell className="font-mono text-xs">{e.username || "-"}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{e.role || "-"}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.method}</TableCell>
                  <TableCell className="max-w-[360px] truncate font-mono text-xs" title={e.path}>
                    {e.path}
                  </TableCell>
                  <TableCell>
                    <Badge variant={e.status >= 400 ? "destructive" : "secondary"}>{e.status}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.ip || "-"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}