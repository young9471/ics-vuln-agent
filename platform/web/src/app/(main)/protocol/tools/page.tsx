"use client";

import * as React from "react";

import { AlertTriangleIcon, CheckCircle2Icon, Loader2Icon, RefreshCwIcon, TerminalIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { protocolApi, type ProtocolToolStatus } from "@/lib/protocol-api";

const TOOL_DESCRIPTIONS: Record<string, string> = {
  "recon_pe.py": "P1 资产侦察：PE 解剖 + 通信嫌疑打分",
  "capture.py": "P2 抓包编排：tshark 后台 + netstat 轮询",
  "frame_hypothesis.py": "P3 帧假设拟合：魔数/长度场搜索 + 零重同步验证",
  "field_map.py": "P3b 帧内字段划分：常量/长度/事务号/计数器",
  "extract_codes.py": "P4 静态功能码提取：导出表锚定 + 模式匹配",
  "client_harness.py": "P5 声明式协议客户端：只读 identify 验证",
  "dissector_gen.py": "P6 Wireshark Lua dissector 生成器",
  "findings.py": "findings.json 证据分级状态存储",
  "binary_survey.py": "P1 补充侦察：ELF/Mach-O/.NET/安装包/配置关键词",
  "analyzer_bundle.py": "自动发现 offline/analyzers-win-x64 离线包及运行环境",
  "analyzer_cache.py": "静态分析 SHA256 缓存：Ghidra/ILSpy 结果跨案例复用",
  "session_model.py": "P3 会话/状态机：请求响应配对、重试/超时、TCP 分片和状态迁移",
  "probe_dsl.py": "P5 声明式探针：帧字段/序列号/校验/超时/重试，默认 dry-run",
  "elf_analyze.py": "P1/P4 ELF 符号、导入导出与通信关键词提取（纯 Python）",
  "dotnet_analyze.py": "P4 .NET 反编译（ILSpyCmd）与常量/功能码提取",
  "ghidra_analyze.py": "P1/P4 Ghidra headless 桥接（需 GHIDRA_HOME）",
  "ida_analyze.py": "P1/P4 IDA headless 桥接（需已安装 IDA）",
  "traffic_insights.py": "P3 流量洞察：CRC 参数搜索、压缩/TLS 识别、字段差分与状态转移",
  "GhidraExport.java": "Ghidra headless 导出脚本",
  "ida_export.py": "IDA headless 导出脚本",
};

export default function ProtocolToolsPage() {
  const [status, setStatus] = React.useState<ProtocolToolStatus | null>(null);
  const [loading, setLoading] = React.useState(false);

  const check = React.useCallback(async () => {
    setLoading(true);
    try {
      setStatus(await protocolApi.tools());
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "检查失败");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void check();
  }, [check]);

  return (
    <div className="flex flex-col gap-5 p-4 lg:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">工具链</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            平台通过 Python 工具链执行 PLAYBOOK。路径可在 config.json 的 protocol 段或环境变量中调整。
          </p>
        </div>
        <Button size="sm" variant="outline" onClick={() => void check()} disabled={loading}>
          <RefreshCwIcon className={`mr-1.5 size-4 ${loading ? "animate-spin" : ""}`} /> 重新检查
        </Button>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-sm">
            <TerminalIcon className="size-4" /> 运行环境
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm sm:grid-cols-2">
          <div>
            <div className="text-xs text-muted-foreground">工具目录</div>
            <div className="mt-0.5 break-all font-mono text-xs">{status?.tools_dir || "—"}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Python</div>
            <div className="mt-0.5 font-mono text-xs">{status?.python || "—"}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">tshark</div>
            <div className="mt-0.5 font-mono text-xs">{status?.tshark || "—"}</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">状态</div>
            <div className="mt-1">
              {status?.ready ? (
                <Badge className="bg-emerald-500/15 text-emerald-700 dark:text-emerald-400">
                  <CheckCircle2Icon className="mr-1 size-3.5" /> 就绪
                </Badge>
              ) : (
                <Badge className="bg-amber-500/15 text-amber-700 dark:text-amber-400">
                  <AlertTriangleIcon className="mr-1 size-3.5" /> 缺少文件
                </Badge>
              )}
            </div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">缺失</div>
            <div className="mt-0.5 text-xs">{status?.missing?.length ? status.missing.join("、") : "无"}</div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">可选分析后端</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {(status?.optional ?? []).map((t) => (
            <div key={t.name} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2">
              <div className="min-w-0">
                <span className="font-mono text-xs">{t.name}</span>
                {t.path && <div className="mt-0.5 break-all text-muted-foreground text-xs">{t.path}</div>}
                {!t.ready && <p className="mt-0.5 text-muted-foreground text-xs">{t.hint}</p>}
              </div>
              {t.ready ? <Badge variant="outline">可用</Badge> : <Badge variant="secondary">未安装（可回退）</Badge>}
            </div>
          ))}
          {!(status?.optional ?? []).length && <p className="text-muted-foreground text-sm">暂无检测结果</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">工具清单</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {Object.entries(TOOL_DESCRIPTIONS).map(([name, desc]) => {
            const missing = status?.missing?.includes(name);
            return (
              <div key={name} className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2">
                <div className="min-w-0">
                  <span className="font-mono text-xs">{name}</span>
                  <p className="mt-0.5 text-xs text-muted-foreground">{desc}</p>
                </div>
                {missing ? <Badge variant="destructive">缺失</Badge> : <Badge variant="outline">可用</Badge>}
              </div>
            );
          })}
        </CardContent>
      </Card>

      {loading ? (
        <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <Loader2Icon className="size-4 animate-spin" /> 检查中…
        </div>
      ) : null}
    </div>
  );
}