"use client";

import * as React from "react";

// 协议会话状态机有向图：把 findings 的 session-model（states + transitions /
// verified_transitions，可能是数组 [from,to,label,verdict] 或对象）渲染成
// 左→右分层布局的 SVG 状态转移图。已验证迁移=绿实线，未验证=灰虚线，
// 自环（轮询）画在节点上方。端点命名不规范时按 hex 码/前缀归一匹配。

interface SMEdge {
  from: string;
  to: string;
  label: string;
  verified: boolean | null; // null = 未知
}

interface SMNode {
  id: string;
  label: string;
  col: number;
  row: number;
}

const NODE_H = 40;
const COL_GAP = 200;
const ROW_GAP = 78;
const PAD = 24;

function text(v: unknown): string {
  if (v == null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "";
}

// 状态规范名：取 "(" 前主体；并提取首个 hex 码用于模糊匹配。
function normKey(s: string): string {
  return s.split("(")[0].trim().toLowerCase();
}
function hexOf(s: string): string | null {
  const m = s.match(/0x[0-9a-fA-F]+/);
  return m ? m[0].toLowerCase() : null;
}

function parseEdges(p: Record<string, unknown>): SMEdge[] {
  const out: SMEdge[] = [];
  const push = (from: unknown, to: unknown, label: unknown, verified: unknown) => {
    const f = text(from).trim();
    const t = text(to).trim();
    if (!f || !t) return;
    let v: boolean | null = null;
    if (verified === true || /已验证|verified/i.test(text(verified))) v = true;
    else if (verified === false || /未验证|unverified/i.test(text(verified))) v = false;
    out.push({ from: f, to: t, label: text(label), verified: v });
  };
  const handle = (arr: unknown, isVerifiedList: boolean) => {
    if (!Array.isArray(arr)) return;
    for (const item of arr) {
      if (Array.isArray(item)) {
        // [from, to, label?, verdict?]
        push(item[0], item[1], item[2] ?? "", isVerifiedList ? (item[2] ?? item[3] ?? "已验证") : item[3]);
      } else if (item && typeof item === "object") {
        const o = item as Record<string, unknown>;
        push(o.from ?? o.src, o.to ?? o.dst ?? o.target, o.label ?? o.transition ?? o.code, o.verified);
      }
    }
  };
  handle(p.verified_transitions, true);
  handle(p.transitions, false);
  return out;
}

// 从观测序列（0x01→0x10→…）兜底构造链式边。
function sequenceEdges(p: Record<string, unknown>): SMEdge[] {
  const seq = text(p.observed_sequence_p2) || text(p.observed_sequence_p5);
  if (!seq) return [];
  const tokens = seq.split(/→|->/).map((s) => s.trim()).filter(Boolean);
  const out: SMEdge[] = [];
  for (let i = 0; i + 1 < tokens.length; i++) {
    out.push({ from: tokens[i], to: tokens[i + 1], label: "观测", verified: null });
  }
  return out;
}

export function SessionStateGraph({ payload }: { payload: Record<string, unknown> }) {
  const model = React.useMemo(() => {
    const rawStates = Array.isArray(payload.states) ? payload.states.map(text).filter(Boolean) : [];
    let edges = parseEdges(payload);
    if (edges.length < 2) {
      const seq = sequenceEdges(payload);
      if (seq.length > edges.length) edges = seq;
    }
    if (rawStates.length === 0 && edges.length === 0) return null;

    //  canonical 状态表（来自 states 字段）
    const canon = rawStates.map((s) => ({ key: normKey(s), hex: hexOf(s), label: s }));
    const matchCanon = (endpoint: string): string | null => {
      const k = normKey(endpoint);
      const h = hexOf(endpoint);
      for (const c of canon) {
        if (c.key === k) return c.label;
        if (h && c.hex === h) return c.label;
        if (c.key && (k.startsWith(c.key) || c.key.startsWith(k)) && k.length > 2) return c.label;
      }
      return null;
    };

    // 节点集合：canonical 状态 + 无法匹配的端点（独立节点）
    const nodeLabels: string[] = [...rawStates];
    const ensure = (endpoint: string): string => {
      const m = matchCanon(endpoint);
      if (m) return m;
      const existing = nodeLabels.find((n) => normKey(n) === normKey(endpoint) || (hexOf(n) && hexOf(n) === hexOf(endpoint)));
      if (existing) return existing;
      nodeLabels.push(endpoint);
      return endpoint;
    };
    const normEdges = edges.map((e) => ({
      from: ensure(e.from),
      to: ensure(e.to),
      label: e.label,
      verified: e.verified,
    }));
    // 去重边
    const seen = new Set<string>();
    const uniq = normEdges.filter((e) => {
      const k = `${e.from}\u0001${e.to}\u0001${e.label}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });

    // 分层：最长路径法（忽略自环），源点 col=0
    const idx = new Map(nodeLabels.map((n, i) => [n, i]));
    const incoming = new Map<string, number>();
    nodeLabels.forEach((n) => incoming.set(n, 0));
    for (const e of uniq) if (e.from !== e.to) incoming.set(e.to, (incoming.get(e.to) ?? 0) + 1);
    const col = new Map<string, number>();
    nodeLabels.forEach((n) => col.set(n, 0));
    // 迭代松弛（节点数小，足够）
    for (let iter = 0; iter < nodeLabels.length; iter++) {
      let changed = false;
      for (const e of uniq) {
        if (e.from === e.to) continue;
        const want = (col.get(e.from) ?? 0) + 1;
        if (want > (col.get(e.to) ?? 0) && want < nodeLabels.length) {
          col.set(e.to, want);
          changed = true;
        }
      }
      if (!changed) break;
    }
    // 孤立节点（无边）放最后列
    const maxCol = Math.max(0, ...Array.from(col.values()));
    nodeLabels.forEach((n) => {
      if ((incoming.get(n) ?? 0) === 0 && !uniq.some((e) => e.from === n)) col.set(n, maxCol + 1);
    });
    // 每列内排序：按原始 states 顺序
    const byCol = new Map<number, string[]>();
    nodeLabels.forEach((n) => {
      const c = col.get(n) ?? 0;
      if (!byCol.has(c)) byCol.set(c, []);
      byCol.get(c)!.push(n);
    });
    const nodes: SMNode[] = [];
    const pos = new Map<string, { x: number; y: number; w: number }>();
    const cols = Array.from(byCol.keys()).sort((a, b) => a - b);
    let maxRows = 1;
    for (const c of cols) {
      const list = byCol.get(c)!;
      maxRows = Math.max(maxRows, list.length);
      list.forEach((n, r) => {
        const w = Math.min(170, Math.max(96, n.length * 7.2 + 24));
        const x = PAD + c * COL_GAP;
        const y = PAD + r * ROW_GAP;
        nodes.push({ id: n, label: n, col: c, row: r });
        pos.set(n, { x, y, w });
      });
    }
    const width = PAD * 2 + (cols.length ? (Math.max(...cols) + 1) * COL_GAP : COL_GAP);
    const height = PAD * 2 + maxRows * ROW_GAP + 30;
    return { nodes, edges: uniq, pos, width, height, idx };
  }, [payload]);

  if (!model) return null;
  const { nodes, edges, pos, width, height } = model;

  const edgePath = (e: SMEdge) => {
    const a = pos.get(e.from)!;
    const b = pos.get(e.to)!;
    if (e.from === e.to) {
      // 自环：节点上方弧
      const cx = a.x + a.w / 2;
      const top = a.y;
      return { d: `M ${cx - 14} ${top} C ${cx - 40} ${top - 46}, ${cx + 40} ${top - 46}, ${cx + 14} ${top}`, lx: cx, ly: top - 40, self: true };
    }
    const forward = b.x >= a.x + a.w;
    if (forward) {
      const x1 = a.x + a.w, y1 = a.y + NODE_H / 2;
      const x2 = b.x, y2 = b.y + NODE_H / 2;
      const mx = (x1 + x2) / 2;
      return { d: `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`, lx: mx, ly: (y1 + y2) / 2 - 6, self: false };
    }
    // 回边：从上方绕
    const x1 = a.x + a.w / 2, y1 = a.y;
    const x2 = b.x + b.w / 2, y2 = b.y;
    const lift = Math.min(y1, y2) - 40;
    return { d: `M ${x1} ${y1} C ${x1} ${lift}, ${x2} ${lift}, ${x2} ${y2}`, lx: (x1 + x2) / 2, ly: lift - 4, self: false };
  };

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
        <span className="inline-flex items-center gap-1"><span className="inline-block h-0.5 w-5 bg-green-600" /> 已验证</span>
        <span className="inline-flex items-center gap-1"><span className="inline-block h-0.5 w-5 border-t-2 border-dashed border-gray-400" /> 未验证/观测</span>
        <span>节点 {nodes.length} · 迁移 {edges.length}</span>
      </div>
      <div className="overflow-auto rounded border bg-muted/20">
        <svg width={width} height={height} className="min-w-full">
          <defs>
            <marker id="sm-arrow-green" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#16a34a" />
            </marker>
            <marker id="sm-arrow-gray" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="#9ca3af" />
            </marker>
          </defs>
          {edges.map((e, i) => {
            const path = edgePath(e);
            const green = e.verified === true;
            const stroke = green ? "#16a34a" : "#9ca3af";
            return (
              <g key={`e${i}`}>
                <path d={path.d} fill="none" stroke={stroke} strokeWidth={green ? 1.8 : 1.3}
                  strokeDasharray={green ? undefined : "5 4"}
                  markerEnd={`url(#sm-arrow-${green ? "green" : "gray"})`} />
                {e.label ? (
                  <text x={path.lx} y={path.ly} textAnchor="middle" className="fill-muted-foreground"
                    fontSize="10" fontFamily="monospace">
                    {e.label.length > 26 ? e.label.slice(0, 25) + "…" : e.label}
                  </text>
                ) : null}
              </g>
            );
          })}
          {nodes.map((n) => {
            const p = pos.get(n.id)!;
            const isStart = n.row === 0 && n.col === 0;
            const isClose = /closed|close|释放|末尾/i.test(n.label);
            return (
              <g key={n.id}>
                <rect x={p.x} y={p.y} width={p.w} height={NODE_H} rx={8}
                  fill={isClose ? "#fee2e2" : isStart ? "#dcfce7" : "#ffffff"}
                  stroke={isClose ? "#ef4444" : isStart ? "#16a34a" : "#64748b"} strokeWidth={1.3} />
                <text x={p.x + p.w / 2} y={p.y + NODE_H / 2 + 3.5} textAnchor="middle"
                  fontSize="11" fontFamily="monospace" fill="#1e293b">
                  {n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
