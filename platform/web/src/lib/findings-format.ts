import type { ProtocolField, ProtocolNote } from "./protocol-api";

// Agent-authored findings use several shapes for the same data (traffic vs
// static field keys, nested payloads, pairs vs items). These helpers keep the
// rendering tolerant and are covered by node --test regressions.

export function scalarText(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "string") return v || "-";
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "-";
}

// Findings rows returned by the API are DB projections; source/verdict live in
// the full item payload (frames: detail, fields/codes: payload).
export function findingMeta(item: { source?: string; verdict?: string; payload?: unknown; detail?: unknown }): {
  verdict?: string;
  source?: string;
} {
  const raw = (item.payload ?? item.detail ?? {}) as Record<string, unknown>;
  return {
    verdict: typeof raw.verdict === "string" ? raw.verdict : item.verdict,
    source: typeof raw.source === "string" ? raw.source : item.source,
  };
}

export function fieldValuesText(f: ProtocolField): string {
  if (Array.isArray(f.values)) return f.values.length ? f.values.join("/") : "-";
  if (typeof f.values === "string") return f.values || "-";
  return scalarText(f.value);
}

// P5 agents have written both {kind,payload:{states,...}} and a nested
// {kind,payload:{payload:{states,...}}} shape; return the innermost payload.
export function unwrapNotePayload(note: ProtocolNote): Record<string, unknown> {
  const raw = (note.payload ?? {}) as Record<string, unknown>;
  const inner = raw.payload;
  if (inner && typeof inner === "object" && !Array.isArray(inner)) {
    return inner as Record<string, unknown>;
  }
  return raw;
}

export function reconciliationItems(notes: ProtocolNote[]): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  for (const note of notes) {
    if (note.kind !== "code-reconciliation") continue;
    const payload = (note.payload ?? {}) as Record<string, unknown>;
    const nested =
      payload.payload && typeof payload.payload === "object" && !Array.isArray(payload.payload)
        ? (payload.payload as Record<string, unknown>)
        : null;
    const list = [payload.pairs, payload.items, nested?.pairs, nested?.items].find((v) => Array.isArray(v));
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (!item || typeof item !== "object") continue;
      const row = item as Record<string, unknown>;
      const key = JSON.stringify([row.code, row.verdict, row.traffic ?? row.traffic_label, row.static ?? row.static_label]);
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(row);
      if (out.length >= 500) return out;
    }
  }
  return out;
}