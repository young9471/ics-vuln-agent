import { http, sseUrl } from "@/lib/api";

export type ProtocolAuthorization = "read-only" | "write" | "destructive" | "full";
export type ProtocolCaseStatus = "draft" | "queued" | "running" | "paused" | "done" | "failed";
export type ProtocolPhaseStatus = "pending" | "running" | "pass" | "fail" | "skip";

export interface ProtocolCase {
  id: number;
  name: string;
  description: string;
  install_root: string;
  device_ip: string;
  authorization: ProtocolAuthorization;
  status: ProtocolCaseStatus;
  mode: "live" | "static";
  workdir: string;
  config: Record<string, unknown>;
  findings?: Record<string, unknown>;
  error?: string;
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
}

export interface ProtocolPhase {
  case_id: number;
  phase: string;
  gate: string;
  status: ProtocolPhaseStatus;
  detail: string;
  evidence?: Record<string, unknown>;
  started_at?: string;
  finished_at?: string;
  updated_at: string;
}

export interface ProtocolAsset {
  id: number;
  case_id: number;
  path: string;
  name: string;
  ext: string;
  score: number;
  comm_exports: number;
  machine: string;
  md5: string;
  config_ips?: unknown;
  grade: string;
  evidence?: unknown;
  created_at: string;
}

export interface ProtocolStream {
  id: number;
  case_id: number;
  pcap: string;
  stream: number;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  protocol: string;
  bytes: number;
  frames: number;
  grade: string;
}

export interface ProtocolFrame {
  id: number;
  case_id: number;
  frame_key: string;
  protocol: string;
  stream: number;
  magic: string;
  alt_magic: string;
  header_size: number;
  len_offset: number;
  len_size: number;
  endian: string;
  len_bias: number;
  frames: number;
  bytes: number;
  carrier: string;
  inner_layout: string;
  channels: string;
  commands_observed: number;
  grade: string;
  source?: string;
  verdict?: string;
  detail?: unknown;
}

export interface ProtocolField {
  name?: string;
  class?: string;
  kind?: string;
  off?: number;
  offset?: number;
  size?: number;
  width?: number;
  type?: string;
  value?: string | number | boolean;
  values?: string[] | string;
  distinct?: number;
  note?: string;
  evidence?: string;
}

export interface ProtocolFieldMap {
  id: number;
  case_id: number;
  map_key: string;
  direction: string;
  samples: number;
  frame_len_min: number;
  frame_len_max: number;
  grade: string;
  fields: ProtocolField[];
  tail?: { from_off?: number; len_range?: number[] };
  source?: string;
  verdict?: string;
  payload?: unknown;
}

export interface ProtocolFunctionCode {
  id: number;
  case_id: number;
  layer: string;
  code: number;
  code_key: string;
  label: string;
  grade: string;
  evidence: string;
  source: string;
  verdict?: string;
  verified: boolean;
  semantic?: boolean;
  payload?: unknown;
}

export interface ProtocolCodeView extends ProtocolFunctionCode {
  case_name: string;
}

export interface ProtocolProbe {
  id: number;
  case_id: number;
  kind: string;
  spec: string;
  host: string;
  port: number;
  action: string;
  request: string;
  response: string;
  status: string;
  grade: string;
  reason?: string;
  payload?: unknown;
  created_at: string;
}

export interface ProtocolNote {
  id: number;
  case_id: number;
  kind: string;
  payload?: unknown;
  created_at: string;
}

export interface ProtocolFindings {
  case_id: number;
  raw?: unknown;
  comm_assets: ProtocolAsset[] | null;
  streams: ProtocolStream[] | null;
  frame_formats: ProtocolFrame[] | null;
  field_maps: ProtocolFieldMap[] | null;
  function_codes: ProtocolFunctionCode[] | null;
  probes: ProtocolProbe[] | null;
  notes: ProtocolNote[] | null;
}

export interface ProtocolReport {
  case_id: number;
  doc_type: string;
  title: string;
  content: string;
  version: number;
  approved_by?: string;
  approved_at?: string;
  approved_version?: number;
  updated_at: string;
}

export interface ProtocolReportVersion {
  id: number;
  case_id: number;
  doc_type: string;
  version: number;
  title: string;
  content: string;
  created_at: string;
}

export interface ProtocolArtifact {
  id: number;
  case_id: number;
  kind: string;
  name: string;
  path: string;
  size: number;
  sha256: string;
  created_at: string;
}

export interface ProtocolEvent {
  id: number;
  case_id: number;
  phase: string;
  kind: string;
  message: string;
  payload?: unknown;
  created_at: string;
}

export interface ProtocolCaseDetail {
  case: ProtocolCase;
  phases: ProtocolPhase[] | null;
  findings: ProtocolFindings;
  reports: ProtocolReport[] | null;
  artifacts: ProtocolArtifact[] | null;
  running: boolean;
}

export interface ProtocolStats {
  cases: number;
  running: number;
  done: number;
  failed: number;
  assets: number;
  frames: number;
  field_maps: number;
  codes: number;
  verified_codes: number;
  codes_by_grade: Record<string, number>;
  phase_counts: Record<string, number>;
}

export interface ProtocolCaseInput {
  name: string;
  description?: string;
  install_root?: string;
  device_ip?: string;
  authorization?: ProtocolAuthorization;
  mode?: "live" | "static";
  workdir?: string;
  config?: Record<string, unknown>;
}

export interface ProtocolOptionalTool {
  name: string;
  path: string;
  ready: boolean;
  hint: string;
}

export interface ProtocolToolStatus {
  tools_dir: string;
  python: string;
  tshark: string;
  missing: string[];
  ready: boolean;
  optional: ProtocolOptionalTool[];
}

export const protocolApi = {
  listCases(params?: { status?: string; q?: string; page?: number; page_size?: number }) {
    const p = new URLSearchParams();
    if (params?.status) p.set("status", params.status);
    if (params?.q) p.set("q", params.q);
    if (params?.page) p.set("page", String(params.page));
    if (params?.page_size) p.set("page_size", String(params.page_size));
    const qs = p.toString();
    return http<{ items: ProtocolCase[] | null; total: number; page: number; page_size: number }>(
      `/protocol/cases${qs ? `?${qs}` : ""}`,
    );
  },
  createCase(body: ProtocolCaseInput) {
    return http<ProtocolCase>("/protocol/cases", { method: "POST", body: JSON.stringify(body) });
  },
  createCaseMultipart(body: ProtocolCaseInput, file: File) {
    const fd = new FormData();
    for (const [key, value] of Object.entries(body)) {
      if (value === undefined) continue;
      fd.append(key, typeof value === "string" ? value : JSON.stringify(value));
    }
    fd.append("pcap", file);
    return http<ProtocolCase>("/protocol/cases", { method: "POST", body: fd });
  },
  getCase(id: number) {
    return http<ProtocolCaseDetail>(`/protocol/cases/${id}`);
  },
  updateCase(id: number, body: ProtocolCaseInput) {
    return http<ProtocolCase>(`/protocol/cases/${id}`, { method: "PATCH", body: JSON.stringify(body) });
  },
  updateCode(caseId: number, codeId: number, body: { label: string; grade?: string }) {
    return http<ProtocolFunctionCode>(`/protocol/cases/${caseId}/codes/${codeId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  },
  deleteCase(id: number) {
    return http<{ ok: boolean }>(`/protocol/cases/${id}`, { method: "DELETE" });
  },
  agentRun(id: number, opts?: { message?: string; llm_profile_id?: number }) {
    return http<{ status: string; conversation_id: number }>(`/protocol/cases/${id}/agent-run`, {
      method: "POST",
      body: JSON.stringify(opts ?? {}),
    });
  },
  uploadPcap(id: number, file: File) {
    const form = new FormData();
    form.append("file", file);
    return http<{ ok: boolean; name: string; path: string }>(`/protocol/cases/${id}/pcaps`, {
      method: "POST",
      body: form,
      headers: {},
    });
  },
  uploadArtifact(id: number, file: File) {
    const form = new FormData();
    form.append("file", file);
    return http<{ ok: boolean; name: string; path: string }>(`/protocol/cases/${id}/artifacts`, {
      method: "POST",
      body: form,
      headers: {},
    });
  },
  captureInterfaces() {
    return http<{ interfaces: CaptureInterface[] }>("/protocol/capture/interfaces").then((r) => r.interfaces ?? []);
  },
  captureStatus(id: number) {
    return http<ProtocolCaptureStatus>(`/protocol/cases/${id}/capture`);
  },
  startCapture(id: number, body: { interface: string; filter?: string; duration_seconds?: number }) {
    return http<ProtocolCaptureStatus>(`/protocol/cases/${id}/capture`, { method: "POST", body: JSON.stringify(body) });
  },
  stopCapture(id: number) {
    return http<{ ok: boolean; status: string }>(`/protocol/cases/${id}/capture/stop`, { method: "POST", body: "{}" });
  },
  findings(id: number) {
    return http<ProtocolFindings>(`/protocol/cases/${id}/findings`);
  },
  approvals(id: number) {
    return http<{ items: ProtocolApproval[] | null }>(`/protocol/cases/${id}/approvals`).then(
      (r) => r.items ?? [],
    );
  },
  createApproval(id: number, body: { kind?: string; risk?: string; payload?: Record<string, unknown>; note?: string }) {
    return http<ProtocolApproval>(`/protocol/cases/${id}/approvals`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },
  decideApproval(approvalId: number, decision: "approve" | "reject", note?: string) {
    return http<ProtocolApproval>(`/protocol/approvals/${approvalId}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, note: note ?? "" }),
    });
  },
  phases(id: number) {
    return http<{ items: ProtocolPhase[] | null }>(`/protocol/cases/${id}/phases`);
  },
  reports(id: number) {
    return http<{ items: ProtocolReport[] | null }>(`/protocol/cases/${id}/reports`);
  },
  metrics(id: number) {
    return http<{ phases: ProtocolPhaseMetric[] | null; agents: ProtocolAgentUsage[] | null }>(
      `/protocol/cases/${id}/metrics`,
    );
  },
  phaseJobs(id: number) {
    return http<{ items: ProtocolPhaseJob[] | null; running: string[] }>(`/protocol/cases/${id}/phase-jobs`);
  },
  cancelPhaseJob(id: number, phase: string) {
    return http<{ ok: boolean; case_id: number; phase: string; status: string }>(
      `/protocol/cases/${id}/phase-jobs/${encodeURIComponent(phase)}/cancel`,
      { method: "POST", body: "{}" },
    );
  },
  pcapQuality(id: number) {
    return http<{ items: ProtocolPcapQuality[] | null }>(`/protocol/cases/${id}/pcaps/quality`).then((r) => r.items ?? []);
  },
  reportVersions(id: number, docType: string) {
    return http<{ items: ProtocolReportVersion[] | null }>(
      `/protocol/cases/${id}/reports/${encodeURIComponent(docType)}/versions`,
    ).then((r) => r.items ?? []);
  },
  approveReport(id: number, docType: string) {
    return http<ProtocolReport>(`/protocol/cases/${id}/reports/${encodeURIComponent(docType)}/approve`, {
      method: "POST",
      body: "{}",
    });
  },
  async exportReports(id: number): Promise<Blob> {
    const token = typeof window === "undefined" ? null : localStorage.getItem("protocol_agent_token");
    const r = await fetch(`/api/protocol/cases/${id}/reports/export`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!r.ok) throw new Error(`导出失败: ${r.status}`);
    return r.blob();
  },
  events(id: number, after = 0, limit = 500) {
    return http<{ items: ProtocolEvent[] | null }>(`/protocol/cases/${id}/events?after=${after}&limit=${limit}`);
  },
  exploitScript(id: number, path: string) {
    return http<{ path: string; name: string; size: number; content: string }>(
      `/protocol/cases/${id}/exploit?path=${encodeURIComponent(path)}`,
    );
  },
  vulnDashboard() {
    return http<VulnDashboard>(`/protocol/dashboard`);
  },
  listFindings(params?: { q?: string; grade?: string; layer?: string; limit?: number }) {
    const p = new URLSearchParams();
    if (params?.q) p.set("q", params.q);
    if (params?.grade) p.set("grade", params.grade);
    if (params?.layer) p.set("layer", params.layer);
    if (params?.limit) p.set("limit", String(params.limit));
    const qs = p.toString();
    return http<{ items: ProtocolCodeView[] | null }>(`/protocol/findings${qs ? `?${qs}` : ""}`);
  },
  stats() {
    return http<ProtocolStats>("/protocol/stats");
  },
  tools() {
    return http<ProtocolToolStatus>("/protocol/tools/check");
  },
};

export function protocolEventStreamUrl(caseId: number, since = 0) {
  return sseUrl(`/api/protocol/cases/${caseId}/events/stream?since=${since}`);
}

export const PHASES = ["P1", "P2", "P3", "P4", "P5", "P6"] as const;
export const V2_PHASES = ["P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"] as const;

export const PHASE_META: Record<string, { title: string; gate: string; desc: string }> = {
  P1: { title: "P1 资产侦察", gate: "A", desc: "扫描安装目录，定位通信承载体与端口线索" },
  P2: { title: "P2 流量获取", gate: "B", desc: "后台抓包或解析既有 pcap，确认协议生命周期覆盖" },
  P3: { title: "P3 流量分析", gate: "C", desc: "只从流量推断功能码语义、帧格式与字段划分" },
  P4: { title: "P4 静态分析", gate: "D", desc: "只从通信文件静态推断功能码语义、帧格式与字段划分" },
  P5: { title: "P5 交叉验证", gate: "E", desc: "交叉佐证 P3/P4 结果，再按授权动态验证或降级" },
  P6: { title: "P6 文档交付", gate: "F", desc: "消费佐证结果定名功能码，生成四份交付文档" },
  P7: { title: "P7 漏洞面测绘", gate: "G", desc: "设备画像、情报匹配与直判类检测，产出三态适用性与假设" },
  P8: { title: "P8 验证与Fuzz", gate: "H", desc: "destructive 假设走审批后确定性验证，模糊类执行灰盒 campaign" },
  P9: { title: "P9 EXP与报告", gate: "I", desc: "汇总定级，生成可复现 EXP 与漏洞报告" },
};

// ---------------------------------------------------------------------------
// V2 漏洞挖掘（P7-P9）：findings 原文（raw）里的新 section 与审批 API
// ---------------------------------------------------------------------------
export interface VulnEvidenceRef { ref?: string; grade?: string }

export interface VulnCapabilityRow {
  protocol?: VulnEvidenceRef[];
  service?: VulnEvidenceRef[];
  physical?: VulnEvidenceRef[];
}

export interface DeviceProfile {
  facts?: { vendor?: string; model?: string; firmware?: string; os?: string; device_ip?: string };
  matrix?: Record<string, VulnCapabilityRow>;
  firmware_obtainable?: string;
  tracks?: string[];
  ports_scanned?: Record<string, boolean>;
}

export interface VulnHypothesis {
  id: string;
  template_id?: string;
  vclass?: number;
  name: string;
  risk?: "read" | "write" | "destructive";
  detection?: "deterministic" | "fuzz";
  state?: string;
  requires_approval?: boolean;
  plan?: string;
  verdict?: string;
  verdict_rule?: string;
  verdict_reason?: string;
  evidence?: unknown;
  ts?: string;
}

export interface ExploitAsset {
  id: string;
  hypothesis?: string;
  tier?: string;
  path?: string;
  sha256_16?: string;
  risk?: string;
  frames?: string[];
  expect?: Record<string, unknown>;
  evidence_level?: string;
  ts?: string;
}

export interface ApplicabilityItem {
  template_id?: string;
  vclass?: number;
  name?: string;
  risk?: string;
  detection?: string;
  state?: "applicable" | "not_applicable" | "unknown";
  reason?: string;
  missing_caps?: string[];
}

export interface IntelHit {
  cve_id?: string;
  summary?: string;
  vclass?: number;
  vclass_guess?: number;
  source?: string;
  protocols?: string | string[];
  confidence?: string;
  cvss?: number;
}

export interface VulnSurface {
  applicability?: {
    summary?: { total?: number; applicable?: number; not_applicable?: number; unknown?: number };
    items?: ApplicabilityItem[];
    posture_tasks?: { capability?: string; hint?: string; blocks?: string[] }[];
  };
  intel_matches?: {
    ts?: string;
    merged?: IntelHit[];
    sources_ok?: Record<string, boolean | null>;
  };
}

export interface CampaignRecord {
  campaign_id?: string;
  hypothesis?: string;
  mode?: "verify" | "fuzz" | string;
  risk?: string;
  started?: string;
  finished?: string;
  approval?: string;
  packets_sent?: number;
  duration_sec?: number;
  response_histogram?: Record<string, number>;
  new_classes?: string[];
  reconnects?: number;
  crashes?: { sample?: string; minimized_hex?: string; rate_hint?: string }[];
  circuit_breaker?: string;
  _redline?: boolean;
  guardian?: { red_line?: boolean };
  verify_verdicts?: { label?: string; verdict?: string; expect_fail?: string }[];
  result?: string;
  note?: string;
}

export interface DashboardCaseRow {
  case_id: number;
  name: string;
  mode: string;
  status: string;
  vuln_enabled: boolean;
  p7: string;
  p8: string;
  p9: string;
  confirmed: number;
  hypotheses: number;
  exploits: number;
}

export interface DashboardApproval {
  id: number;
  case_id: number;
  kind: string;
  risk: string;
  status: string;
  hypothesis: string;
  requested_by: string;
  created_at: string;
  decided_at?: string;
}

export interface DashboardEvent {
  id: number;
  case_id: number;
  phase: string;
  kind: string;
  message: string;
  created_at: string;
}

export interface VulnDashboard {
  cases: { total: number; running: number; done: number; vuln_enabled: number };
  hypotheses: {
    total: number;
    by_state: Record<string, number>;
    by_vclass: Record<string, number>;
    confirmed_by_risk: Record<string, number>;
  };
  exploits: { total: number; by_tier: Record<string, number> };
  campaigns: { total: number; by_mode: Record<string, number> };
  approvals: { pending: number; recent: DashboardApproval[] | null };
  knowledge: { rows: number; cves: number; vclass_covered: number };
  events: DashboardEvent[] | null;
  case_rows: DashboardCaseRow[] | null;
}

export interface ProtocolApproval {
  id: number;
  case_id: number;
  kind: string;
  payload: Record<string, unknown>;
  risk: string;
  status: "pending" | "approved" | "rejected";
  requested_by: string;
  decided_by?: string;
  decided_at?: string;
  note?: string;
  created_at: string;
}

export function fmtProtocolTime(v?: string) {
  if (!v) return "-";
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? v : d.toLocaleString("zh-CN");
}

export function hexCode(code: number) {
  return `0x${code.toString(16).padStart(4, "0")}`;
}

// codeDisplay prefers the raw P4/P6 spelling (e.g. 0x58/0x01) over the
// normalized identity, so sub-code zero padding stays readable in tables.
export function codeDisplay(c: { code: number; code_key?: string; payload?: unknown }): string {
  const raw = (c.payload as Record<string, unknown> | undefined)?.code;
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  return c.code_key || hexCode(c.code);
}

export const GRADE_META: Record<string, { title: string }> = {
  traffic: { title: "流量证据：pcap/帧级事实" },
  live: { title: "实机验证：live 探针成功" },
  static: { title: "静态证据：二进制/配置，尚未 live 验证" },
  inferred: { title: "推断，未确认" },
};

export function isLiveVerified(c: { verified?: boolean; grade?: string }): boolean {
  return c.verified === true && c.grade === "live";
}
export interface CaptureInterface {
  id: string;
  name: string;
}

export interface ProtocolCaptureStatus {
  case_id?: number;
  interface?: string;
  filter?: string;
  path?: string;
  started_at?: string;
  status: string;
  running: boolean;
  bytes?: number;
  error?: string;
  log_path?: string;
}

export interface ProtocolPcapQuality {
  path: string;
  name: string;
  bytes: number;
  packets: number;
  duration_seconds: number;
  endpoints: number;
  protocols: string[];
  warnings: string[];
  error?: string;
}

export interface ProtocolPhaseJob {
  job_id: string;
  case_id: number;
  phase: string;
  agent_key?: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  passed?: boolean;
}

export interface ProtocolPhaseMetric {
  phase: string;
  status: string;
  runs: number;
  avg_duration_ms: number;
}

export interface ProtocolAgentUsage {
  agent: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
}
