package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/protocol-agent/config"
	"github.com/Autumn-27/protocol-agent/db"
	"github.com/Autumn-27/protocol-agent/protocol"
)

// protocolHub is a per-case in-process pub/sub for pipeline events. The runner
// persists every event to protocol_events first, so the DB remains the source of
// truth and an SSE client can always catch up by id after a reconnect.
type protocolHub struct {
	mu   sync.Mutex
	subs map[int64]map[chan db.ProtocolEvent]struct{}
}

func newProtocolHub() *protocolHub {
	return &protocolHub{subs: map[int64]map[chan db.ProtocolEvent]struct{}{}}
}

func (h *protocolHub) subscribe(caseID int64) (<-chan db.ProtocolEvent, func()) {
	ch := make(chan db.ProtocolEvent, 256)
	h.mu.Lock()
	if h.subs[caseID] == nil {
		h.subs[caseID] = map[chan db.ProtocolEvent]struct{}{}
	}
	h.subs[caseID][ch] = struct{}{}
	h.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			if m := h.subs[caseID]; m != nil {
				delete(m, ch)
				if len(m) == 0 {
					delete(h.subs, caseID)
				}
			}
			h.mu.Unlock()
			close(ch)
		})
	}
}

func (h *protocolHub) publish(e *db.ProtocolEvent) {
	if e == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[e.CaseID] {
		select {
		case ch <- *e:
		default:
			// Slow client: it will resume from protocol_events by id.
		}
	}
}

// emitProtocolEvent persists one case event and fans it out over SSE. Agent
// phase boundaries and gate verdicts use the same log the UI shows.
func (s *Server) emitProtocolEvent(caseID int64, phase, kind, message string, payload any) {
	if s.m.pg == nil {
		return
	}
	var raw json.RawMessage
	if payload != nil {
		if b, err := json.Marshal(payload); err == nil {
			raw = b
		}
	}
	rec, err := s.m.pg.AppendProtocolEvent(caseID, phase, kind, message, raw)
	if err != nil {
		log.Printf("[protocol %d] event: %v", caseID, err)
		return
	}
	if s.protocolHub != nil {
		s.protocolHub.publish(rec)
	}
}

type protocolCaseRequest struct {
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	InstallRoot   string          `json:"install_root"`
	DeviceIP      string          `json:"device_ip"`
	Authorization string          `json:"authorization"`
	Mode          string          `json:"mode"`
	Workdir       string          `json:"workdir"`
	Config        json.RawMessage `json:"config"`
}

// protocolCaseConfigMap decodes a case config blob for validation.
func protocolCaseConfigMap(raw json.RawMessage) map[string]any {
	cfg := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &cfg)
	}
	return cfg
}

// protocolCasePcapPaths lists pcap candidates referenced by the case config.
// Relative paths resolve against baseDir; create-time validation passes "" and
// rejects them because the default workdir does not exist before insertion.
func protocolCasePcapPaths(cfg map[string]any, baseDir string) []string {
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if !filepath.IsAbs(raw) && baseDir != "" {
			raw = filepath.Join(baseDir, raw)
		}
		out = append(out, raw)
	}
	if p, ok := cfg["pcap"].(string); ok {
		add(p)
	}
	if gold, ok := cfg["golden_artifacts"].(map[string]any); ok {
		for k, v := range gold {
			s, _ := v.(string)
			low := strings.ToLower(strings.TrimSpace(s))
			if strings.Contains(strings.ToLower(k), "pcap") ||
				strings.HasSuffix(low, ".pcap") || strings.HasSuffix(low, ".pcapng") || strings.HasSuffix(low, ".cap") {
				add(s)
			}
		}
	}
	return out
}

// validateProtocolCaseMode enforces the two supported creation paths:
// live cases need a device IP; static cases need at least one existing pcap.
func validateProtocolCaseMode(mode, deviceIP string, cfg map[string]any, baseDir string) error {
	switch mode {
	case "live":
		if strings.TrimSpace(deviceIP) == "" {
			return fmt.Errorf("live 模式必须填写设备 IP")
		}
	case "static":
		paths := protocolCasePcapPaths(cfg, baseDir)
		if len(paths) == 0 {
			return fmt.Errorf("static 模式必须提供抓包文件（.pcap/.pcapng）用于后续分析")
		}
		for _, p := range paths {
			if !filepath.IsAbs(p) {
				return fmt.Errorf("抓包文件请填写绝对路径：%s", p)
			}
			if st, err := os.Stat(p); err != nil || st.IsDir() {
				return fmt.Errorf("抓包文件不存在：%s", p)
			}
		}
	default:
		return fmt.Errorf("mode 必须是 live 或 static")
	}
	return nil
}

func (s *Server) protocolListCases(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size < 1 {
		size = 50
	}
	items, total, err := pg.ListProtocolCases(r.URL.Query().Get("status"), r.URL.Query().Get("q"), size, (page-1)*size)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) protocolCreateCase(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		s.protocolCreateCaseMultipart(w, r, pg)
		return
	}
	var req protocolCaseRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if err := normalizeProtocolCaseRequest(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateProtocolCaseMode(req.Mode, req.DeviceIP, protocolCaseConfigMap(req.Config), ""); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, err := pg.CreateProtocolCase(db.ProtocolCaseInput{
		Name: req.Name, Description: req.Description, InstallRoot: req.InstallRoot,
		DeviceIP: req.DeviceIP, Authorization: req.Authorization, Mode: req.Mode,
		Workdir: req.Workdir, Config: req.Config,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 201, c)
}

func normalizeProtocolCaseRequest(req *protocolCaseRequest) error {
	req.Authorization = strings.TrimSpace(req.Authorization)
	if req.Authorization == "" {
		req.Authorization = "read-only"
	}
	switch req.Authorization {
	case "read-only", "write", "destructive", "full":
	default:
		return fmt.Errorf("authorization 必须是 read-only / write / destructive / full")
	}
	req.Mode = strings.ToLower(strings.TrimSpace(req.Mode))
	if req.Mode == "" {
		if strings.TrimSpace(req.DeviceIP) != "" {
			req.Mode = "live"
		} else {
			req.Mode = "static"
		}
	}
	return nil
}

// protocolCreateCaseMultipart creates a case and stores an uploaded pcap in one
// request. The case row is created first because the workdir is derived from its
// id; validation failure rolls the row back.
func (s *Server) protocolCreateCaseMultipart(w http.ResponseWriter, r *http.Request, pg *db.DB) {
	if s.protocolRunner == nil {
		writeErr(w, 503, "protocol runner unavailable")
		return
	}
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		writeErr(w, 400, "multipart: "+err.Error())
		return
	}
	req := protocolCaseRequest{
		Name: r.FormValue("name"), Description: r.FormValue("description"),
		InstallRoot: r.FormValue("install_root"), DeviceIP: r.FormValue("device_ip"),
		Authorization: r.FormValue("authorization"), Mode: r.FormValue("mode"),
		Workdir: r.FormValue("workdir"),
	}
	if raw := strings.TrimSpace(r.FormValue("config")); raw != "" {
		if !json.Valid([]byte(raw)) {
			writeErr(w, 400, "config 必须是 JSON")
			return
		}
		req.Config = json.RawMessage(raw)
	}
	if err := normalizeProtocolCaseRequest(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	var pcapFile multipart.File
	var pcapHeader *multipart.FileHeader
	if f, h, err := r.FormFile("pcap"); err == nil {
		pcapFile, pcapHeader = f, h
		defer pcapFile.Close()
	}
	if req.Mode == "live" {
		if err := validateProtocolCaseMode(req.Mode, req.DeviceIP, protocolCaseConfigMap(req.Config), ""); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
	}
	if req.Mode == "static" && pcapHeader == nil && len(protocolCasePcapPaths(protocolCaseConfigMap(req.Config), "")) == 0 {
		writeErr(w, 400, "static 模式必须上传 pcap 或提供已存在的抓包文件路径")
		return
	}
	c, err := pg.CreateProtocolCase(db.ProtocolCaseInput{
		Name: req.Name, Description: req.Description, InstallRoot: req.InstallRoot,
		DeviceIP: req.DeviceIP, Authorization: req.Authorization, Mode: req.Mode,
		Workdir: req.Workdir, Config: req.Config,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	fail := func(status int, msg string) {
		_ = pg.DeleteProtocolCase(c.ID)
		writeErr(w, status, msg)
	}
	if pcapHeader != nil {
		if _, status, err := s.saveCasePcap(pg, c, pcapHeader, pcapFile); err != nil {
			fail(status, err.Error())
			return
		}
		updated, err := pg.GetProtocolCase(c.ID)
		if err != nil || updated == nil {
			fail(500, "reload case failed")
			return
		}
		c = updated
	}
	if req.Mode == "static" {
		if err := validateProtocolCaseMode(req.Mode, c.DeviceIP, protocolCaseConfigMap(c.Config), s.protocolRunner.Workdir(c)); err != nil {
			fail(400, err.Error())
			return
		}
	}
	writeJSON(w, 201, c)
}

// saveCasePcap stores an uploaded capture under <workdir>/pcaps and registers it
// in config.golden_artifacts so gate B and the agents see it.
func (s *Server) saveCasePcap(pg *db.DB, c *db.ProtocolCase, header *multipart.FileHeader, file multipart.File) (string, int, error) {
	name := filepath.Base(header.Filename)
	ext := strings.ToLower(filepath.Ext(name))
	if name == "" || name == "." || (ext != ".pcap" && ext != ".pcapng" && ext != ".cap") {
		return "", 400, fmt.Errorf("only .pcap / .pcapng / .cap are accepted")
	}
	if err := s.checkProtocolCaseQuota(c, header.Size); err != nil {
		return "", 413, err
	}
	dir := filepath.Join(s.protocolRunner.Workdir(c), "pcaps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", 500, err
	}
	dst := filepath.Join(dir, name)
	if _, err := os.Stat(dst); err == nil {
		dst = filepath.Join(dir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), name))
	}
	out, err := os.Create(dst)
	if err != nil {
		return "", 500, err
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		return "", 500, err
	}
	if err := out.Close(); err != nil {
		return "", 500, err
	}
	abs, _ := filepath.Abs(dst)
	var cfg map[string]any
	_ = json.Unmarshal(c.Config, &cfg)
	if cfg == nil {
		cfg = map[string]any{}
	}
	gold, _ := cfg["golden_artifacts"].(map[string]any)
	if gold == nil {
		gold = map[string]any{}
	}
	gold["pcap_codesys"] = abs
	cfg["golden_artifacts"] = gold
	if b, err := json.Marshal(cfg); err == nil {
		_ = pg.UpdateProtocolCaseConfig(c.ID, b)
	}
	return abs, 201, nil
}

func (s *Server) protocolGetCase(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	phases, _ := pg.ListProtocolPhases(id)
	// Match the /phases endpoint: synthesize not_started rows for the case's
	// active order so the UI detail view shows P7-P9 for opted-in cases.
	seenPhases := map[string]bool{}
	for _, p := range phases {
		seenPhases[p.Phase] = true
	}
	for _, ph := range s.activePhaseOrder(id) {
		if seenPhases[ph] {
			continue
		}
		phases = append(phases, &db.ProtocolPhase{
			CaseID: id, Phase: ph, Gate: protocolPhaseGate(ph), Status: "not_started",
		})
	}
	findings, _ := pg.GetProtocolFindings(id)
	reports, _ := pg.ListProtocolReports(id)
	artifacts, _ := pg.ListProtocolArtifacts(id)
	writeJSON(w, 200, map[string]any{
		"case": c, "phases": phases, "findings": findings,
		"reports": reports, "artifacts": artifacts,
		"running": c.Status == "running",
	})
}

func (s *Server) protocolUpdateCase(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	var req protocolCaseRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Authorization != "" {
		switch req.Authorization {
		case "read-only", "write", "destructive", "full":
		default:
			writeErr(w, 400, "authorization 必须是 read-only / write / destructive / full")
			return
		}
	}
	existing, err := pg.GetProtocolCase(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if existing == nil {
		writeErr(w, 404, "case not found")
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = existing.Mode
	}
	cfgRaw := req.Config
	if len(cfgRaw) == 0 {
		cfgRaw = existing.Config
	}
	// Relative pcap paths in an update resolve against the case workdir.
	if err := validateProtocolCaseMode(mode, req.DeviceIP, protocolCaseConfigMap(cfgRaw), s.protocolRunner.Workdir(existing)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, err := pg.UpdateProtocolCase(id, db.ProtocolCaseInput{
		Name: req.Name, Description: req.Description, InstallRoot: req.InstallRoot,
		DeviceIP: req.DeviceIP, Authorization: req.Authorization, Mode: mode,
		Workdir: req.Workdir, Config: req.Config,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) protocolUpdateCodeSemantics(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	codeID, ok := pathInt(r, "codeId")
	if !ok || codeID <= 0 {
		writeErr(w, 400, "invalid code id")
		return
	}
	var req struct {
		Label string `json:"label"`
		Grade string `json:"grade"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		writeErr(w, 400, "label 必填")
		return
	}
	grade := strings.ToLower(strings.TrimSpace(req.Grade))
	switch grade {
	case "", "traffic", "live", "static", "inferred":
	default:
		writeErr(w, 400, "grade 必须是 traffic / live / static / inferred")
		return
	}
	updated, err := pg.UpdateProtocolCodeSemantics(id, codeID, label, grade)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "功能码不存在")
		return
	}
	writeJSON(w, 200, updated)
}

func (s *Server) protocolDeleteCase(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	if c, err := pg.GetProtocolCase(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	} else if c != nil && c.Status == "running" {
		writeErr(w, 409, "Agent 正在分析该案例，请先在对话页停止再删除")
		return
	}
	s.clearProtocolJobs(id)
	if err := pg.DeleteProtocolCase(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// protocolAgentRun creates a conversation with the built-in protocol agent. This
// is the only way to analyze a case: the main agent delegates each phase to the
// matching sub-agent and the platform only judges the returned evidence.
func (s *Server) protocolAgentRun(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	if c.Status == "running" {
		writeErr(w, 409, "该案例已有 Agent 分析在运行，请先停止原对话")
		return
	}
	if a, err := pg.GetAgentByKey("protocol"); err != nil || a == nil {
		writeErr(w, 503, "protocol agent 未初始化")
		return
	}
	var req struct {
		Message      string `json:"message"`
		LLMProfileID *int64 `json:"llm_profile_id"`
	}
	if r.Body != nil {
		_ = decode(r, &req)
	}
	title := "协议主控 · " + c.Name
	conv, err := pg.CreateConversation("protocol", title, req.LLMProfileID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if s.resolveChatAgent(conv) == nil {
		_ = pg.DeleteConversation(conv.ID)
		writeErr(w, 503, s.chatUnavailableReason())
		return
	}
	busyKey := s.convBusyKey(conv.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		_ = pg.DeleteConversation(conv.ID)
		writeErr(w, 409, "该协议主控会话正在运行")
		return
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()

	_ = pg.UpdateProtocolCaseStatus(c.ID, "running", c.Mode, "")
	s.emitProtocolEvent(c.ID, "", "status", "Agent 分析开始", map[string]any{
		"agent_key": "protocol", "conversation_id": conv.ID,
	})

	prompt := buildProtocolAgentPrompt(c, s.protocolRunner.ToolsDir(), s.protocolRunner.Python(), s.protocolRunner.Tshark())
	if extra := strings.TrimSpace(req.Message); extra != "" {
		prompt += "\n\n操作者补充要求：\n" + extra
	}
	vulnEnabled, _ := protocol.ParseCaseConfig(c.Config)["vuln_enabled"].(bool)
	ua := userActivityWithAttachments(conv.AgentKey, prompt, nil)
	if vulnEnabled {
		ua.Summary = "Agent 驱动案例 P1-P9"
	} else {
		ua.Summary = "Agent 驱动案例 P1-P6"
	}
	ua.Detail = prompt
	if _, err := pg.AppendConvActivity(conv.ID, ua); err != nil {
		log.Printf("[protocol-agent] append user msg: %v", err)
	}
	_ = pg.TouchConversation(conv.ID)
	s.runConversationWithDone(conv, prompt, busyKey, func() { s.finishProtocolAgentRun(c.ID) })
	writeJSON(w, 202, map[string]any{"status": "accepted", "conversation_id": conv.ID})
}

// finishProtocolAgentRun runs when the main orchestration turn ends. If the six
// gates are not all green the case becomes paused so the UI no longer shows it
// as actively running and the operator can inspect/restart the conversation.
func (s *Server) finishProtocolAgentRun(caseID int64) {
	c, err := s.m.pg.GetProtocolCase(caseID)
	if err != nil || c == nil || c.Status != "running" {
		return
	}
	if s.protocolRunner.AllPhasesPass(caseID) && !s.hasRunningProtocolJobs(caseID) {
		_ = s.m.pg.UpdateProtocolCaseStatus(caseID, "done", c.Mode, "")
		return
	}
	pauseReason := "Agent 会话已结束，六阶段尚未全部通过"
	if s.protocolVulnEnabled(caseID) {
		pauseReason = "Agent 会话已结束，P1-P9 尚未全部通过"
	}
	_ = s.m.pg.UpdateProtocolCaseStatus(caseID, "paused", c.Mode, pauseReason)
	s.emitProtocolEvent(caseID, "", "status", "Agent 会话结束，案例暂停", map[string]any{
		"reason": "not all gates passed",
	})
}

func buildProtocolAgentPrompt(c *db.ProtocolCase, toolsDir, python, tshark string) string {
	cfg := string(c.Config)
	if len(cfg) > 2000 {
		cfg = cfg[:2000] + "…"
	}
	vulnEnabled, _ := protocol.ParseCaseConfig(c.Config)["vuln_enabled"].(bool)
	goal := "P1→P6"
	vulnRules := ""
	if vulnEnabled {
		goal = "P1→P9（P7-P9 为漏洞挖掘阶段）"
		vulnRules = `
V2 漏洞挖掘阶段（本案例已启用，P1-P6 通过后继续）：
12. P7 漏洞面测绘（依赖 P6）：用 tools 里的 device_profile.py（能力画像）→
    applicability.py（47 子模板三态适用性 + 生成假设）→ vuln_intel.py（本地
    CVE 语义层匹配），产出 device_profile / vuln_surface / vuln_hypotheses。
    设备画像缺口（unknown 能力）转 P7a 只读探测任务补全，不要臆造能力。
13. P8 验证与 Fuzz（依赖 P7）：**static 模式不执行 campaign**（无设备）——fuzz 类
    假设裁决 inconclusive/fuzz-deferred-live 并注明需 live 复跑，deterministic
    类按 P7 证据复核定终态，campaign 只写计划 JSON；live 模式才用
    campaign_runner.py 实际执行（deterministic 假设 --mode verify 确定性验证；
    fuzz 假设 --mode fuzz 灰盒执行）。read/write 类在授权内直接跑；
    destructive 类必须先由操作者审批（protocol_approvals），无批准 campaign
    会拒绝执行——如实停下等审批，不要绕过。假设状态更新为
    confirmed/falsified/enforced/inconclusive 并附证据。
14. P9 EXP 与报告（依赖 P8）：对 confirmed 假设跑 exp_gen.py 生成 EXP 脚本
    （replay/poc/chain），产出 05 号漏洞利用报告；write/destructive 类 EXP
    齐备才算门 I 通过。完成后总结补充：漏洞假设统计（confirmed/falsified/
    inconclusive）、EXP 资产、待审批项。`
	}
	return fmt.Sprintf(`你是工控系统脆弱性分析与利用智能体的主控 Agent。请驱动案例 #%d «%s» 完成 %s（协议逆向是基础阶段）。

案例输入：
- install_root: %s
- device_ip: %s
- authorization: %s
- mode: %s
- config: %s
- tools_dir: %s
- python: %s
- tshark: %s

执行规则：
1. 先调用 protocol_get_case(case_id=%d) 读取当前 phases / findings / reports，确认已有输入、
   哪些阶段已通过，避免重复运行。已通过 P1-P6 的续跑案例直接从未通过的阶段继续（例如
   只剩 P7-P9 时从 P7 开始，不要重跑 P1-P6）。
2. 阶段之间不是线性顺序，而是数据依赖。P1 资产侦察和 P2 流量获取通常可并行：P1 分析
   安装目录时，P2 可以解析已有 pcap，或后台启动抓包并提示操作者打开上位机软件与 PLC
   通信。P3 只依赖 pcap（流量分析：从流量推断功能码语义/帧格式/字段划分）；P4 只依赖
   P1 的通信 DLL/EXE（静态分析：从静态文件推断功能码语义/帧格式/字段划分），P3/P4
   可并行。P5 先对 P3/P4 结果做交叉佐证，再按授权动态验证或降级；P6 依赖 P1–P5 的
   结果。依赖已满足就可以并行。
3. 用 protocol_delegate_phase(case_id, phase="Pn", task="...", expected_output="...")
   异步启动阶段。该工具默认立即返回 job_id，不阻塞；同一轮或连续几轮启动所有可并行
   阶段。同一阶段同时只能有一个 job。
4. 用 protocol_wait_phases(case_id, phases=["P1","P2"], timeout_seconds=60) 做检查点：
   timeout_seconds=0 只查询，60–180 秒适合轮询，1800 秒适合等最后一批。返回 items +
   still_running；timed_out=true 只表示还有阶段在跑，不是失败。每个 item 含
   passed / gate / detail / counts / summary / next_hint。门由平台按 findings 判定。
5. 根据已完成项决策，不必等整批结束：某个 passed=true 就启动依赖它的下一阶段（例如
   P1 完成后启动 P4，P2 继续抓包，P6 通过后启动 P7）；passed=false 时只重试失败阶段，
   把 summary 与 next_hint 写进新的 task（补输入、换方法、换脚本），已完成阶段不要重跑。
   still_running 非空则先处理已完成项，之后继续 wait。同一阶段连续失败 2 次或
   needs_human 非空时停止，向操作者说明具体缺什么。
6. P2 按案例 mode 执行：
   - live：没有 pcap 时要求子 Agent 立即后台启动抓包（输出到工作目录 pcaps/）并等待，
     明确告诉操作者打开上位机软件、连接 PLC、执行至少 3 种操作并停留足够时间；不要让
     子 Agent 在本机搜索 pcap。仅当抓包不可用（tshark/网卡异常、操作者无法操作）时才
     请操作者上传 .pcap/.pcapng 或配置 config.golden_artifacts。
   - static：子 Agent 只解析案例已提供的 pcap，禁止启动抓包、禁止搜索本机 pcap；缺
     pcap 说明建案输入有误，报 fail 请操作者补齐。不要用假数据继续。
7. P5 先对 P3 流量结论与 P4 静态结论做交叉佐证（notes kind=code-reconciliation），再按
   mode 和 authorization 执行：live 按授权实际执行在线探针（write 允许写变量/参数、
   下载、启停，destructive/full 允许复位/破坏类），不得把 write/full 降级成纯只读；
   设备离线/不可达才写带原因的静态降级并继续 P6，设备在线但 identify/探针失败必须如实
   报 fail。static 不连接设备，完成佐证后写带原因（static 模式）的降级并继续 P6。
8. P6 文档必须消费 P5 的交叉佐证结果（冲突未裁决项标“待验证”），完成后总结：通信资产、
   帧格式、功能码数量、live 验证范围、四份文档，以及仍未验证/受阻的项。
9. 所有结论必须带证据等级（traffic > live > static > inferred）；不得把推断写成已确认。
   不要自己用 Bash/Python 代替子 Agent；需要细节时用 protocol_get_case。
10. 操作者要求停止某个阶段时，调用 protocol_cancel_phase(case_id, phase="Pn")；
    只取消该阶段，其它并行阶段和本会话继续。
11. 平台会按案例 authorization 在工具层拦截越权操作；子 Agent 被拒绝时应改用只读方案，
    或向你说明需要操作者提高授权。%s`,
		c.ID, c.Name, goal, c.InstallRoot, c.DeviceIP, c.Authorization, c.Mode, cfg, toolsDir, python, tshark, c.ID, vulnRules)
}

func (s *Server) protocolCaseFindings(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	f, err := pg.GetProtocolFindings(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, f)
}

func (s *Server) protocolCasePhases(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	phases, err := pg.ListProtocolPhases(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// Synthesize not_started rows for the case's active phase order (P1-P6,
	// plus P7-P9 when the case opted into V2) so the UI shows the full
	// pipeline before anything has run.
	seen := map[string]bool{}
	for _, p := range phases {
		seen[p.Phase] = true
	}
	for _, ph := range s.activePhaseOrder(id) {
		if seen[ph] {
			continue
		}
		phases = append(phases, &db.ProtocolPhase{
			CaseID: id, Phase: ph, Gate: protocolPhaseGate(ph), Status: "not_started",
		})
	}
	writeJSON(w, 200, map[string]any{"items": phases})
}

func (s *Server) protocolCaseReports(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	reports, err := pg.ListProtocolReports(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": reports})
}

func (s *Server) protocolCaseMetrics(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	phases, err := pg.ProtocolPhaseMetrics(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	usage, err := pg.ProtocolAgentUsage(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"phases": phases, "agents": usage})
}

func (s *Server) protocolListPhaseJobs(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	items, running := s.protocolPhaseSnapshots(id, nil)
	// Keep this endpoint about jobs; phase rows without a job are not job history.
	jobs := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if _, ok := it["job_id"]; ok {
			jobs = append(jobs, it)
		}
	}
	writeJSON(w, 200, map[string]any{"items": jobs, "running": running})
}

func (s *Server) protocolCancelPhaseJob(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	phase := strings.ToUpper(strings.TrimSpace(r.PathValue("phase")))
	if phaseAgentKey(phase) == "" {
		writeErr(w, 400, "phase 必须是 P1..P6")
		return
	}
	if err := s.cancelProtocolPhaseJob(id, phase); err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	s.emitProtocolEvent(id, phase, "status", "阶段取消请求已发送", nil)
	writeJSON(w, 202, map[string]any{"ok": true, "case_id": id, "phase": phase, "status": "cancelling"})
}

func (s *Server) protocolReportVersions(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	doc := strings.TrimSpace(r.PathValue("doc"))
	if doc == "" {
		writeErr(w, 400, "doc required")
		return
	}
	versions, err := pg.ListProtocolReportVersions(id, doc)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": versions})
}

func (s *Server) protocolApproveReport(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	doc := strings.TrimSpace(r.PathValue("doc"))
	if doc == "" {
		writeErr(w, 400, "doc required")
		return
	}
	p, _ := principalFrom(r.Context())
	rep, err := pg.ApproveProtocolReport(id, doc, p.Username)
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.emitProtocolEvent(id, "P6", "status", "报告已批准: "+doc, map[string]any{"doc_type": doc, "approved_by": p.Username, "version": rep.Version})
	writeJSON(w, 200, rep)
}

func (s *Server) protocolExportReports(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	reports, err := pg.ListProtocolReports(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if len(reports) == 0 {
		writeErr(w, 404, "暂无报告")
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	seen := map[string]int{}
	for _, rep := range reports {
		name := strings.TrimSpace(rep.DocType)
		if name == "" {
			name = rep.Title
		}
		name = sanitizeReportFilename(name)
		if name == "" {
			name = "report"
		}
		if !strings.HasSuffix(strings.ToLower(name), ".md") {
			name += ".md"
		}
		if n := seen[name]; n > 0 {
			name = strings.TrimSuffix(name, ".md") + "-" + strconv.Itoa(n+1) + ".md"
		}
		seen[name]++
		f, err := zw.Create(name)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if _, err := f.Write([]byte(rep.Content)); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if err := zw.Close(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="case-%d-reports.zip"`, id))
	w.WriteHeader(200)
	_, _ = w.Write(buf.Bytes())
}

func sanitizeReportFilename(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("\\", "_", "/", "_", ":", "_", "\r", "", "\n", "", "\t", " ").Replace(s)
	if len([]rune(s)) > 80 {
		s = string([]rune(s)[:80])
	}
	return s
}

func (s *Server) protocolCaseEvents(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := pg.ListProtocolEvents(id, after, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) protocolCaseEventStream(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	if le := r.Header.Get("Last-Event-ID"); le != "" {
		if n, err := strconv.ParseInt(le, 10, 64); err == nil {
			since = n
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, unsub := s.protocolHub.subscribe(id)
	defer unsub()

	send := func(e db.ProtocolEvent) {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "id: %d\ndata: %s\n\n", e.ID, b)
		flusher.Flush()
	}
	const batch = 500
	for {
		items, err := pg.ListProtocolEvents(id, since, batch)
		if err != nil {
			return
		}
		for _, e := range items {
			send(*e)
		}
		if len(items) < batch {
			break
		}
		since = items[len(items)-1].ID
	}
	flusher.Flush()

	ctx := r.Context()
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if e.ID <= since {
				continue
			}
			since = e.ID
			send(e)
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) protocolUploadPcap(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil || c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	if s.protocolRunner == nil {
		writeErr(w, 503, "protocol runner unavailable")
		return
	}
	if err := r.ParseMultipartForm(256 << 20); err != nil {
		writeErr(w, 400, "multipart: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "file required: "+err.Error())
		return
	}
	defer file.Close()
	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		writeErr(w, 400, "invalid filename")
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" {
		writeErr(w, 400, "only .pcap / .pcapng / .cap are accepted")
		return
	}
	if err := s.checkProtocolCaseQuota(c, header.Size); err != nil {
		writeErr(w, 413, err.Error())
		return
	}
	dir := filepath.Join(s.protocolRunner.Workdir(c), "pcaps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	dst := filepath.Join(dir, name)
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		writeErr(w, 500, err.Error())
		return
	}
	if err := out.Close(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.emitProtocolEvent(id, "P2", "artifact", "已上传 pcap: "+name, map[string]any{"path": dst})
	writeJSON(w, 201, map[string]any{"ok": true, "name": name, "path": dst})
}

func (s *Server) protocolUploadArtifact(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil || c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	if err := r.ParseMultipartForm(512 << 20); err != nil {
		writeErr(w, 400, "multipart: "+err.Error())
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "file required: "+err.Error())
		return
	}
	defer file.Close()
	name := filepath.Base(header.Filename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		writeErr(w, 400, "invalid filename")
		return
	}
	if err := s.checkProtocolCaseQuota(c, header.Size); err != nil {
		writeErr(w, 413, err.Error())
		return
	}
	ext := strings.ToLower(filepath.Ext(name))
	dirName := "artifacts"
	if ext == ".pcap" || ext == ".pcapng" || ext == ".cap" {
		// Gate B and the traffic agents read <workdir>/pcaps; uploaded captures
		// belong there, not in the generic artifacts directory.
		dirName = "pcaps"
	}
	dir := filepath.Join(s.protocolRunner.Workdir(c), dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	dst := filepath.Join(dir, name)
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		writeErr(w, 500, err.Error())
		return
	}
	if err := out.Close(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// A DLL uploaded here becomes the P4 starting point without extra wiring.
	if strings.EqualFold(filepath.Ext(name), ".dll") {
		var cfg map[string]any
		_ = json.Unmarshal(c.Config, &cfg)
		if cfg == nil {
			cfg = map[string]any{}
		}
		gold, _ := cfg["golden_artifacts"].(map[string]any)
		if gold == nil {
			gold = map[string]any{}
		}
		gold["comm_dll"] = dst
		cfg["golden_artifacts"] = gold
		if b, err := json.Marshal(cfg); err == nil {
			_ = pg.UpdateProtocolCaseConfig(id, b)
		}
	}
	s.emitProtocolEvent(id, "", "artifact", "已上传工件: "+name, map[string]any{"path": dst})
	writeJSON(w, 201, map[string]any{"ok": true, "name": name, "path": dst})
}

// protocolExploitScript returns the text content of a workdir file (EXP 脚本)
// for the frontend viewer. The path must resolve inside the case workdir;
// traversal outside it and oversized files are rejected.
func (s *Server) protocolExploitScript(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil || c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	rel := strings.TrimSpace(r.URL.Query().Get("path"))
	if rel == "" {
		writeErr(w, 400, "path required")
		return
	}
	workdir := s.protocolRunner.Workdir(c)
	absWd, err := filepath.Abs(workdir)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// P9 registers the absolute script path (it generates into the phase-run
	// dir <workdir>/.runs/...); the UI may also pass a workdir-relative path.
	var absFull string
	if filepath.IsAbs(rel) {
		absFull = filepath.Clean(rel)
	} else {
		absFull, err = filepath.Abs(filepath.Join(absWd, filepath.FromSlash(rel)))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	// A retried phase can register a path inside a run dir that later timed
	// out; the same script usually exists in a sibling run dir (or the
	// canonical exploits/). Fall back to basename lookup, still workdir-bound.
	if !fileExists(absFull) {
		base := filepath.Base(filepath.FromSlash(rel))
		if base != "" && base != "." && base != string(filepath.Separator) {
			for _, pat := range []string{
				filepath.Join(absWd, "exploits", base),
				filepath.Join(absWd, ".runs", "*", "exploits", base),
				filepath.Join(absWd, ".runs", "*", "*", "exploits", base),
			} {
				if hits, _ := filepath.Glob(pat); len(hits) > 0 {
					absFull = hits[0]
					break
				}
			}
		}
	}
	if absFull != absWd && !strings.HasPrefix(absFull, absWd+string(filepath.Separator)) {
		writeErr(w, 400, "path escapes case workdir")
		return
	}
	st, err := os.Stat(absFull)
	if err != nil || st.IsDir() {
		writeErr(w, 404, "file not found")
		return
	}
	if st.Size() > 256<<10 {
		writeErr(w, 413, "file too large")
		return
	}
	data, err := os.ReadFile(absFull)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"path": rel, "name": filepath.Base(absFull),
		"size": st.Size(), "content": string(data),
	})
}

func (s *Server) protocolListFindings(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := pg.ListProtocolFunctionCodesAll(
		r.URL.Query().Get("q"), r.URL.Query().Get("grade"), r.URL.Query().Get("layer"), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) protocolStats(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	st, err := pg.ProtocolStats()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// protocolVulnDashboard aggregates the cross-case vulnerability posture for the
// dashboard page (hypotheses, EXP, campaigns, approval queue, knowledge base,
// recent events and a per-case P7-P9 table).
func (s *Server) protocolVulnDashboard(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	d, err := pg.VulnDashboard()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, d)
}

// protocolKnowledge browses the vulnerability knowledge base (CVE priors from
// plc-intel/icsvuln plus ICSsploit payloads). Filters: source/vclass/vendor/q.
func (s *Server) protocolKnowledge(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	vclass, _ := strconv.Atoi(q.Get("vclass"))
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	items, total, bySource, err := pg.VulnKnowledgeList(db.VulnKnowledgeFilter{
		Source:   strings.TrimSpace(q.Get("source")),
		Vclass:   vclass,
		Vendor:   strings.TrimSpace(q.Get("vendor")),
		Query:    strings.TrimSpace(q.Get("q")),
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"items": items, "total": total, "by_source": bySource,
		"page": page, "page_size": pageSize,
	})
}

func (s *Server) protocolToolConfig(w http.ResponseWriter, r *http.Request) {
	// The paths are read-only here; change them in config.json / env and restart.
	// The check endpoint proves the interpreter and tool files are reachable.
	writeJSON(w, 200, map[string]any{
		"tools_dir": s.protocolToolsDir(),
		"python":    s.protocolPython(),
		"tshark":    s.protocolTshark(),
	})
}

func (s *Server) protocolCheckTools(w http.ResponseWriter, r *http.Request) {
	dir := s.protocolToolsDir()
	required := []string{
		"recon_pe.py", "capture.py", "frame_hypothesis.py", "field_map.py",
		"extract_codes.py", "client_harness.py", "dissector_gen.py", "findings.py",
		"binary_survey.py", "analyzer_bundle.py", "analyzer_cache.py", "session_model.py", "probe_dsl.py",
		"elf_analyze.py", "dotnet_analyze.py", "ghidra_analyze.py",
		"ida_analyze.py", "traffic_insights.py", "GhidraExport.java", "ida_export.py",
	}
	missing := make([]string, 0)
	for _, f := range required {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			missing = append(missing, f)
		}
	}
	python, tshark := s.protocolPython(), s.protocolTshark()
	if !executableExists(python) {
		missing = append(missing, "python")
	}
	if !executableExists(tshark) {
		missing = append(missing, "tshark")
	}
	if executableExists(python) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := exec.CommandContext(ctx, python, "-c", "import pefile, capstone").Run()
		cancel()
		if err != nil {
			missing = append(missing, "python:pefile/capstone")
		}
	}
	writeJSON(w, 200, map[string]any{
		"tools_dir": dir,
		"python":    python,
		"tshark":    tshark,
		"missing":   missing,
		"ready":     len(missing) == 0,
		"optional":  s.protocolOptionalTools(dir),
	})
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func executableExists(name string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	if p, err := exec.LookPath(name); err == nil && p != "" {
		return true
	}
	st, err := os.Stat(name)
	return err == nil && !st.IsDir()
}

func (s *Server) protocolOptionalTools(toolsDir string) []map[string]any {
	type spec struct {
		name  string
		paths []string
		hint  string
	}
	home := strings.TrimSpace(os.Getenv("GHIDRA_HOME"))
	ghidraPaths := []string{"analyzeHeadless", "analyzeHeadless.bat"}
	if home != "" {
		ghidraPaths = append(ghidraPaths, filepath.Join(home, "support", "analyzeHeadless.bat"), filepath.Join(home, "support", "analyzeHeadless"))
	}
	bundle := config.AnalyzerBundleDir()
	if bundle != "" {
		ghidraPaths = append(ghidraPaths, filepath.Join(bundle, "ghidra", "ghidra_12.2_PUBLIC", "support", "analyzeHeadless.bat"))
		if matches, _ := filepath.Glob(filepath.Join(bundle, "ghidra", "*", "support", "analyzeHeadless.bat")); len(matches) > 0 {
			ghidraPaths = append(ghidraPaths, matches[0])
		}
	}
	specs := []spec{
		{"ilspycmd", func() []string {
			paths := []string{filepath.Join(toolsDir, "bin", "ilspycmd.exe"), filepath.Join(toolsDir, "bin", "ilspycmd")}
			if bundle != "" {
				paths = append(paths, filepath.Join(bundle, "ilspycmd", "ilspycmd.exe"))
			}
			return paths
		}(), "dotnet tool install --tool-path tools/bin ilspycmd"},
		{"Ghidra analyzeHeadless", ghidraPaths, "set GHIDRA_HOME or run tools/install-analyzers.ps1 -DownloadGhidra"},
		{"IDA idat64/idat", nil, "install IDA (license) and add its bin directory to PATH"},
		{"readelf", nil, "binutils"},
		{"objdump", nil, "binutils"},
		{"rabin2", nil, "radare2"},
		{"r2", nil, "radare2"},
	}
	out := make([]map[string]any, 0, len(specs))
	for _, sp := range specs {
		path := ""
		if len(sp.paths) > 0 {
			for _, p := range sp.paths {
				if executableExists(p) {
					path = p
					break
				}
			}
		}
		if path == "" {
			names := []string{sp.name}
			if strings.Contains(sp.name, " ") {
				names = []string{strings.Fields(sp.name)[0], strings.Fields(sp.name)[0] + ".exe"}
			}
			for _, n := range names {
				if p, err := exec.LookPath(n); err == nil {
					path = p
					break
				}
			}
		}
		if strings.Contains(sp.name, "IDA") {
			for _, n := range []string{"idat64", "idat", "idat64.exe", "idat.exe"} {
				if p, err := exec.LookPath(n); err == nil {
					path = p
					break
				}
			}
		}
		out = append(out, map[string]any{
			"name": sp.name, "path": path, "ready": path != "", "hint": sp.hint,
		})
	}
	return out
}

func (s *Server) protocolToolsDir() string {
	if s.protocolRunner == nil {
		return ""
	}
	return s.protocolRunner.ToolsDir()
}

func (s *Server) protocolPython() string {
	if s.protocolRunner == nil {
		return ""
	}
	return s.protocolRunner.Python()
}

func (s *Server) protocolTshark() string {
	if s.protocolRunner == nil {
		return ""
	}
	return s.protocolRunner.Tshark()
}
