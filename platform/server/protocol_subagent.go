package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
	"github.com/Autumn-27/protocol-agent/llmrec"
	"github.com/Autumn-27/protocol-agent/protocol"
)

// phaseAgentKey maps P1..P9 to the built-in sub-agent that owns that phase.
func phaseAgentKey(phase string) string {
	switch strings.ToUpper(strings.TrimSpace(phase)) {
	case "P1":
		return "protocol_p1"
	case "P2":
		return "protocol_p2"
	case "P3":
		return "protocol_p3"
	case "P4":
		return "protocol_p4"
	case "P5":
		return "protocol_p5"
	case "P6":
		return "protocol_p6"
	case "P7":
		return "protocol_p7"
	case "P8":
		return "protocol_p8"
	case "P9":
		return "protocol_p9"
	}
	return ""
}

// toolProtocolDelegatePhase starts one phase sub-agent. It is asynchronous by
// default: the call returns immediately with a job id so the main agent can
// launch independent phases together and wait for them later.
func (s *Server) toolProtocolDelegatePhase() actool.CoreTool {
	return wrTool("protocol_delegate_phase",
		"异步启动 P1..P6 中的一个阶段子 Agent，立即返回 job_id。子 Agent 自行选择 Bash/Python/文件工具，完成后用 protocol_wait_phases 获取门判定与摘要。可连续启动多个无依赖阶段；同一阶段同时只能跑一个。",
		objSchema(map[string]any{
			"case_id":         idParam("协议案例 id"),
			"phase":           strParam("P1|P2|P3|P4|P5|P6"),
			"task":            strParam("下发给子 Agent 的具体任务：目标、已知线索、要求它重点尝试什么"),
			"expected_output": strParam("期望输出/验收说明（可选）"),
			"wait":            map[string]any{"type": "boolean", "description": "true=阻塞到该阶段结束（兼容旧用法）；默认 false=立即返回 job_id"},
		}, "case_id", "phase", "task"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				CaseID         json.RawMessage `json:"case_id"`
				Phase          string          `json:"phase"`
				Task           string          `json:"task"`
				ExpectedOutput string          `json:"expected_output"`
				Wait           *bool           `json:"wait"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID := parseProfileID(in.CaseID)
			phase := strings.ToUpper(strings.TrimSpace(in.Phase))
			if caseID <= 0 || phaseAgentKey(phase) == "" {
				return actool.Errorf("case_id/phase 必填且 phase 必须是 P1..P6"), nil
			}
			if s.protocolRunner == nil {
				return actool.Errorf("protocol runner 不可用"), nil
			}
			if in.Wait != nil && *in.Wait {
				res, err := s.runProtocolSubagent(ctx, caseID, phase, in.Task, in.ExpectedOutput)
				if err != nil {
					return jsonResult(map[string]any{
						"case_id": caseID, "phase": phase, "passed": false,
						"error": err.Error(), "next_hint": "检查阶段子 Agent 的 LLM 配置/日志后重试",
					})
				}
				return jsonResult(res)
			}
			job, err := s.startProtocolPhaseJob(ctx, caseID, phase, in.Task, in.ExpectedOutput)
			if err != nil {
				return jsonResult(map[string]any{
					"case_id": caseID, "phase": phase, "accepted": false, "error": err.Error(),
				})
			}
			out := job.snapshot()
			out["accepted"] = true
			out["next_hint"] = "任务已异步启动；继续启动其它无依赖阶段，或调用 protocol_wait_phases(case_id, phases=[...], timeout_seconds=...)。"
			return jsonResult(out)
		})
}

// toolProtocolCancelPhase cancels one running phase job without stopping the
// other parallel phases or the main orchestration turn.
func (s *Server) toolProtocolCancelPhase() actool.CoreTool {
	return wrTool("protocol_cancel_phase",
		"取消一个正在运行的阶段子 Agent；其它并行阶段和主 Agent 会话不受影响。",
		objSchema(map[string]any{
			"case_id": idParam("协议案例 id"),
			"phase":   strParam("P1|P2|P3|P4|P5|P6"),
		}, "case_id", "phase"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				CaseID json.RawMessage `json:"case_id"`
				Phase  string          `json:"phase"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID := parseProfileID(in.CaseID)
			phase := strings.ToUpper(strings.TrimSpace(in.Phase))
			if caseID <= 0 || phaseAgentKey(phase) == "" {
				return actool.Errorf("case_id/phase 必填"), nil
			}
			if err := s.cancelProtocolPhaseJob(caseID, phase); err != nil {
				return jsonResult(map[string]any{"cancelled": false, "error": err.Error()})
			}
			return jsonResult(map[string]any{"cancelled": true, "case_id": caseID, "phase": phase})
		})
}

// toolProtocolWaitPhases waits for one or more phase jobs, or returns their
// current state when timeout_seconds=0. Phases without a running job fall back
// to their persisted phase rows, so a completed phase can still be inspected.
func (s *Server) toolProtocolWaitPhases() actool.CoreTool {
	return wrTool("protocol_wait_phases",
		"等待阶段任务并返回 passed/gate/counts/summary/ready_phases；timeout_seconds=0 只查询。默认多阶段等待中任一阶段结束就立即返回全部阶段当前快照（return_on_any=false 可改为等全部结束或超时），用于“谁先完成先启动谁的下游”。timed_out=true 只表示仍有阶段在跑，不是失败。阶段没有已启动的 job 时返回数据库中的阶段状态。",
		objSchema(map[string]any{
			"case_id":         idParam("协议案例 id"),
			"phases":          map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "P1..P6 子集；省略=当前所有 job"},
			"timeout_seconds": map[string]any{"type": "integer", "description": "最长等待秒数，默认 1800；0=立即返回"},
			"return_on_any":   map[string]any{"type": "boolean", "description": "默认多阶段任一完成即返回；显式 false=等全部结束或超时"},
		}, "case_id"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			var in struct {
				CaseID         json.RawMessage `json:"case_id"`
				Phases         []string        `json:"phases"`
				TimeoutSeconds *int            `json:"timeout_seconds"`
				ReturnOnAny    *bool           `json:"return_on_any"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID := parseProfileID(in.CaseID)
			if caseID <= 0 {
				return actool.Errorf("case_id 必填"), nil
			}
			phases := normalizeProtocolPhases(in.Phases)
			timeout := 1800
			if in.TimeoutSeconds != nil {
				timeout = *in.TimeoutSeconds
			}
			if timeout < 0 {
				timeout = 0
			}
			if timeout > 7200 {
				timeout = 7200
			}
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			var initialRunning []string
			returnOnAny := false
			for first := true; ; first = false {
				items, running := s.protocolPhaseSnapshots(caseID, phases)
				if first {
					initialRunning = append([]string(nil), running...)
					returnOnAny = effectiveReturnOnAny(len(initialRunning), in.ReturnOnAny)
				}
				anyFinished := returnOnAny && anyPhaseFinished(initialRunning, running)
				if timeout == 0 || len(running) == 0 || anyFinished || time.Now().After(deadline) {
					allPassed := len(items) > 0
					for _, it := range items {
						if it["passed"] != true {
							allPassed = false
							break
						}
					}
					allItems, _ := s.protocolPhaseSnapshots(caseID, nil)
					waitMode := "all"
					if returnOnAny {
						waitMode = "any"
					}
					return jsonResult(map[string]any{
						"case_id":         caseID,
						"items":           items,
						"still_running":   running,
						"timed_out":       len(running) > 0 && time.Now().After(deadline),
						"all_passed":      allPassed,
						"returned_on_any": anyFinished,
						"wait_mode":       waitMode,
						"ready_phases":    protocolReadyPhases(allItems, s.protocolVulnEnabled(caseID)),
					})
				}
				select {
				case <-ctx.Done():
					return actool.Errorf(fmt.Sprintf("等待被取消: %v", ctx.Err())), nil
				case <-time.After(500 * time.Millisecond):
				}
			}
		})
}

// anyPhaseFinished reports whether any phase that was running at the start of a
// return_on_any wait has since stopped running (completed, failed or partial).
func anyPhaseFinished(initialRunning, currentRunning []string) bool {
	if len(initialRunning) == 0 {
		return false
	}
	now := make(map[string]bool, len(currentRunning))
	for _, p := range currentRunning {
		now[p] = true
	}
	for _, p := range initialRunning {
		if !now[p] {
			return true
		}
	}
	return false
}

// effectiveReturnOnAny makes multi-phase waits default to "return on first
// completion" so a slow phase cannot block downstream work unlocked by a fast
// one. An explicit value from the caller always wins.
func effectiveReturnOnAny(initialRunning int, explicit *bool) bool {
	if explicit != nil {
		return *explicit
	}
	return initialRunning > 1
}

var protocolPhasePrereqs = map[string][]string{
	"P1": nil,
	"P2": nil,
	"P3": {"P2"},
	"P4": {"P1"},
	"P5": {"P3", "P4"},
	"P6": {"P5"},
	// V2: P7 漏洞面测绘依赖完整协议逆向结论；P8 验证/Fuzz 依赖测绘出的假设；
	// P9 EXP/报告依赖验证终态。
	"P7": {"P6"},
	"P8": {"P7"},
	"P9": {"P8"},
}

// protocolVulnEnabled reports whether the case opted into the V2 vulnerability
// phases (P7-P9).
func (s *Server) protocolVulnEnabled(caseID int64) bool {
	if s.m == nil || s.m.pg == nil {
		return false
	}
	c, err := s.m.pg.GetProtocolCase(caseID)
	if err != nil || c == nil {
		return false
	}
	enabled, _ := protocol.ParseCaseConfig(c.Config)["vuln_enabled"].(bool)
	return enabled
}

// activePhaseOrder returns the case's full phase order for handlers that only
// hold the case id (P1-P6, plus P7-P9 when opted in).
func (s *Server) activePhaseOrder(caseID int64) []string {
	if s.protocolRunner == nil {
		return []string{"P1", "P2", "P3", "P4", "P5", "P6"}
	}
	return s.protocolRunner.ActivePhaseOrder(caseID)
}

// protocolReadyPhases derives which phases are unlocked right now: every
// prerequisite phase has passed, and the phase itself is neither passed nor
// running (so retries of failed phases also show up as ready). V2 phases are
// only offered when the case opted in.
func protocolReadyPhases(items []map[string]any, vulnEnabled bool) []string {
	passed := map[string]bool{}
	running := map[string]bool{}
	for _, it := range items {
		phase := strings.ToUpper(snapshotString(it, "phase"))
		if phase == "" {
			continue
		}
		if b, ok := it["passed"].(bool); ok && b {
			passed[phase] = true
		}
		switch strings.ToLower(snapshotString(it, "status")) {
		case "running", "cancelling":
			running[phase] = true
		}
	}
	order := []string{"P1", "P2", "P3", "P4", "P5", "P6"}
	if vulnEnabled {
		order = append(order, "P7", "P8", "P9")
	}
	ready := make([]string, 0, len(protocolPhasePrereqs))
	for _, phase := range order {
		if passed[phase] || running[phase] {
			continue
		}
		ok := true
		for _, req := range protocolPhasePrereqs[phase] {
			if !passed[req] {
				ok = false
				break
			}
		}
		if ok {
			ready = append(ready, phase)
		}
	}
	return ready
}

func snapshotString(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func normalizeProtocolPhases(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.ToUpper(strings.TrimSpace(p))
		if phaseAgentKey(p) == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func (s *Server) protocolPhaseSnapshots(caseID int64, phases []string) ([]map[string]any, []string) {
	jobs := s.protocolJobsFor(caseID, phases)
	byPhase := map[string]map[string]any{}
	running := make([]string, 0)
	for _, j := range jobs {
		snap := j.snapshot()
		byPhase[j.Phase] = snap
		if snap["status"] == "running" || snap["status"] == "cancelling" {
			running = append(running, j.Phase)
		}
	}
	if len(byPhase) == 0 && s.m != nil && s.m.pg != nil {
		// After a restart the in-memory registry is empty; expose the last
		// persisted job per phase instead of pretending nothing ran.
		if rows, err := s.m.pg.ListLatestProtocolPhaseJobs(caseID, phases); err == nil {
			for _, r := range rows {
				it := map[string]any{
					"job_id": r.JobID, "case_id": r.CaseID, "phase": r.Phase,
					"agent_key": r.AgentKey, "status": r.Status,
					"started_at": r.StartedAt.Format(time.RFC3339),
					"passed":     false,
				}
				if r.FinishedAt != nil {
					it["finished_at"] = r.FinishedAt.Format(time.RFC3339)
				}
				var res map[string]any
				if len(r.Result) > 0 && json.Unmarshal(r.Result, &res) == nil {
					for k, v := range res {
						if _, exists := it[k]; !exists {
							it[k] = v
						}
					}
				}
				if r.Error != "" {
					it["error"] = r.Error
				}
				byPhase[r.Phase] = it
			}
		}
	}
	check := phases
	if len(check) == 0 {
		// Default view follows the case's active phase set: pure reverse cases
		// keep P1-P6; cases that opted into V2 also see P7-P9.
		check = []string{"P1", "P2", "P3", "P4", "P5", "P6"}
		if s.protocolVulnEnabled(caseID) {
			check = append(check, "P7", "P8", "P9")
		}
	}
	rows := map[string]*db.ProtocolPhase{}
	if s.m.pg != nil {
		if list, err := s.m.pg.ListProtocolPhases(caseID); err == nil {
			for _, p := range list {
				rows[p.Phase] = p
			}
		}
	}
	items := make([]map[string]any, 0, len(check))
	for _, p := range check {
		if snap := byPhase[p]; snap != nil {
			items = append(items, snap)
			continue
		}
		it := map[string]any{"phase": p, "status": "not_started", "passed": false}
		if ph := rows[p]; ph != nil {
			it["status"] = ph.Status
			it["gate"] = ph.Gate
			it["detail"] = ph.Detail
			it["passed"] = ph.Status == "pass"
		}
		items = append(items, it)
	}
	return items, running
}

// toolProtocolReportPhase lets a phase sub-agent finish its delegation row with
// a structured verdict. The main agent still applies the deterministic gate.
func (s *Server) toolProtocolReportPhase() actool.CoreTool {
	return wrTool("protocol_report_phase",
		"阶段子 Agent 完成工作时调用：写入本次委派的结论、证据与产物路径。主 Agent 会据此与确定性门判定对照。",
		objSchema(map[string]any{
			"run_id":    idParam("protocol_delegate_phase 返回/提示中给出的 subagent run id"),
			"status":    strParam("pass|partial|fail"),
			"summary":   strParam("一句话结论 + 关键证据/未完成项"),
			"evidence":  map[string]any{"type": "object", "description": "结构化证据（计数、路径、命令摘要等）"},
			"artifacts": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "产物文件路径列表"},
		}, "run_id", "status", "summary"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				RunID     json.RawMessage `json:"run_id"`
				Status    string          `json:"status"`
				Summary   string          `json:"summary"`
				Evidence  json.RawMessage `json:"evidence"`
				Artifacts json.RawMessage `json:"artifacts"`
			}
			_ = json.Unmarshal(raw, &in)
			id := parseProfileID(in.RunID)
			if id <= 0 || strings.TrimSpace(in.Status) == "" {
				return actool.Errorf("run_id/status 必填"), nil
			}
			if err := pg.FinishProtocolSubagentRun(id, strings.TrimSpace(in.Status), in.Summary, in.Evidence, in.Artifacts); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			r, _ := pg.GetProtocolSubagentRun(id)
			return jsonResult(r)
		})
}

// toolProtocolSyncFindings persists the case's findings.json into the normalized
// tables. Sub-agents call it after editing the file; the parent also syncs after
// the run as a safety net.
func (s *Server) toolProtocolSyncFindings() actool.CoreTool {
	return wrTool("protocol_sync_findings",
		"把本阶段隔离的 findings 文件合并回案例 canonical findings.json 并同步数据库。并行子 Agent 必须传 path（prompt 里的 findings_path）与 phase；不传 path 时只同步 canonical 文件。",
		objSchema(map[string]any{
			"case_id": idParam("协议案例 id"),
			"path":    strParam("本阶段 findings 文件路径（prompt 中的 findings_path；可选）"),
			"phase":   strParam("P1|P2|P3|P4|P5|P6（传 path 时必填）"),
		}, "case_id"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				CaseID json.RawMessage `json:"case_id"`
				Path   string          `json:"path"`
				Phase  string          `json:"phase"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID := parseProfileID(in.CaseID)
			phase := strings.ToUpper(strings.TrimSpace(in.Phase))
			if caseID <= 0 {
				return actool.Errorf("case_id 必填"), nil
			}
			c, err := pg.GetProtocolCase(caseID)
			if err != nil || c == nil {
				return actool.Errorf("案例不存在"), nil
			}
			workdir := s.protocolRunner.Workdir(c)
			if p := strings.TrimSpace(in.Path); p != "" {
				if phaseAgentKey(phase) == "" {
					return actool.Errorf("传 path 时必须同时传 phase（P1..P6）"), nil
				}
				if !filepath.IsAbs(p) {
					p = filepath.Join(workdir, p)
				}
				abs, err := filepath.Abs(p)
				if err != nil {
					return actool.Errorf("findings 路径无效: " + err.Error()), nil
				}
				wdAbs, wdErr := filepath.Abs(workdir)
				if wdErr != nil {
					return actool.Errorf("案例工作目录无效: " + wdErr.Error()), nil
				}
				rel, relErr := filepath.Rel(wdAbs, abs)
				if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
					return actool.Errorf("findings_path 必须位于案例工作目录内"), nil
				}
				if err := mergeProtocolRunFindings(pg, caseID, workdir, abs, phase); err != nil {
					return actool.Errorf("合并 findings 失败: " + err.Error()), nil
				}
			} else if err := syncProtocolFindingsFile(pg, caseID, workdir); err != nil {
				return actool.Errorf("同步 findings 失败: " + err.Error()), nil
			}
			f, _ := pg.GetProtocolFindings(caseID)
			return jsonResult(map[string]any{
				"ok": true,
				"counts": map[string]int{
					"assets": len(f.Assets), "frames": len(f.Frames),
					"field_maps": len(f.Fields), "codes": len(f.Codes),
					"probes": len(f.Probes),
				},
			})
		})
}

// runProtocolSubagent builds a phase-specific agent session in the case workdir,
// streams its steps into the parent conversation, then syncs findings.json and
// evaluates the gate.
func (s *Server) runProtocolSubagent(ctx context.Context, caseID int64, phase, task, expected string) (map[string]any, error) {
	pg := s.m.pg
	if pg == nil {
		return nil, fmt.Errorf("PostgreSQL 未连接")
	}
	if err := s.requireProtocolPhasePrereqs(caseID, phase); err != nil {
		return nil, err
	}
	c, err := pg.GetProtocolCase(caseID)
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("案例不存在")
	}
	agentKey := phaseAgentKey(phase)
	a, err := pg.GetAgentByKey(agentKey)
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, fmt.Errorf("阶段子 Agent %s 未初始化", agentKey)
	}

	// Resolve the provider exactly like chat: agent binding first, then global.
	var ca *agent.ChatAgent
	if id := s.effectiveProfileForAgent(agentKey, nil); id != nil {
		ca = s.chatAgentForProfile(*id)
	} else {
		ca = s.chatAgentRef()
	}
	if ca == nil {
		return nil, fmt.Errorf("%s", s.chatUnavailableReason())
	}

	workdir := s.protocolRunner.Workdir(c)
	ensureProtocolFindingsFile(workdir)
	runID := fmt.Sprintf("proto-%d-%s-%d", caseID, strings.ToLower(phase), time.Now().UnixNano())
	run, err := pg.CreateProtocolSubagentRun(caseID, phase, agentKey, runID)
	if err != nil {
		return nil, err
	}
	runFindings, err := prepareProtocolRunFindings(workdir, runID)
	if err != nil {
		return nil, err
	}
	initialFindings, _ := os.ReadFile(runFindings)

	_ = pg.UpdateProtocolCaseStatus(caseID, "running", c.Mode, "")
	_ = pg.UpsertProtocolPhase(caseID, phase, protocolPhaseGate(phase), "running", "子 Agent 正在执行", nil)
	s.emitProtocolEvent(caseID, phase, "phase", fmt.Sprintf("%s 子 Agent 开始（%s）", phase, agentKey), map[string]any{
		"agent_key": agentKey, "subagent_run_id": run.ID,
	})

	analyzerBlock := ""
	if phase == "P4" {
		analyzerBlock = s.protocolAnalyzerInfo().promptBlock()
	}
	prompt := buildProtocolSubagentPrompt(c, phase, task, expected, run.ID, workdir, runFindings,
		s.protocolRunner.ToolsDir(), s.protocolRunner.Python(), s.protocolRunner.Tshark(), s.protocolRunner.Spec(), analyzerBlock)
	convID := convIDFromContext(ctx)
	emit := func(r db.Activity) {
		if convID > 0 {
			_, _ = pg.AppendConvActivity(convID, r)
		}
	}

	budget := time.Duration(a.RunSecs) * time.Second
	if a.MaxTurns > 0 {
		prompt += fmt.Sprintf(`

本阶段预算：墙钟约 %d 秒，最多 %d 个工具回合。接近上限时先调用 protocol_sync_findings 保存成果，再用 protocol_report_phase 报 partial，不要空转到被硬超时。`, a.RunSecs, a.MaxTurns)
	} else {
		prompt += fmt.Sprintf(`

本阶段预算：墙钟约 %d 秒。接近上限时先调用 protocol_sync_findings 保存成果，再用 protocol_report_phase 报 partial，不要空转到被硬超时。`, a.RunSecs)
	}
	phaseCtx, releaseParent := agent.WithoutRunDeadline(ctx)
	defer releaseParent()
	hardCtx, cancelHard := agent.WithHardRunTimeout(phaseCtx, budget)
	defer cancelHard()
	hardCtx = llmrec.WithWorker(hardCtx, agentKey)
	hardCtx = llmrec.WithSession(hardCtx, runID)

	sub := ca.WithRunDir(workdir)
	permMode, permCB, disallowed := s.protocolSubagentPolicy(c, phase, workdir)
	sub = sub.WithPermission(permMode, permCB, disallowed)
	started := time.Now()
	text, chatErr := sub.Chat(hardCtx, agentKey, runID, prompt, a.MaxTurns, budget, a.WebSearch, emit)
	durationMs := time.Since(started).Milliseconds()

	// Merge only when this run actually changed its isolated findings file. If it
	// fell back to editing canonical findings (legacy behavior), just mirror that.
	finalFindings, readErr := os.ReadFile(runFindings)
	if readErr == nil && string(finalFindings) != string(initialFindings) {
		if err := mergeProtocolRunFindings(pg, caseID, workdir, runFindings, phase); err != nil {
			log.Printf("[protocol-subagent %s] merge findings: %v", phase, err)
		}
	} else if err := syncProtocolFindingsFile(pg, caseID, workdir); err != nil {
		log.Printf("[protocol-subagent %s] sync findings: %v", phase, err)
	}
	if phase == "P6" {
		syncProtocolDocs(pg, caseID, workdir)
	}

	gate := s.protocolRunner.EvaluateGate(c, workdir, phase)
	phaseStatus := "fail"
	if gate.Passed {
		phaseStatus = "pass"
	}
	if phase == "P6" && gate.Passed {
		s.storeProtocolKnowledge(c)
	}
	detail := gate.Detail
	if strings.TrimSpace(text) != "" {
		detail += " | " + firstLine(text, 200)
	}
	evidence, _ := json.Marshal(gate.Evidence)
	if evidence == nil {
		evidence = []byte(`{}`)
	}
	_ = pg.UpsertProtocolPhase(caseID, phase, gate.Gate, phaseStatus, detail, evidence)
	s.emitProtocolEvent(caseID, phase, "gate", fmt.Sprintf("[门 %s] %s %s", gate.Gate, strings.ToUpper(phaseStatus), gate.Detail), gate.Evidence)
	if chatErr != nil {
		s.emitProtocolEvent(caseID, phase, "error", "子 Agent 返回错误: "+chatErr.Error(), nil)
	}
	s.maybeCompleteProtocolCase(caseID, c.Mode)

	// Prefer the sub-agent's structured report; fall back to its final text.
	rr, _ := pg.GetProtocolSubagentRun(run.ID)
	subStatus := "partial"
	if !gate.Passed {
		subStatus = "fail"
	}
	if rr != nil && rr.Status != "running" && gate.Passed {
		subStatus = rr.Status
	}
	summary := ""
	if rr != nil {
		summary = strings.TrimSpace(rr.Summary)
	}
	if summary == "" {
		summary = strings.TrimSpace(text)
	}
	if summary == "" && chatErr != nil {
		summary = chatErr.Error()
	}
	if summary == "" {
		summary = "子 Agent 未返回摘要"
	}
	if rr == nil || rr.Status == "running" {
		ev, _ := json.Marshal(map[string]any{"gate": gate.Evidence, "duration_ms": durationMs})
		_ = pg.FinishProtocolSubagentRun(run.ID, subStatus, summary, ev, nil)
	}

	out := map[string]any{
		"case_id": caseID, "phase": phase, "agent_key": agentKey,
		"subagent_run_id": run.ID, "session_id": runID,
		"subagent_status": subStatus, "summary": truncateRunes(summary, 4000),
		"gate": gate.Gate, "passed": gate.Passed, "detail": gate.Detail,
		"counts": gate.Evidence, "duration_ms": durationMs,
	}
	if chatErr != nil {
		out["error"] = chatErr.Error()
	}
	if !gate.Passed {
		out["needs_human"] = protocolPhaseNeedsHuman(phase)
		out["next_hint"] = protocolPhaseNextHint(phase, false, s.protocolVulnEnabled(caseID)) + " 建议把子 Agent 的 summary/错误作为新线索，refine task 后重试一次。"
	} else {
		out["next_hint"] = protocolPhaseNextHint(phase, true, s.protocolVulnEnabled(caseID))
	}
	return out, nil
}

func protocolPhaseGate(phase string) string {
	switch phase {
	case "P1":
		return "A"
	case "P2":
		return "B"
	case "P3":
		return "C"
	case "P4":
		return "D"
	case "P5":
		return "E"
	case "P6":
		return "F"
	}
	return ""
}

func protocolPhaseNeedsHuman(phase string) string {
	switch phase {
	case "P1":
		return "check_install_root"
	case "P2":
		return "upload_pcap"
	case "P3":
		return "check_pcap_or_tshark"
	case "P4":
		return "check_comm_dll"
	case "P5":
		return "check_device_or_spec"
	case "P6":
		return "check_report_generation"
	}
	return ""
}

func protocolPhaseNextHint(phase string, passed bool, vulnEnabled bool) string {
	next := map[string]string{"P1": "P2", "P2": "P3", "P3": "P4", "P4": "P5", "P5": "P6", "P6": "P7", "P7": "P8", "P8": "P9"}
	if passed {
		if phase == "P6" && !vulnEnabled {
			return "六阶段全部通过：向用户总结资产/帧/功能码/验证/文档结论，并指出未验证项。"
		}
		if phase == "P9" {
			return "P1-P9 全部通过：向用户总结漏洞假设统计（confirmed/falsified/inconclusive）、EXP 资产与审批状态，并指出待验证项。"
		}
		return "门 " + protocolPhaseGate(phase) + " PASS；继续调用 protocol_delegate_phase 执行 " + next[phase] + "。"
	}
	switch phase {
	case "P1":
		return "门 A 未通过：让子 Agent 检查 install_root 是否可读，或换方法从安装包/进程中提取通信承载体。"
	case "P2":
		return "门 B 未通过：检查后台抓包是否启动、tshark/网卡是否可用、抓包是否写入工作目录 pcaps/；请操作者按 H1 脚本操作上位机后重试；确实无法抓包再上传 pcap。"
	case "P3":
		return "门 C 未通过：检查 pcap 有效性、tshark 路径和帧切分假设；同时必须至少产出 1 个 traffic 功能码或 1 条 session-model，两者都没有也会失败。"
	case "P4":
		return "门 D 未通过：要求静态功能码（不含纯流量码）有指令级出处的比例 ≥60%；让子 Agent 从二进制/配置补 RVA/指令字节证据后重试。"
	case "P5":
		return "门 E 未通过：检查是否先完成 P3×P4 交叉佐证（notes kind=code-reconciliation，pairs 非空）、是否留下带 verdict 的最终记录，再核对 device_ip/probe_port/授权；离线写带 reason 的 degraded，在线失败必须如实报 fail，不能伪装降级。"
	case "P6":
		return "门 F 未通过：检查四份 01–04 文档、必填章节和证据 ID 引用（[asset/code/frame/field:<id>]）；报告必须同步到 protocol_reports。"
	case "P7":
		return "门 G 未通过：需要 device_profile 画像 + applicability 无 unknown（缺口转 P7a 只读探测补全）+ 直判类假设全部裁决；让子 Agent 用 device_profile.py/applicability.py/vuln_intel.py 补齐后重试。"
	case "P8":
		return "门 H 未通过：所有假设需到终态（confirmed/falsified/enforced/inconclusive）；static 模式不执行 campaign——fuzz 类按 fuzz-deferred-live 裁决即可，live 模式才要求 campaign ≥1 且 destructive 需审批，无批准会被拒——如实向操作者申请审批，不要绕过。"
	case "P9":
		return "门 I 未通过：write/destructive 的 confirmed 假设必须全部有 EXP（exp_gen.py），并产出 05 号漏洞利用报告。"
	}
	return "查看阶段详情与子 Agent 摘要后决定重试或请求人工。"
}

func buildProtocolSubagentPrompt(c *db.ProtocolCase, phase, task, expected string, runID int64, workdir, findingsPath, toolsDir, python, tshark, spec, analyzers string) string {
	cfg := string(c.Config)
	if len(cfg) > 1500 {
		cfg = cfg[:1500] + "…"
	}
	var focus string
	switch phase {
	case "P1":
		focus = "找出通信承载体/进程/DLL、端口与配置线索，写 comm_assets 与 notes。"
	case "P2":
		if strings.EqualFold(c.Mode, "static") {
			focus = "案例为 static：只解析已提供的 pcap（config 登记或 pcaps/），禁止启动抓包、禁止搜索本机 pcap；判定 static 模式并写 notes/streams。缺 pcap 直接报 fail。"
		} else {
			focus = "获取或导入覆盖协议生命周期的 pcap，判定 live/static，写 notes/streams。没有 pcap 就后台启动抓包并输出到工作目录 pcaps/，提示操作者操作上位机后等待；不要在本机搜索 pcap，不要伪造。"
		}
	case "P3":
		focus = "只从 pcap/流量推断功能码语义、帧格式与字段划分（function_codes 用 layer/source=traffic），写 frame_formats/field_maps/streams；不读静态结论，不发包。"
	case "P4":
		focus = "只从上位机通信文件静态推断功能码语义、帧格式与字段划分（function_codes source=static-instruction、frame/field source=static），每条码带指令级出处；不读流量结论，不发包。"
	case "P5":
		if strings.EqualFold(c.Mode, "static") {
			focus = "案例为 static：先对 P3 流量码与 P4 静态码做交叉佐证（notes kind=code-reconciliation），再把帧/字段/功能码合并重写为最终结果并追加 notes(kind=session-model-final)，然后写带 reason（static 模式）的降级并同步 findings。"
		} else {
			focus = "先对 P3 流量码与 P4 静态码做交叉佐证（notes kind=code-reconciliation），再把帧/字段/功能码合并重写为最终结果并追加 notes(kind=session-model-final)；随后按案例授权验证功能码（write/full 要实际执行写/停止/下载类探针，read-only 才只做只读）；离线写带 reason 的降级，在线失败如实报 fail，写 probes。"
		}
	case "P6":
		focus = "先消费 P5 交叉佐证，再三源合流定名功能码，生成/润色 01-04 四份文档，写 protocol_reports。"
	case "P7":
		focus = "构建设备能力画像（device_profile.py）、47 子模板三态适用性（applicability.py）、本地 CVE 情报匹配（vuln_intel.py），并完成 deterministic 类直判裁决，产出 vuln_hypotheses。"
	case "P8":
		if strings.EqualFold(c.Mode, "static") {
			focus = "案例为 static：禁止执行任何 campaign（verify/fuzz 都不发包）、禁止构建离线重放语料。fuzz 类假设裁决 inconclusive（verdict=fuzz-deferred-live，注明需 live 复跑），deterministic 类按 P7 证据复核定终态，campaign 只写计划 JSON 到 campaigns/。"
		} else {
			focus = "用 campaign_runner.py 实际执行：deterministic 假设 verify 确定性验证，fuzz 假设灰盒执行；destructive 先审批（无批准会被拒）；Guardian 红线触发即停。"
		}
	case "P9":
		focus = "对 confirmed 假设用 exp_gen.py 生成 EXP（replay/poc/chain），产出 05 号漏洞利用报告，登记 exploit_assets。"
	}
	if strings.TrimSpace(expected) == "" {
		expected = "完成本阶段目标，把结构化结果写入 findings 文件 / 报告表，并用 protocol_report_phase 汇报。"
	}
	specLabel := strings.TrimSpace(spec)
	if specLabel == "" {
		specLabel = "auto（未指定，由你根据 pcap/DLL/findings 判断协议族）"
	}
	return fmt.Sprintf(`主 Agent 下发的阶段任务（%s）：

案例：#%d «%s»
- install_root: %s
- device_ip: %s
- authorization: %s
- mode: %s
- 工作目录（你的 CWD）: %s
- findings_path（本阶段唯一 findings 文件）: %s
- config: %s
- tools_dir: %s
- python: %s
- tshark: %s
%s- client_harness spec: %s

本阶段重点：%s

主 Agent 的具体要求：
%s

验收说明：
%s

工作方式：
- 你只负责 %s，不要推进其它阶段；遇到跨阶段问题写进 summary 交给主 Agent。
- 可以使用 Bash/Python/Read/Write/Edit/LS/Glob/Grep，也可以调用现有脚本
  （tools/recon_pe.py、frame_hypothesis.py、field_map.py、extract_codes.py、
  client_harness.py、dissector_gen.py 等），但不要只依赖固定脚本：安装包/PE/.NET/
  pcap/隧道协议形态不同，自行选择最合适的方法，必要时写临时 Python。
- 只读写 findings_path 指向的隔离文件（初始是当前 canonical findings 的快照）；
  不要编辑 canonical findings.json。服务端会在本阶段结束后按 section 合并。
- 现有 Python 脚本的 --out 参数也指向 findings_path。
- 控制工具回合：批量执行命令、一次写完脚本再运行；不要对同一文件反复小段
  Read/Edit。每阶段有明确轮次上限，接近上限先保存成果并报 partial。
- 结果写回后调用 protocol_sync_findings(case_id=%d, path=findings_path, phase="%s")；
- 最后必须调用 protocol_report_phase(run_id=%d, status="pass|partial|fail",
  summary="一句话结论与关键证据", evidence={...}, artifacts=[...])。
- 安全红线：案例 authorization 就是操作者已确认的 H2 授权范围（read-only 只读；
  write 可写；destructive/full 可复位/破坏类），按授权实际执行，不要把 write/full 降级成
  只读，也不要超出授权；探针单步执行并做前后状态快照。平台会按案例 authorization 在
  工具层拦截越权命令；被拒绝时不要绕过，说明需要操作者提高授权。证据等级
  traffic > live > static > inferred。

开始时先读 findings.json 和正确的工作目录；完成后只输出简短总结。`,
		phase, c.ID, c.Name, c.InstallRoot, c.DeviceIP, c.Authorization, c.Mode,
		workdir, findingsPath, cfg, toolsDir, python, tshark, analyzers, specLabel,
		focus, strings.TrimSpace(task), strings.TrimSpace(expected),
		phase, c.ID, phase, runID)
}

func ensureProtocolFindingsFile(workdir string) {
	path := filepath.Join(workdir, "findings.json")
	if _, err := os.Stat(path); err == nil {
		return
	}
	skeleton := `{"schema":"protocol-agent/findings/v1","phases":[],"comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"pitfalls_hit":[],"probes":[],"notes":[]}`
	_ = os.WriteFile(path, []byte(skeleton), 0o600)
}

func syncProtocolDocs(pg *db.DB, caseID int64, workdir string) {
	dir := filepath.Join(workdir, "docs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	findings, _ := pg.GetProtocolFindings(caseID)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if bad := protocol.InvalidEvidenceRefs(string(b), findings); len(bad) > 0 {
			log.Printf("[protocol-docs] skip %s: %d invalid refs: %v", e.Name(), len(bad), bad)
			continue
		}
		docType := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		_ = pg.UpsertProtocolReport(caseID, docType, e.Name(), string(b))
	}
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
