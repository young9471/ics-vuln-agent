package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
	"github.com/Autumn-27/protocol-agent/protocol"
)

// protocolTools are host tools for the built-in "protocol" agent. They are seeded
// into the tools table and bound only to that agent, so ordinary pentest agents
// never see them.
func (s *Server) protocolTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolProtocolListCases(),
		s.toolProtocolGetCase(),
		s.toolProtocolDelegatePhase(),
		s.toolProtocolWaitPhases(),
		s.toolProtocolCancelPhase(),
		s.toolProtocolUpdateCode(),
		s.toolProtocolWriteReport(),
		s.toolProtocolReportPhase(),
		s.toolProtocolSyncFindings(),
		s.toolProtocolLookupKnowledge(),
	}
}

func (s *Server) toolProtocolLookupKnowledge() actool.CoreTool {
	return roTool("protocol_lookup_knowledge",
		"查询跨案例协议指纹知识库（端口/magic/厂商/型号/协议/帧/码表/状态机）。只作为假设来源，必须用当前案例证据重新确认。",
		objSchema(map[string]any{
			"q":     strParam("关键字：协议/厂商/型号/端口/magic/案例名（可选）"),
			"limit": map[string]any{"type": "integer", "description": "最多返回条数，默认 10"},
		}),
		func(_ context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				Q     string `json:"q"`
				Limit int    `json:"limit"`
			}
			_ = json.Unmarshal(raw, &in)
			items, err := pg.ListProtocolKnowledge(in.Q, in.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"items": items})
		})
}

func (s *Server) toolProtocolListCases() actool.CoreTool {
	return roTool("protocol_list_cases",
		"列出协议逆向案例（可按状态/关键字过滤）。用于找到 case_id 后再调用 protocol_get_case。",
		objSchema(map[string]any{
			"q":      strParam("关键字：案例名/安装目录/设备 IP（可选）"),
			"status": strParam("draft|queued|running|paused|done|failed（可选）"),
			"limit":  map[string]any{"type": "integer", "description": "最多返回条数，默认 50"},
		}),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				Q      string `json:"q"`
				Status string `json:"status"`
				Limit  int    `json:"limit"`
			}
			_ = json.Unmarshal(raw, &in)
			items, total, err := pg.ListProtocolCases(in.Status, in.Q, in.Limit, 0)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"items": items, "total": total})
		})
}

func (s *Server) toolProtocolGetCase() actool.CoreTool {
	return roTool("protocol_get_case",
		"读取一个协议案例的完整态势：案例字段、六阶段状态、通信资产/帧/字段/功能码/探针、交付文档。",
		objSchema(map[string]any{
			"case_id": idParam("协议案例 id（protocol_list_cases 返回的 id）"),
		}, "case_id"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				CaseID json.RawMessage `json:"case_id"`
			}
			_ = json.Unmarshal(raw, &in)
			id := parseProfileID(in.CaseID)
			if id <= 0 {
				return actool.Errorf("case_id 无效"), nil
			}
			c, err := pg.GetProtocolCase(id)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if c == nil {
				return actool.Errorf("案例不存在"), nil
			}
			phases, _ := pg.ListProtocolPhases(id)
			findings, _ := pg.GetProtocolFindings(id)
			reports, _ := pg.ListProtocolReports(id)
			// Report bodies can be long; return titles/lengths so the agent can ask
			// for a specific doc type without flooding the context.
			reportMeta := make([]map[string]any, 0, len(reports))
			for _, r := range reports {
				reportMeta = append(reportMeta, map[string]any{
					"doc_type": r.DocType, "title": r.Title, "version": r.Version,
					"chars": len(r.Content), "updated_at": r.UpdatedAt,
				})
			}
			return jsonResult(map[string]any{
				"case": c, "phases": phases, "findings": findings, "reports": reportMeta,
			})
		})
}

func (s *Server) toolProtocolUpdateCode() actool.CoreTool {
	return wrTool("protocol_update_code",
		"更新一个功能码的语义标签与证据等级。只改 label/grade，保留原始 P4 出处地址；用于 LLM 三源合流定名。",
		objSchema(map[string]any{
			"case_id": idParam("协议案例 id"),
			"code_id": idParam("功能码记录 id（protocol_get_case.findings.function_codes[].id）"),
			"label":   strParam("语义标签/函数名"),
			"grade":   strParam("证据等级：traffic|live|static|inferred（可选，默认 static）"),
		}, "case_id", "code_id", "label"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				CaseID json.RawMessage `json:"case_id"`
				CodeID json.RawMessage `json:"code_id"`
				Label  string          `json:"label"`
				Grade  string          `json:"grade"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID, codeID := parseProfileID(in.CaseID), parseProfileID(in.CodeID)
			if caseID <= 0 || codeID <= 0 || strings.TrimSpace(in.Label) == "" {
				return actool.Errorf("case_id/code_id/label 必填"), nil
			}
			updated, err := pg.UpdateProtocolCodeSemantics(caseID, codeID, strings.TrimSpace(in.Label), strings.TrimSpace(in.Grade))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if updated == nil {
				return actool.Errorf("功能码不存在"), nil
			}
			return jsonResult(updated)
		})
}

func (s *Server) toolProtocolWriteReport() actool.CoreTool {
	return wrTool("protocol_write_report",
		"写入/覆盖一份协议交付文档（Markdown）。doc_type 建议 01_通信文件清单与架构 / 02_功能码表 / 03_帧格式详解 / 04_字段划分。工具会拒绝无法解析的证据引用；只允许 findings 中真实存在的数字 ID 或原始 key。",
		objSchema(map[string]any{
			"case_id":  idParam("协议案例 id"),
			"doc_type": strParam("文档类型（稳定 key）"),
			"title":    strParam("文档标题（可选）"),
			"content":  strParam("Markdown 正文"),
		}, "case_id", "doc_type", "content"),
		func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
			pg := s.m.pg
			if pg == nil {
				return actool.Errorf("PostgreSQL 未连接"), nil
			}
			var in struct {
				CaseID  json.RawMessage `json:"case_id"`
				DocType string          `json:"doc_type"`
				Title   string          `json:"title"`
				Content string          `json:"content"`
			}
			_ = json.Unmarshal(raw, &in)
			caseID := parseProfileID(in.CaseID)
			if caseID <= 0 || strings.TrimSpace(in.DocType) == "" {
				return actool.Errorf("case_id/doc_type 必填"), nil
			}
			title := in.Title
			if title == "" {
				title = in.DocType
			}
			findings, err := pg.GetProtocolFindings(caseID)
			if err != nil {
				return actool.Errorf("读取 findings 失败: " + err.Error()), nil
			}
			if bad := protocol.InvalidEvidenceRefs(in.Content, findings); len(bad) > 0 {
				preview := bad
				if len(preview) > 8 {
					preview = preview[:8]
				}
				return actool.Errorf(fmt.Sprintf(
					"报告包含 %d 个无法解析的证据引用：%s。只能使用 findings 中真实的数字 ID 或原始 key（如 [probe:<probe_key>]、[probe:<id>]）；不要使用 code/action 名称或 tcp:5562 这类描述性标签。",
					len(bad), strings.Join(preview, ", "))), nil
			}
			if err := pg.UpsertProtocolReport(caseID, in.DocType, title, in.Content); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return jsonResult(map[string]any{"ok": true, "case_id": caseID, "doc_type": in.DocType, "chars": len(in.Content)})
		})
}

// seedProtocolAgent creates the built-in protocol agent (idempotent), seeds its
// host tools into the tools table, and binds them to that agent. The agent row
// itself is created by db.seedBuiltins; this only wires tools/prompt for DBs that
// predate the protocol feature.
func (s *Server) seedProtocolAgent() {
	pg := s.m.pg
	if pg == nil {
		return
	}
	a, err := pg.GetAgentByKey("protocol")
	if err != nil || a == nil {
		return
	}
	// Deterministic phase execution was removed; old installs may still carry
	// its tool row. Delete it so the tool list and prompt cannot advertise it.
	_, _ = pg.Exec(`DELETE FROM tools WHERE key='protocol_run_phase'`)
	// One-time refresh: existing tool rows are insert-only, so the new async
	// delegate description and the sync_findings path/phase params would never
	// reach upgraded databases otherwise.
	const toolsFlag = "protocol_tools_parallel_v1"
	refreshTools := false
	if v, _, _ := pg.GetSetting(toolsFlag); v != "true" {
		refreshTools = true
	}
	for _, t := range s.protocolTools() {
		agents := protocolToolAgents(t.Name())
		schema, _ := json.Marshal(t.InputSchema())
		agentsJSON, _ := json.Marshal(agents)
		if err := pg.SeedTool(t.Name(), t.Description(), schema, agentsJSON); err != nil {
			continue
		}
		if refreshTools {
			_ = pg.RefreshToolDefaults(t.Name(), t.Description(), schema)
		}
		for _, ak := range agents {
			_ = pg.AddAgentToToolBinding(ak, []string{t.Name()})
		}
	}
	if refreshTools {
		_ = pg.SetSetting(toolsFlag, "true")
	}
	// Seed prompt bodies when empty, then migrate all protocol-agent defaults once.
	// Old versions are preserved in agent_prompts history by ResetPromptToDefault.
	const flag = "protocol_prompt_ready_v33"
	migrate := false
	if v, _, _ := pg.GetSetting(flag); v != "true" {
		migrate = true
	}
	for _, key := range append([]string{"protocol"}, protocolPhaseAgentKeys()...) {
		ag, err := pg.GetAgentByKey(key)
		if err != nil || ag == nil {
			continue
		}
		tmpl := agentPromptSeed(key)
		if tmpl == "" {
			continue
		}
		_ = pg.SeedPromptIfEmpty(ag.ID, tmpl)
		if migrate {
			if cur, note, by, err := pg.CurrentPromptMeta(ag.ID); err == nil && cur != tmpl && (by == "system" || note == "内置默认" || note == "恢复为内置默认") {
				_, _ = pg.ResetPromptToDefault(ag.ID, tmpl)
			}
		}
	}
	if migrate {
		_ = pg.SetSetting(flag, "true")
	}
	s.ensureProtocolBudgets(pg)
}

// ensureProtocolBudgets gives the orchestrator enough wall clock to run six
// sequential sub-agents, and caps each phase so one runaway phase cannot burn
// hundreds of model turns. Only untouched defaults are migrated; operator
// customizations are preserved.
func (s *Server) ensureProtocolBudgets(pg *db.DB) {
	const flag = "protocol_agent_budgets_v4"
	if v, _, _ := pg.GetSetting(flag); v == "true" {
		return
	}
	if _, err := pg.Exec(`UPDATE agents SET max_turns=80, run_seconds=14400
WHERE key='protocol' AND max_turns=0 AND run_seconds=1200`); err != nil {
		return
	}
	if _, err := pg.Exec(`UPDATE agents SET max_turns=60
WHERE key IN ('protocol_p1','protocol_p2','protocol_p3','protocol_p4','protocol_p5','protocol_p6')
  AND max_turns=0`); err != nil {
		return
	}
	_ = pg.SetSetting(flag, "true")
}

func protocolPhaseAgentKeys() []string {
	return []string{"protocol_p1", "protocol_p2", "protocol_p3", "protocol_p4", "protocol_p5", "protocol_p6"}
}

// protocolToolAgents decides which agents see each protocol tool. Sub-agents get
// read/sync/report tools; only the main agent can delegate a phase.
func protocolToolAgents(tool string) []string {
	phases := protocolPhaseAgentKeys()
	switch tool {
	case "protocol_list_cases", "protocol_delegate_phase", "protocol_wait_phases", "protocol_cancel_phase":
		return []string{"protocol"}
	case "protocol_get_case":
		return append([]string{"protocol"}, phases...)
	case "protocol_report_phase", "protocol_sync_findings":
		return phases
	case "protocol_update_code":
		return []string{"protocol", "protocol_p4", "protocol_p6"}
	case "protocol_lookup_knowledge":
		return []string{"protocol", "protocol_p1", "protocol_p4", "protocol_p6"}
	case "protocol_write_report":
		return []string{"protocol", "protocol_p6"}
	}
	return []string{"protocol"}
}

// agentPromptSeed isolates the agent package import for the one call site above.
func agentPromptSeed(key string) string {
	return agent.BuiltinPromptSeeds()[key]
}
