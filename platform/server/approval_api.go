package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// V2 (PLAN-V2 §5): the destructive-campaign approval hard gate. P8 agents
// create approval requests here; only admins decide; campaign_runner refuses
// destructive campaigns unless the referenced approval is "approved" (it checks
// GET /api/protocol/approvals/{id} itself, so the gate lives outside the LLM).

func (s *Server) pgCreateApproval(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "案例 id 无效")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if c == nil {
		writeErr(w, 404, "案例不存在")
		return
	}
	var req struct {
		Kind    string          `json:"kind"`
		Risk    string          `json:"risk"`
		Payload json.RawMessage `json:"payload"`
		Note    string          `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	req.Kind = strings.TrimSpace(req.Kind)
	if req.Kind == "" {
		req.Kind = "campaign"
	}
	if req.Risk == "" {
		req.Risk = "destructive"
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage("{}")
	}
	if req.Payload != nil && req.Note != "" {
		var p map[string]any
		if json.Unmarshal(req.Payload, &p) == nil && p != nil {
			p["note"] = req.Note
			if b, err := json.Marshal(p); err == nil {
				req.Payload = b
			}
		}
	}
	me, _ := principalFrom(r.Context())
	a, err := pg.CreateProtocolApproval(id, req.Kind, req.Payload, req.Risk, me.Username)
	if err != nil {
		writeErr(w, 500, "创建审批失败")
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) pgListApprovals(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "案例 id 无效")
		return
	}
	list, err := pg.ListProtocolApprovals(id)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"items": list})
}

func (s *Server) pgGetApproval(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "审批 id 无效")
		return
	}
	a, err := pg.GetProtocolApproval(id)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if a == nil {
		writeErr(w, 404, "审批不存在")
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) pgDecideApproval(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "审批 id 无效")
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	switch strings.ToLower(strings.TrimSpace(req.Decision)) {
	case "approve", "approved":
		req.Decision = "approved"
	case "reject", "rejected":
		req.Decision = "rejected"
	default:
		writeErr(w, 400, "decision 必须是 approve 或 reject")
		return
	}
	me, _ := principalFrom(r.Context())
	a, err := pg.DecideProtocolApproval(id, req.Decision, me.Username, req.Note)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if a == nil {
		writeErr(w, 409, "审批不存在或已裁决")
		return
	}
	writeJSON(w, 200, a)
}
