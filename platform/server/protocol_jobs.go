package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
)

// protocolPhaseJob is one asynchronous sub-agent delegation. The delegate tool
// returns as soon as the job starts; the main agent can launch independent
// phases together and later wait with protocol_wait_phases.
type protocolPhaseJob struct {
	ID         string
	DBID       int64
	CaseID     int64
	Phase      string
	AgentKey   string
	Task       string
	Expected   string
	StartedAt  time.Time
	done       chan struct{}
	mu         sync.Mutex
	runID      int64
	result     map[string]any
	err        error
	cancelled  bool
	cancel     context.CancelCauseFunc
	pg         *db.DB
	finishedAt time.Time
}

func (j *protocolPhaseJob) finish(result map[string]any, err error) {
	j.mu.Lock()
	j.result = result
	j.err = err
	j.runID = int64FromAny(result["subagent_run_id"])
	j.finishedAt = time.Now()
	cancelled := j.cancelled
	pg, dbID := j.pg, j.DBID
	j.mu.Unlock()
	if pg != nil && dbID > 0 && j.ID != "" {
		status := "done"
		errText := ""
		if cancelled {
			status = "cancelled"
			errText = "阶段被操作者取消"
		} else if err != nil {
			status = "error"
			errText = err.Error()
		}
		raw, _ := json.Marshal(result)
		_ = pg.FinishProtocolPhaseJob(j.ID, status, raw, errText)
	}
	close(j.done)
}

func (j *protocolPhaseJob) isDone() bool {
	select {
	case <-j.done:
		return true
	default:
		return false
	}
}

func (j *protocolPhaseJob) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	status := "running"
	if j.isDone() {
		switch {
		case j.cancelled:
			status = "cancelled"
		case j.err != nil:
			status = "error"
		default:
			status = "done"
		}
	}
	out := map[string]any{
		"job_id":     j.ID,
		"case_id":    j.CaseID,
		"phase":      j.Phase,
		"agent_key":  j.AgentKey,
		"status":     status,
		"started_at": j.StartedAt.Format(time.RFC3339),
	}
	if j.cancelled && status == "running" {
		out["status"] = "cancelling"
	}
	if j.runID > 0 {
		out["subagent_run_id"] = j.runID
	}
	if !j.finishedAt.IsZero() {
		out["finished_at"] = j.finishedAt.Format(time.RFC3339)
		out["duration_ms"] = j.finishedAt.Sub(j.StartedAt).Milliseconds()
	}
	if j.err != nil {
		out["error"] = j.err.Error()
	}
	for k, v := range j.result {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}
	return out
}

func int64FromAny(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		var n int64
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}

// requireProtocolPhasePrereqs stops a manual delegate from bypassing the phase
// dependency graph. In particular P6 must not run until P5's Gate E has passed,
// and the V2 phases (P7-P9) require the case to opt in via config.vuln_enabled.
func (s *Server) requireProtocolPhasePrereqs(caseID int64, phase string) error {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	switch strings.ToUpper(strings.TrimSpace(phase)) {
	case "P7", "P8", "P9":
		if !s.protocolVulnEnabled(caseID) {
			return fmt.Errorf("%s 不能启动：案例未启用漏洞挖掘阶段（config.vuln_enabled=true 才开放 P7–P9）", phase)
		}
	}
	rows, err := s.m.pg.ListProtocolPhases(caseID)
	if err != nil {
		return err
	}
	statuses := make(map[string]string, len(rows))
	for _, p := range rows {
		if p != nil {
			statuses[strings.ToUpper(p.Phase)] = p.Status
		}
	}
	return protocolPhasePrerequisiteError(phase, statuses)
}

func protocolPhaseStatusPassed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "pass", "done":
		return true
	default:
		return false
	}
}

func protocolPhasePrerequisiteError(phase string, statuses map[string]string) error {
	phase = strings.ToUpper(strings.TrimSpace(phase))
	for _, req := range protocolPhasePrereqs[phase] {
		if protocolPhaseStatusPassed(statuses[req]) {
			continue
		}
		status := strings.TrimSpace(statuses[req])
		if status == "" {
			status = "not_started"
		}
		hint := ""
		if phase == "P6" {
			hint = "（P6 必须等 P5 门 E PASS）"
		}
		return fmt.Errorf("%s 不能启动：前置阶段 %s 当前为 %s，必须先通过门 %s%s",
			phase, req, status, protocolPhaseGate(req), hint)
	}
	return nil
}

func (s *Server) startProtocolPhaseJob(ctx context.Context, caseID int64, phase, task, expected string) (*protocolPhaseJob, error) {
	phase = strings.ToUpper(strings.TrimSpace(phase))
	if err := s.requireProtocolPhasePrereqs(caseID, phase); err != nil {
		return nil, err
	}
	s.protocolJobsMu.Lock()
	if s.protocolJobs == nil {
		s.protocolJobs = map[int64]map[string]*protocolPhaseJob{}
	}
	if s.protocolJobs[caseID] == nil {
		s.protocolJobs[caseID] = map[string]*protocolPhaseJob{}
	}
	if old := s.protocolJobs[caseID][phase]; old != nil && !old.isDone() {
		s.protocolJobsMu.Unlock()
		return nil, fmt.Errorf("%s 子 Agent 仍在运行，请等待或先查询状态", phase)
	}
	running := 0
	for _, j := range s.protocolJobs[caseID] {
		if !j.isDone() {
			running++
		}
	}
	maxParallel := 4
	if v, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PROTOCOL_AGENT_MAX_CONCURRENCY"))); err == nil && v > 0 {
		maxParallel = v
	}
	if running >= maxParallel {
		s.protocolJobsMu.Unlock()
		return nil, fmt.Errorf("每案例最多 %d 个阶段并行，请等待已有阶段完成后再启动", maxParallel)
	}
	jobID := fmt.Sprintf("job-%d-%s-%d", caseID, strings.ToLower(phase), time.Now().UnixNano())
	jobMode := ""
	if s.m != nil && s.m.pg != nil {
		if c, err := s.m.pg.GetProtocolCase(caseID); err == nil && c != nil {
			jobMode = c.Mode
		}
	}
	var row *db.ProtocolPhaseJob
	if s.m != nil && s.m.pg != nil {
		var err error
		row, err = s.m.pg.CreateProtocolPhaseJob(caseID, jobID, phase, phaseAgentKey(phase), task, expected)
		if err != nil {
			s.protocolJobsMu.Unlock()
			return nil, err
		}
	}
	// Detach from the parent (conversation-turn) context: the turn ends with
	// AbortChatTurnFinished as soon as the main agent stops talking, which would
	// kill this background job mid-run. Values are kept (logging, session);
	// cancellation and deadline come from the job registry and the subagent's
	// own run budget instead. See PLAN-V2.md M0-1.
	jobCtx, cancel := context.WithCancelCause(context.WithoutCancel(ctx))
	job := &protocolPhaseJob{
		ID: jobID, CaseID: caseID, Phase: phase, AgentKey: phaseAgentKey(phase),
		Task: task, Expected: expected, StartedAt: time.Now(), done: make(chan struct{}),
		cancel: cancel, pg: func() *db.DB {
			if s.m == nil {
				return nil
			}
			return s.m.pg
		}(),
	}
	if row != nil {
		job.DBID = row.ID
	}
	s.protocolJobs[caseID][phase] = job
	s.protocolJobsMu.Unlock()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				job.finish(nil, fmt.Errorf("阶段任务 panic: %v", r))
			}
		}()
		res, err := s.runProtocolSubagent(jobCtx, caseID, phase, task, expected)
		job.finish(res, err)
		// The final gate may have passed while this job was still marked
		// running — re-check completion now that it has left the map.
		s.maybeCompleteProtocolCase(caseID, jobMode)
	}()
	return job, nil
}

func (s *Server) cancelProtocolPhaseJob(caseID int64, phase string) error {
	phase = strings.ToUpper(strings.TrimSpace(phase))
	s.protocolJobsMu.Lock()
	j := s.protocolJobs[caseID][phase]
	s.protocolJobsMu.Unlock()
	if j == nil {
		return fmt.Errorf("阶段 %s 当前没有运行中的任务", phase)
	}
	j.mu.Lock()
	if j.isDone() {
		j.mu.Unlock()
		return fmt.Errorf("阶段 %s 已经结束", phase)
	}
	j.cancelled = true
	cancel := j.cancel
	err := j.err
	j.mu.Unlock()
	if err != nil {
		return err
	}
	if cancel != nil {
		cancel(agent.AbortChatStoppedByUser)
	}
	return nil
}

func (s *Server) protocolJobsFor(caseID int64, phases []string) []*protocolPhaseJob {
	s.protocolJobsMu.Lock()
	defer s.protocolJobsMu.Unlock()
	m := s.protocolJobs[caseID]
	if len(m) == 0 {
		return nil
	}
	if len(phases) == 0 {
		out := make([]*protocolPhaseJob, 0, len(m))
		for _, j := range m {
			out = append(out, j)
		}
		sort.Slice(out, func(i, k int) bool { return out[i].Phase < out[k].Phase })
		return out
	}
	out := make([]*protocolPhaseJob, 0, len(phases))
	for _, p := range phases {
		if j := m[p]; j != nil {
			out = append(out, j)
		}
	}
	return out
}

func (s *Server) hasRunningProtocolJobs(caseID int64) bool {
	s.protocolJobsMu.Lock()
	defer s.protocolJobsMu.Unlock()
	for _, j := range s.protocolJobs[caseID] {
		if !j.isDone() {
			return true
		}
	}
	return false
}

// maybeCompleteProtocolCase flips a running case to done once every active
// phase passed and no phase job is in flight. It must be called from BOTH the
// post-gate path and after the phase job finishes: the gate row is written
// while the job itself is still marked running, so a single check point races
// and the final-phase completion is silently skipped whenever the master turn
// already ended (server restart, turn timeout, …), leaving the case stuck in
// "running".
func (s *Server) maybeCompleteProtocolCase(caseID int64, mode string) {
	if s.m == nil || s.m.pg == nil || s.protocolRunner == nil {
		return
	}
	if !s.protocolRunner.AllPhasesPass(caseID) || s.hasRunningProtocolJobs(caseID) {
		return
	}
	c, err := s.m.pg.GetProtocolCase(caseID)
	if err != nil || c == nil || c.Status != "running" {
		return
	}
	if err := s.m.pg.UpdateProtocolCaseStatus(caseID, "done", mode, ""); err != nil {
		return
	}
	doneMsg := "六阶段全部通过，案例完成"
	if s.protocolVulnEnabled(caseID) {
		doneMsg = "P1-P9 全部通过，案例完成（含漏洞挖掘与 EXP）"
	}
	s.emitProtocolEvent(caseID, "", "status", doneMsg, nil)
}

func (s *Server) clearProtocolJobs(caseID int64) {
	// Jobs are detached from the conversation turn (M0-1), so removing the
	// registry entry must also cancel any still-running job, otherwise it
	// survives orphaned and keeps writing findings for a deleted case.
	s.protocolJobsMu.Lock()
	jobs := s.protocolJobs[caseID]
	delete(s.protocolJobs, caseID)
	s.protocolJobsMu.Unlock()
	for _, j := range jobs {
		j.mu.Lock()
		if !j.isDone() {
			j.cancelled = true
			if j.cancel != nil {
				j.cancel(agent.AbortTaskDeleted)
			}
		}
		j.mu.Unlock()
	}
}
