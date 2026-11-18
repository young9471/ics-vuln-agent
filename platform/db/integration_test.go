//go:build integration

package db

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func integrationDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("PROTOCOL_AGENT_PG_DSN")
	if dsn == "" {
		t.Skip("PROTOCOL_AGENT_PG_DSN not set")
	}
	pg, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

func TestIntegrationFindingsCodeKeysAndSemantics(t *testing.T) {
	pg := integrationDB(t)
	c, err := pg.CreateProtocolCase(ProtocolCaseInput{Name: fmt.Sprintf("integration-findings-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteProtocolCase(c.ID) })
	raw := json.RawMessage(`{"function_codes":[
		{"code":"0x58","label":"Diagnostics","layer":"UMAS","grade":"traffic","evidence":"pcap frame 1"},
		{"code":"0x58/0x01","label":"Login","layer":"UMAS","grade":"static","evidence":"dll@1000"},
		{"code":"0x58/0x02","label":"Logout","layer":"UMAS","grade":"static","evidence":"dll@1010"},
		{"code":"0x10","label":"Session","layer":"UMAS","grade":"live","evidence":"pcap frame 2"}
	]}`)
	if err := pg.ReplaceProtocolFindings(c.ID, raw); err != nil {
		t.Fatal(err)
	}
	f, err := pg.GetProtocolFindings(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Codes) != 4 {
		t.Fatalf("codes=%d want 4", len(f.Codes))
	}
	var login *ProtocolFunctionCode
	for _, code := range f.Codes {
		if code.CodeKey == "0x58/0x1" {
			login = code
		}
	}
	if login == nil {
		t.Fatal("composite code 0x58/0x01 not preserved")
	}
	if _, err := pg.UpdateProtocolCodeSemantics(c.ID, login.ID, "LoginSemantic", "live"); err != nil {
		t.Fatal(err)
	}
	if err := pg.ReplaceProtocolFindings(c.ID, raw); err != nil {
		t.Fatal(err)
	}
	f, err = pg.GetProtocolFindings(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Codes) != 4 {
		t.Fatalf("reimport changed code count: %d", len(f.Codes))
	}
	found := false
	for _, code := range f.Codes {
		if code.CodeKey == "0x58/0x1" && code.Label == "LoginSemantic" && code.Semantic {
			found = true
		}
	}
	if !found {
		t.Fatal("semantic label was not preserved across reimport")
	}
}

func TestIntegrationPhaseJobsUsageAndMigrations(t *testing.T) {
	pg := integrationDB(t)
	ctx := context.Background()
	c, err := pg.CreateProtocolCase(ProtocolCaseInput{Name: fmt.Sprintf("integration-jobs-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteProtocolCase(c.ID) })
	jobID := fmt.Sprintf("integration-job-%d", time.Now().UnixNano())
	job, err := pg.CreateProtocolPhaseJob(c.ID, jobID, "P4", "protocol_p4", "task", "expected")
	if err != nil {
		t.Fatal(err)
	}
	if err := pg.FinishProtocolPhaseJob(jobID, "done", json.RawMessage(`{"passed":true}`), ""); err != nil {
		t.Fatal(err)
	}
	jobs, err := pg.ListLatestProtocolPhaseJobs(c.ID, []string{"P4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].Status != "done" {
		t.Fatalf("jobs=%+v", jobs)
	}
	_ = job

	session := fmt.Sprintf("proto-%d-p4-integration", c.ID)
	if err := pg.InsertLLMUsage(&LLMUsage{SessionID: session, Worker: "protocol_p4", Model: "fixture", InputTokens: 11, OutputTokens: 3, Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM llm_usage WHERE session_id=$1`, session) })
	usage, err := pg.ProtocolAgentUsage(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(usage) != 1 || usage[0].Agent != "protocol_p4" || usage[0].Calls != 1 || usage[0].InputTokens != 11 {
		t.Fatalf("usage=%+v", usage)
	}

	toolSession := session + "-tool"
	if err := pg.InsertToolUsage(&ToolUsage{ToolKey: "Read", AgentKey: "protocol_p4", SessionID: toolSession}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM tool_usage WHERE session_id=$1`, toolSession) })
	counts, err := pg.ToolUsageCounts()
	if err != nil {
		t.Fatal(err)
	}
	if counts["Read"] < 1 {
		t.Fatalf("tool usage Read=%d", counts["Read"])
	}
	migrations, err := pg.SchemaMigrationStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) < 2 {
		t.Fatalf("migrations=%v", migrations)
	}
}
