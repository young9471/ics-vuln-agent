package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
)

type fakeToolCatalog struct {
	rows []*db.Tool
	err  error
}

func (f *fakeToolCatalog) ListTools() ([]*db.Tool, error) { return f.rows, f.err }

type fakeToolRecorder struct {
	nextID  int64
	rows    []*db.ToolUsage
	outcome map[int64]string
}

func (f *fakeToolRecorder) InsertToolUsage(u *db.ToolUsage) error {
	f.nextID++
	u.ID = f.nextID
	f.rows = append(f.rows, u)
	return nil
}

func (f *fakeToolRecorder) FinishToolUsage(id int64, outcome string) error {
	if f.outcome == nil {
		f.outcome = map[int64]string{}
	}
	f.outcome[id] = outcome
	return nil
}

func testTool(name, desc string, run func(json.RawMessage)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        name,
		Description: desc,
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if run != nil {
				run(in)
			}
			return actool.Text("ok"), nil
		},
	})
}

func TestToolResolverFiltersDecoratesAndMeters(t *testing.T) {
	catalog := &fakeToolCatalog{rows: []*db.Tool{
		{
			Key: "bound_tool", Enabled: true, Agents: []string{"protocol_p4"},
			Description: "overridden description",
			Schema:      json.RawMessage(`{"type":"object","properties":{"x":{"type":"string","default":"from-schema"}}}`),
		},
		{Key: "disabled_tool", Enabled: false, Agents: []string{"protocol_p4"}},
		{Key: "unbound_tool", Enabled: true, Agents: []string{"protocol_p6"}},
	}}
	rec := &fakeToolRecorder{}
	resolver := &toolResolver{catalog: catalog, recorder: rec}

	var gotDefault string
	var disabledCalled, unboundCalled bool
	tools := []actool.CoreTool{
		testTool("bound_tool", "original description", func(in json.RawMessage) {
			var v struct {
				X string `json:"x"`
			}
			_ = json.Unmarshal(in, &v)
			gotDefault = v.X
		}),
		testTool("disabled_tool", "disabled", func(json.RawMessage) { disabledCalled = true }),
		testTool("unbound_tool", "unbound", func(json.RawMessage) { unboundCalled = true }),
		testTool("Read", "core read", nil),
	}

	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: "session-1"})
	out := resolver.resolve(ctx, "protocol_p4", tools)
	if len(out) != 2 {
		t.Fatalf("resolved %d tools, want 2: %v", len(out), toolNames(out))
	}
	if out[0].Name() != "bound_tool" || out[1].Name() != "Read" {
		t.Fatalf("unexpected tools: %v", toolNames(out))
	}
	if out[0].Description() != "overridden description" {
		t.Fatalf("description override not applied: %q", out[0].Description())
	}

	if _, err := out[0].Call(ctx, json.RawMessage(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if gotDefault != "from-schema" {
		t.Fatalf("default injection failed: got %q", gotDefault)
	}
	if disabledCalled || unboundCalled {
		t.Fatal("disabled/unbound tool was callable")
	}

	if _, err := out[1].Call(ctx, json.RawMessage(`{}`), nil); err != nil {
		t.Fatal(err)
	}

	if len(rec.rows) != 2 {
		t.Fatalf("recorded %d rows, want 2", len(rec.rows))
	}
	if rec.rows[0].ToolKey != "bound_tool" || rec.rows[0].AgentKey != "protocol_p4" || rec.rows[0].SessionID != "session-1" {
		t.Fatalf("bad catalog attribution: %+v", rec.rows[0])
	}
	if rec.rows[0].ID == 0 || rec.outcome[rec.rows[0].ID] != "success" {
		t.Fatalf("catalog outcome not finished: row=%+v outcomes=%v", rec.rows[0], rec.outcome)
	}
	if rec.rows[1].ToolKey != "Read" || rec.rows[1].AgentKey != "protocol_p4" || rec.rows[1].SessionID != "session-1" {
		t.Fatalf("bad core-tool attribution: %+v", rec.rows[1])
	}
	if rec.rows[1].ID == 0 || rec.outcome[rec.rows[1].ID] != "success" {
		t.Fatalf("core-tool outcome not finished: row=%+v outcomes=%v", rec.rows[1], rec.outcome)
	}
}

func TestToolResolverFailsOpenOnCatalogError(t *testing.T) {
	resolver := &toolResolver{
		catalog:  &fakeToolCatalog{err: errors.New("db unavailable")},
		recorder: &fakeToolRecorder{},
	}
	tools := []actool.CoreTool{testTool("Read", "core read", nil)}
	out := resolver.resolve(context.Background(), "protocol", tools)
	if len(out) != 1 || out[0].Name() != "Read" {
		t.Fatalf("catalog failure should preserve tools, got %v", toolNames(out))
	}
}

func toolNames(tools []actool.CoreTool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.Name())
	}
	return out
}
