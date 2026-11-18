package server

import (
	"context"
	"encoding/json"
	"log"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
)

// toolCatalog is the slice of the DB the resolver needs. Keeping it narrow makes
// the binding/filter/meter rules testable without a live PostgreSQL.
type toolCatalog interface {
	ListTools() ([]*db.Tool, error)
}

// toolResolver applies the tools table at runtime: per-agent binding, enabled
// flag, description/schema overrides, and the usage ledger. It mirrors what the
// Tools page edits; without this hook those edits are stored but never enforced.
type toolResolver struct {
	catalog  toolCatalog
	recorder toolUsageRecorder
}

// wireToolCatalog registers the runtime resolver. Tools with a catalog row are
// filtered/decorated/metered; tools without a row (core Read/Bash, MCP, Skill,
// platform host tools) stay available and are metered under their own name.
func wireToolCatalog(pg *db.DB) {
	if pg == nil {
		return
	}
	r := &toolResolver{catalog: pg, recorder: pg}
	agent.ToolResolve = r.resolve
}

func (r *toolResolver) resolve(ctx context.Context, agentKey string, tools []actool.CoreTool) []actool.CoreTool {
	rows, err := r.catalog.ListTools()
	if err != nil {
		// Fail open: a statistics/catalog read failure must not remove the
		// agent's tools. The call still runs; only attribution is lost.
		log.Printf("[toolresolve] list tools: %v", err)
		return tools
	}
	byKey := make(map[string]*db.Tool, len(rows))
	for _, row := range rows {
		if row != nil {
			byKey[row.Key] = row
		}
	}
	ri := agent.RunInfoFrom(ctx)
	out := make([]actool.CoreTool, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		row, ok := byKey[t.Name()]
		if !ok {
			// Skill has its own ledger (and its own wrapper) to record misses;
			// wrapping it here would double-count successful loads.
			if t.Name() == "Skill" {
				out = append(out, t)
				continue
			}
			if r.recorder != nil {
				t = meterTool(t, r.recorder, t.Name(), agentKey, ri)
			}
			out = append(out, t)
			continue
		}
		if !row.Enabled || !contains(row.Agents, agentKey) {
			continue
		}
		var schema map[string]any
		if len(row.Schema) > 0 {
			_ = json.Unmarshal(row.Schema, &schema)
		}
		t = agent.DecorateTool(t, row.Description, schema)
		if r.recorder != nil {
			t = meterTool(t, r.recorder, row.Key, agentKey, ri)
		}
		out = append(out, t)
	}
	return out
}
