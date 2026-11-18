package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"

	actool "github.com/Autumn-27/norma/tool"
)

// DeferredInfo carries the deferred-tools wiring an agent needs to build its
// Options: MCP tool names whose schemas are withheld, the subset listed in the
// system-prompt block, and the shared session unlock set.
type DeferredInfo struct {
	Deferred    []string          // all MCP tool names (schema withheld)
	GlobalNames []string          // MCP names to list in the system-prompt block
	Unlock      *actool.UnlockSet // shared call-gate; nil when no MCP tools
	UnlockSkill func(skillName string)
}

// ToolAugment, if set, returns the extra tools an agent should see beyond its
// built-in base set: visible skills (packed into one Skill meta-tool) and visible
// MCP servers (expanded to mcp__server__tool). The server wires it to the PG
// agent_visibility table. cleanup releases any spawned MCP clients.
var ToolAugment func(ctx context.Context, agentKey string) (extra []actool.CoreTool, def DeferredInfo, cleanup func())

// AugmentTools returns base plus the agent's visible skill/MCP tools, the
// DeferredInfo, and a cleanup func the caller must defer.
func AugmentTools(ctx context.Context, agentKey string, base []actool.CoreTool) ([]actool.CoreTool, DeferredInfo, func()) {
	var (
		def     DeferredInfo
		cleanup = func() {}
		out     = base
	)
	if ToolAugment != nil {
		var extra []actool.CoreTool
		var cl func()
		extra, def, cl = ToolAugment(ctx, agentKey)
		if cl != nil {
			cleanup = cl
		}
		if len(extra) > 0 {
			out = append(append([]actool.CoreTool{}, base...), extra...)
		}
	}
	// The DB tools table filters built-in/host tools per agent and applies
	// description/schema overrides. MCP/skill tools have no row and pass through.
	if ToolResolve != nil {
		out = ToolResolve(ctx, agentKey, out)
	}
	for i, t := range out {
		out[i] = guardPanic(t)
	}
	return out, def, cleanup
}

// guardPanic turns a panicking tool handler into an ordinary tool error. The
// harness runs each tool on its own goroutine, so a panic could otherwise take
// down the whole process.
func guardPanic(t actool.CoreTool) actool.CoreTool { return &guardedTool{CoreTool: t} }

type guardedTool struct{ actool.CoreTool }

func (g *guardedTool) Call(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (res actool.Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[tools] %s panic: %v\n%s", g.Name(), r, debug.Stack())
			res, err = actool.Errorf(fmt.Sprintf("工具 %s 内部错误：%v（本次调用已失败，可换个参数或改用别的工具）", g.Name(), r)), nil
		}
	}()
	return g.CoreTool.Call(ctx, in, tc)
}
