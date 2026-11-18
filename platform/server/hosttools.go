package server

import actool "github.com/Autumn-27/norma/tool"

// hostTools are injected into every agent's base tool list and then filtered by
// the DB tools table per agent binding. In this build they are the protocol
// tools (main + six phase agents), the platform-management tools (skill/custom
// tool/MCP CRUD) and any user-defined custom tools.
func (s *Server) hostTools() ([]actool.CoreTool, map[string][]string) {
	tools := append([]actool.CoreTool{}, s.protocolTools()...)
	tools = append(tools, s.platformTools()...)
	if custom, err := s.customTools(); err == nil {
		tools = append(tools, custom...)
	}
	return tools, nil
}
