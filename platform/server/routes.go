package server

import "net/http"

// Handler registers the protocol tool plus the general Agent/MCP/Skill/tool/LLM
// surface. Pentest task/asset/finding/traffic/intercept/notify routes are gone.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerSideRoutes(mux)

	mux.HandleFunc("GET /api/auth/status", s.authStatus)
	mux.HandleFunc("POST /api/auth/init", s.authInit)
	mux.HandleFunc("POST /api/auth/login", s.authLogin)
	mux.HandleFunc("POST /api/auth/change-password", s.authChangePassword)
	mux.HandleFunc("GET /api/auth/me", s.authMe)

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/logs", s.getLogs)
	mux.HandleFunc("GET /api/logs/history", s.getLogsHistory)
	mux.HandleFunc("GET /api/logs/stream", s.streamLogs)

	// Workspace file manager
	mux.HandleFunc("GET /api/workspace/list", s.wsList)
	mux.HandleFunc("GET /api/workspace/read", s.wsRead)
	mux.HandleFunc("POST /api/workspace/write", s.wsWrite)
	mux.HandleFunc("POST /api/workspace/mkdir", s.wsMkdir)
	mux.HandleFunc("DELETE /api/workspace/delete", s.wsDelete)
	mux.HandleFunc("GET /api/workspace/download", s.wsDownload)
	mux.HandleFunc("POST /api/workspace/upload", s.wsUpload)

	// Protocol reverse-engineering
	mux.HandleFunc("GET /api/protocol/cases", s.protocolListCases)
	mux.HandleFunc("POST /api/protocol/cases", s.protocolCreateCase)
	mux.HandleFunc("GET /api/protocol/cases/{id}", s.protocolGetCase)
	mux.HandleFunc("PATCH /api/protocol/cases/{id}", s.protocolUpdateCase)
	mux.HandleFunc("PATCH /api/protocol/cases/{id}/codes/{codeId}", s.protocolUpdateCodeSemantics)
	mux.HandleFunc("DELETE /api/protocol/cases/{id}", s.protocolDeleteCase)
	mux.HandleFunc("POST /api/protocol/cases/{id}/agent-run", s.protocolAgentRun)
	mux.HandleFunc("POST /api/protocol/cases/{id}/pcaps", s.protocolUploadPcap)
	mux.HandleFunc("POST /api/protocol/cases/{id}/artifacts", s.protocolUploadArtifact)
	mux.HandleFunc("GET /api/protocol/capture/interfaces", s.protocolCaptureInterfaces)
	mux.HandleFunc("GET /api/protocol/cases/{id}/capture", s.protocolCaptureStatus)
	mux.HandleFunc("GET /api/protocol/cases/{id}/phase-jobs", s.protocolListPhaseJobs)
	mux.HandleFunc("GET /api/protocol/cases/{id}/metrics", s.protocolCaseMetrics)
	mux.HandleFunc("POST /api/protocol/cases/{id}/phase-jobs/{phase}/cancel", s.protocolCancelPhaseJob)
	mux.HandleFunc("POST /api/protocol/cases/{id}/capture", s.protocolCaptureStart)
	mux.HandleFunc("POST /api/protocol/cases/{id}/capture/stop", s.protocolCaptureStop)
	mux.HandleFunc("GET /api/protocol/cases/{id}/findings", s.protocolCaseFindings)
	mux.HandleFunc("GET /api/protocol/cases/{id}/exploit", s.protocolExploitScript)
	mux.HandleFunc("GET /api/protocol/cases/{id}/phases", s.protocolCasePhases)
	mux.HandleFunc("GET /api/protocol/cases/{id}/reports", s.protocolCaseReports)
	mux.HandleFunc("GET /api/protocol/cases/{id}/pcaps/quality", s.protocolPcapQuality)
	mux.HandleFunc("GET /api/protocol/cases/{id}/reports/export", s.protocolExportReports)
	mux.HandleFunc("GET /api/protocol/cases/{id}/reports/{doc}/versions", s.protocolReportVersions)
	mux.HandleFunc("POST /api/protocol/cases/{id}/reports/{doc}/approve", s.protocolApproveReport)
	mux.HandleFunc("GET /api/protocol/cases/{id}/events", s.protocolCaseEvents)
	// V2: destructive-campaign approval hard gate (admin decides, agents create).
	mux.HandleFunc("POST /api/protocol/cases/{id}/approvals", s.pgCreateApproval)
	mux.HandleFunc("GET /api/protocol/cases/{id}/approvals", s.pgListApprovals)
	mux.HandleFunc("GET /api/protocol/approvals/{id}", s.pgGetApproval)
	mux.HandleFunc("POST /api/protocol/approvals/{id}/decide", s.pgDecideApproval)
	mux.HandleFunc("GET /api/protocol/cases/{id}/events/stream", s.protocolCaseEventStream)
	mux.HandleFunc("GET /api/protocol/findings", s.protocolListFindings)
	mux.HandleFunc("GET /api/protocol/stats", s.protocolStats)
	mux.HandleFunc("GET /api/protocol/dashboard", s.protocolVulnDashboard)
	mux.HandleFunc("GET /api/protocol/knowledge", s.protocolKnowledge)
	mux.HandleFunc("GET /api/protocol/knowledge/script", s.protocolKnowledgeScript)
	mux.HandleFunc("GET /api/protocol/tools", s.protocolToolConfig)
	mux.HandleFunc("GET /api/protocol/tools/check", s.protocolCheckTools)

	// Conversations / chat
	mux.HandleFunc("GET /api/conversations", s.pgListConversations)
	mux.HandleFunc("POST /api/conversations", s.pgCreateConversation)
	mux.HandleFunc("POST /api/conversations/delete/batch", s.pgDeleteConversationsBatch)
	mux.HandleFunc("PATCH /api/conversations/{id}", s.pgRenameConversation)
	mux.HandleFunc("PATCH /api/conversations/{id}/profile", s.pgUpdateConversation)
	mux.HandleFunc("DELETE /api/conversations/{id}", s.pgDeleteConversation)
	mux.HandleFunc("GET /api/conversations/{id}/messages", s.pgConversationMessages)
	mux.HandleFunc("POST /api/conversations/{id}/messages", s.pgSendConversationMessage)
	mux.HandleFunc("POST /api/conversations/{id}/stop", s.pgStopConversation)
	mux.HandleFunc("GET /api/conversations/{id}/messages/{seq}", s.pgConversationMsgDetail)
	mux.HandleFunc("GET /api/chat/mentions", s.searchChatMentions)
	mux.HandleFunc("POST /api/chat/upload", s.chatUpload)

	// Agents / prompts / visibility
	mux.HandleFunc("GET /api/agents", s.pgListAgents)
	mux.HandleFunc("POST /api/agents", s.pgCreateAgent)
	mux.HandleFunc("GET /api/agents/{key}", s.pgGetAgent)
	mux.HandleFunc("PATCH /api/agents/{key}", s.pgUpdateAgent)
	mux.HandleFunc("DELETE /api/agents/{key}", s.pgDeleteAgent)
	mux.HandleFunc("PUT /api/agents/{key}/config", s.pgSaveAgentConfig)
	mux.HandleFunc("PUT /api/agents/{key}/prompt", s.pgSavePrompt)
	mux.HandleFunc("POST /api/agents/{key}/prompt/reset", s.pgResetPrompt)
	mux.HandleFunc("PUT /api/agents/{key}/wrapup", s.pgSaveWrapup)
	mux.HandleFunc("POST /api/agents/{key}/wrapup/reset", s.pgResetWrapup)
	mux.HandleFunc("PUT /api/agents/{key}/wrapup/task-timeout", s.pgSaveTaskTimeoutWrapup)
	mux.HandleFunc("POST /api/agents/{key}/wrapup/task-timeout/reset", s.pgResetTaskTimeoutWrapup)
	mux.HandleFunc("GET /api/agents/{key}/prompts", s.pgListPromptVersions)
	mux.HandleFunc("GET /api/agents/{key}/variables", s.pgPromptVars)
	mux.HandleFunc("POST /api/agents/{key}/prompt/preview", s.pgPreviewPrompt)
	mux.HandleFunc("GET /api/agents/{key}/visibility", s.pgGetAgentVisibility)
	mux.HandleFunc("PUT /api/agents/{key}/visibility", s.pgSetAgentVisibility)

	// Tools / custom tools
	mux.HandleFunc("GET /api/tools", s.pgListTools)
	mux.HandleFunc("GET /api/tools/usage", s.pgToolUsage)
	mux.HandleFunc("PUT /api/tools/{key}", s.pgUpdateTool)
	mux.HandleFunc("POST /api/tools/custom", s.pgCreateCustomTool)
	mux.HandleFunc("POST /api/tools/custom/test", s.pgTestCustomTool)
	mux.HandleFunc("PUT /api/tools/custom/{key}", s.pgUpdateCustomTool)
	mux.HandleFunc("DELETE /api/tools/custom/{key}", s.pgDeleteCustomTool)
	mux.HandleFunc("POST /api/tools/{key}/reset", s.pgResetTool)
	mux.HandleFunc("POST /api/settings/python/detect", s.pgDetectPython)

	// MCP
	mux.HandleFunc("GET /api/mcp", s.pgListMCP)
	mux.HandleFunc("POST /api/mcp", s.pgSaveMCP)
	mux.HandleFunc("DELETE /api/mcp/{id}", s.pgDeleteMCP)
	mux.HandleFunc("GET /api/mcp/{id}/tools", s.pgMCPTools)
	mux.HandleFunc("POST /api/mcp/{id}/refresh", s.pgRefreshMCP)

	// Skills
	mux.HandleFunc("GET /api/skills", s.fsListSkills)
	mux.HandleFunc("POST /api/skills", s.fsCreateSkill)
	mux.HandleFunc("POST /api/skills/upload", s.fsUploadSkill)
	mux.HandleFunc("DELETE /api/skills/{name}", s.fsDeleteSkill)
	mux.HandleFunc("GET /api/skills/missing", s.fsMissingSkills)
	mux.HandleFunc("GET /api/skills/{name}/usage", s.fsSkillUsage)
	mux.HandleFunc("PUT /api/skills/{name}/meta", s.fsUpdateSkillMeta)
	mux.HandleFunc("POST /api/skills/{name}/dirs", s.fsCreateDir)
	mux.HandleFunc("GET /api/skills/{name}/files", s.fsListFiles)
	mux.HandleFunc("GET /api/skills/{name}/files/{file...}", s.fsReadFile)
	mux.HandleFunc("PUT /api/skills/{name}/files/{file...}", s.fsWriteFile)
	mux.HandleFunc("DELETE /api/skills/{name}/files/{file...}", s.fsDeletePath)
	mux.HandleFunc("GET /api/visibility/{kind}/{id}", s.pgResourceVisibility)
	mux.HandleFunc("POST /api/visibility/toggle", s.pgToggleVisibility)
	mux.HandleFunc("GET /api/visibility/skill/{name}", s.pgSkillVisibility)
	mux.HandleFunc("POST /api/visibility/skill/toggle", s.pgToggleSkillVisibility)

	// LLM profiles / pool / records
	mux.HandleFunc("GET /api/llm", s.getLLM)
	mux.HandleFunc("POST /api/llm", s.setLLM)
	mux.HandleFunc("POST /api/llm/test", s.testLLM)
	// V2: admin-only single completion for bulk utilities (vuln_knowledge import).
	mux.HandleFunc("POST /api/llm/complete", s.pgLLMComplete)
	mux.HandleFunc("GET /api/llm/profiles", s.pgListProfiles)
	mux.HandleFunc("POST /api/llm/profiles", s.pgSaveProfile)
	mux.HandleFunc("DELETE /api/llm/profiles/{id}", s.pgDeleteProfile)
	mux.HandleFunc("POST /api/llm/profiles/active", s.pgActivateProfile)
	mux.HandleFunc("GET /api/llm/retry-policy", s.pgGetLLMRetryPolicy)
	mux.HandleFunc("POST /api/llm/retry-policy", s.pgSaveLLMRetryPolicy)
	mux.HandleFunc("GET /api/llm/pool", s.pgLLMPoolStatus)
	mux.HandleFunc("POST /api/llm/pool/reset", s.pgLLMPoolReset)
	mux.HandleFunc("POST /api/llm/models", s.pgListModels)
	mux.HandleFunc("GET /api/llm/records", s.pgListLLMRecords)
	mux.HandleFunc("GET /api/llm/records/by-model", s.pgTokenByModel)
	mux.HandleFunc("GET /api/llm/records/{id}", s.pgGetLLMRecord)

	// Users / audit (admin-only; enforced in requireAuth)
	mux.HandleFunc("GET /api/users", s.pgListUsers)
	mux.HandleFunc("POST /api/users", s.pgCreateUser)
	mux.HandleFunc("PATCH /api/users/{id}", s.pgUpdateUser)
	mux.HandleFunc("DELETE /api/users/{id}", s.pgDeleteUser)
	mux.HandleFunc("GET /api/audit", s.pgListAudit)

	// Settings
	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("PUT /api/settings", s.putSettings)

	api := cors(s.requireAuth(s.auditRequests(mux)))
	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/", s.webuiHandler())
	return root
}

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
