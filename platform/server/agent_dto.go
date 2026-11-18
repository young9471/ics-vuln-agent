package server

import (
	"strconv"

	"github.com/Autumn-27/protocol-agent/db"
)

type AgentDTO struct {
	ID               string `json:"id"`
	Key              string `json:"key"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	Role             string `json:"role"`
	Builtin          bool   `json:"builtin"`
	Enabled          bool   `json:"enabled"`
	MaxTurns         int    `json:"max_turns"`
	RunSecs          int    `json:"run_seconds"`
	WebSearch        bool   `json:"web_search"`
	InteractiveShell bool   `json:"interactive_shell"`
	LLMProfileID     *int64 `json:"llm_profile_id"`
	McpCount         int    `json:"mcp_count"`
	SkillCount       int    `json:"skill_count"`
	ToolCount        int    `json:"tool_count"`
}

func i64s(v int64) string { return strconv.FormatInt(v, 10) }

func agentDTO(a *db.Agent) AgentDTO {
	return AgentDTO{
		ID: i64s(a.ID), Key: a.Key, Name: a.Name, Description: a.Description,
		Role: a.Role, Builtin: a.Builtin, Enabled: a.Enabled,
		MaxTurns: a.MaxTurns, RunSecs: a.RunSecs, WebSearch: a.WebSearch,
		InteractiveShell: a.InteractiveShell, LLMProfileID: a.LLMProfileID,
	}
}

func agentDTOs(in []*db.Agent) []AgentDTO {
	out := make([]AgentDTO, 0, len(in))
	for _, a := range in {
		out = append(out, agentDTO(a))
	}
	return out
}

type LLMProfileDTO struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Format           string           `json:"format"`
	BaseURL          string           `json:"base_url,omitempty"`
	Proxy            string           `json:"proxy,omitempty"`
	Model            string           `json:"model"`
	APIKeyHint       string           `json:"api_key_hint,omitempty"`
	RatePerSecond    float64          `json:"rate_per_second"`
	RatePerMinute    float64          `json:"rate_per_minute"`
	ContextWindowK   int              `json:"context_window_k"`
	ThinkingType     string           `json:"thinking_type"`
	ReasoningEffort  string           `json:"reasoning_effort"`
	IsDefault        bool             `json:"is_default"`
	Priority         int              `json:"priority"`
	PoolExclude      bool             `json:"pool_exclude"`
	Streaming        bool             `json:"streaming"`
	MaxTokens        int              `json:"max_tokens"`
	MaxTokensField   string           `json:"max_tokens_field"`
	SessionHeaderKey string           `json:"session_header_key"`
	Retry            db.RetryOverride `json:"retry"`
}

func llmProfileDTO(p *db.LLMProfile) LLMProfileDTO {
	return LLMProfileDTO{
		ID: i64s(p.ID), Name: p.Name, Format: p.Format, BaseURL: p.BaseURL, Proxy: p.Proxy,
		Model: p.Model, APIKeyHint: p.APIKeyHint, RatePerSecond: p.RatePerSecond,
		RatePerMinute: p.RatePerMinute, ContextWindowK: p.ContextWindowK,
		ThinkingType: p.ThinkingType, ReasoningEffort: p.ReasoningEffort,
		IsDefault: p.IsDefault, Priority: p.Priority, PoolExclude: p.PoolExclude,
		Streaming: p.Streaming, MaxTokens: p.MaxTokens, MaxTokensField: p.MaxTokensField,
		SessionHeaderKey: p.SessionHeaderKey, Retry: p.Retry,
	}
}

func llmProfileDTOs(in []*db.LLMProfile) []LLMProfileDTO {
	out := make([]LLMProfileDTO, 0, len(in))
	for _, p := range in {
		out = append(out, llmProfileDTO(p))
	}
	return out
}

func idStrings(in []int64) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, i64s(v))
	}
	return out
}
