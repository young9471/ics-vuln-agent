package server

import (
	"encoding/json"
	"time"

	"github.com/Autumn-27/protocol-agent/db"
)

type ActivityDTO struct {
	Seq              int64           `json:"seq"`
	IntentID         string          `json:"intent_id,omitempty"`
	Worker           string          `json:"worker"`
	TS               string          `json:"ts"`
	Kind             string          `json:"kind"`
	Tool             string          `json:"tool,omitempty"`
	ToolUseID        string          `json:"tool_use_id,omitempty"`
	IsError          bool            `json:"is_error"`
	Summary          string          `json:"summary"`
	Detail           string          `json:"detail,omitempty"`
	Metadata         json.RawMessage `json:"metadata,omitempty"`
	SourceTaskID     string          `json:"source_task_id,omitempty"`
	Inherited        bool            `json:"inherited,omitempty"`
	MainSeg          *int            `json:"main_seg,omitempty"`
	InputTokens      *int            `json:"input_tokens,omitempty"`
	OutputTokens     *int            `json:"output_tokens,omitempty"`
	CacheReadTokens  *int            `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens *int            `json:"cache_write_tokens,omitempty"`
}

func activityDTO(a db.Activity) ActivityDTO {
	intent := ""
	if a.NodeID != nil {
		intent = i64s(*a.NodeID)
	}
	d := ActivityDTO{
		Seq: a.ID, IntentID: intent, Worker: a.Worker, TS: rfc3339(a.CreatedAt),
		Kind: a.Kind, Tool: a.Tool, ToolUseID: a.ToolUseID, IsError: a.IsError,
		Summary: a.Summary, Detail: a.Detail, Metadata: a.Metadata,
		InputTokens: a.InputTokens, OutputTokens: a.OutputTokens,
		CacheReadTokens: a.CacheReadTokens, CacheWriteTokens: a.CacheWriteTokens,
		MainSeg: a.MainSeg,
	}
	if a.SourceTaskID > 0 {
		d.SourceTaskID = i64s(a.SourceTaskID)
	}
	d.Inherited = a.Inherited
	return d
}

func activityDTOs(in []db.Activity) []ActivityDTO {
	out := make([]ActivityDTO, 0, len(in))
	for _, a := range in {
		out = append(out, activityDTO(a))
	}
	return out
}

func rfc3339(t time.Time) string { return t.Format(time.RFC3339) }

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
