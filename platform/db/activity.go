package db

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// Activity is one conversation/agent execution step. NodeID is kept for
// compatibility with old rows; the protocol build only uses conversation
// activities.
type Activity struct {
	ID        int64           `json:"id"`
	NodeID    *int64          `json:"node_id,omitempty"`
	Worker    string          `json:"worker,omitempty"`
	Kind      string          `json:"kind,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	IsError   bool            `json:"is_error"`
	Summary   string          `json:"summary,omitempty"`
	Detail    string          `json:"-"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`

	InputTokens      *int `json:"input_tokens,omitempty"`
	OutputTokens     *int `json:"output_tokens,omitempty"`
	CacheReadTokens  *int `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens *int `json:"cache_write_tokens,omitempty"`

	SourceTaskID int64 `json:"source_task_id,omitempty"`
	Inherited    bool  `json:"inherited,omitempty"`
	MainSeg      *int  `json:"main_seg,omitempty"`
}

type ModelTokenStat struct {
	Model            string `json:"model"`
	Calls            int    `json:"calls"`
	InputTokens      int64  `json:"input_tokens"`
	OutputTokens     int64  `json:"output_tokens"`
	CacheReadTokens  int64  `json:"cache_read_tokens"`
	CacheWriteTokens int64  `json:"cache_write_tokens"`
}

func utf8Clean(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}

// jsonbClean makes JSON acceptable to PostgreSQL jsonb. Go's encoder writes NUL
// bytes inside strings as \u0000, which is valid JSON but jsonb rejects with
// SQLSTATE 22P05 (unsupported Unicode escape sequence). Tool output captured by
// checkpoints can carry NUL from binary analysis, so strip it from decoded
// strings before re-encoding. Numbers go through json.Number to keep int64
// values (e.g. nanosecond run IDs) exact.
func jsonbClean(b []byte) []byte {
	if len(b) == 0 || !json.Valid(b) {
		return []byte("{}")
	}
	if !bytes.Contains(b, []byte(`\u0000`)) {
		return b
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return []byte("{}")
	}
	cleanJSONNUL(&v)
	out, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return out
}

func cleanJSONNUL(v *any) {
	switch x := (*v).(type) {
	case string:
		*v = strings.ReplaceAll(x, "\x00", "")
	case []any:
		for i := range x {
			cleanJSONNUL(&x[i])
		}
	case map[string]any:
		for k, val := range x {
			cleanJSONNUL(&val)
			delete(x, k)
			x[strings.ReplaceAll(k, "\x00", "")] = val
		}
	}
}
