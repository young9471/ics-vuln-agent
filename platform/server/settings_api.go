package server

import (
	"encoding/json"
	"net/http"
)

// getSettings returns the general settings the chat/agent editor needs.
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	ws := s.m.WebSearchOpts()
	writeJSON(w, 200, map[string]any{
		"llm_record":             s.m.LLMRecordEnabled(),
		"web_search_enabled":     ws.Enabled,
		"web_search_backend":     ws.Backend,
		"brave_key_set":          ws.BraveKey != "",
		"tavily_key_set":         ws.TavilyKey != "",
		"web_search_proxy":       ws.Proxy,
		"global_proxy":           s.m.GlobalProxy(),
		"python_interpreter":     s.pythonInterpreter(),
		"llm_pool_enabled":       s.m.LLMPoolEnabled(),
		"llm_pool_bind_fallback": s.m.LLMPoolBindFallback(),
		"noa_compaction":         s.m.NoaCompactionEnabled(),
	})
}

// putSettings applies the runtime toggles the UI owns. Only fields present in
// the request are changed.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LLMRecord           *bool `json:"llm_record"`
		LLMPoolEnabled      *bool `json:"llm_pool_enabled"`
		LLMPoolBindFallback *bool `json:"llm_pool_bind_fallback"`
		NoaCompaction       *bool `json:"noa_compaction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if in.LLMRecord != nil {
		if err := s.m.SetLLMRecordEnabled(*in.LLMRecord); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if in.LLMPoolEnabled != nil {
		if err := s.m.SetLLMPoolEnabled(*in.LLMPoolEnabled); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if in.LLMPoolBindFallback != nil {
		if err := s.m.SetLLMPoolBindFallback(*in.LLMPoolBindFallback); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	if in.NoaCompaction != nil {
		if err := s.m.SetNoaCompaction(*in.NoaCompaction); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	s.getSettings(w, r)
}

// pgDetectPython re-runs interpreter detection, stores and returns it.
func (s *Server) pgDetectPython(w http.ResponseWriter, r *http.Request) {
	p := detectPython()
	if p == "" {
		writeErr(w, 404, "未检测到 python(python3/python 均不在 PATH)")
		return
	}
	if err := s.m.pg.SetSetting(settingPythonInterp, p); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"python_interpreter": p})
}
