package server

import "net/http"

// Mentions are disabled in this build: the pentest asset/finding catalog they
// referenced is gone. The endpoint returns an empty page so the composer remains
// usable.
func (s *Server) searchChatMentions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": []any{}, "next_cursor": ""})
}

func (s *Server) prepareChatMentionMessage(w http.ResponseWriter, message string) (string, bool) {
	return message, true
}
