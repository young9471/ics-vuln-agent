package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/db"
	"github.com/Autumn-27/protocol-agent/llmrec"
	"github.com/Autumn-27/protocol-agent/sidequestion"
)

const (
	maxConversationRequestBytes  = 64 << 10
	maxConversationAgentKeyRunes = 120
	maxConversationTitleRunes    = 200
)

func decodeConversationRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxConversationRequestBytes)
	if err := decode(r, value); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return false
	}
	return true
}

// ---------- conversations (chat page) ----------
//
// A conversation is a ChatGPT-style thread bound to an agent key, independent of
// the pentest task graph. Turns run on ChatAgent; steps persist to
// conversation_activities and the browser POLLS ?since=cursor for live updates
// (no per-conversation SSE broadcaster needed).

type conversationListItem struct {
	*db.Conversation
	Running bool `json:"running"`
}

func (s *Server) pgListConversations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cs, err := pg.ListConversations()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	items := make([]conversationListItem, 0, len(cs))
	s.chatMu.Lock()
	for _, c := range cs {
		items = append(items, conversationListItem{Conversation: c, Running: s.chatBusy[s.convBusyKey(c.ID)]})
	}
	s.chatMu.Unlock()
	writeJSON(w, 200, map[string]any{"conversations": items})
}

func (s *Server) pgCreateConversation(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		AgentKey     string `json:"agent_key"`
		Title        string `json:"title"`
		LLMProfileID *int64 `json:"llm_profile_id"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	req.AgentKey = strings.TrimSpace(req.AgentKey)
	if req.AgentKey == "" {
		writeErr(w, 400, "agent_key 不能为空")
		return
	}
	if utf8.RuneCountInString(req.AgentKey) > maxConversationAgentKeyRunes {
		writeErr(w, 400, fmt.Sprintf("agent_key 最多 %d 个字符", maxConversationAgentKeyRunes))
		return
	}
	a, err := pg.GetAgentByKey(req.AgentKey)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if a == nil {
		writeErr(w, 404, "agent 不存在")
		return
	}
	if req.LLMProfileID != nil {
		if _, ok := s.loadProfileConfig(*req.LLMProfileID); !ok {
			writeErr(w, 400, "指定的 LLM 配置不存在或未设置 API Key")
			return
		}
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "新对话"
	}
	if utf8.RuneCountInString(title) > maxConversationTitleRunes {
		writeErr(w, 400, fmt.Sprintf("标题最多 %d 个字符", maxConversationTitleRunes))
		return
	}
	c, err := pg.CreateConversation(req.AgentKey, title, req.LLMProfileID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) pgUpdateConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		LLMProfileID *int64 `json:"llm_profile_id"` // null clears the override
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if req.LLMProfileID != nil {
		if _, ok := s.loadProfileConfig(*req.LLMProfileID); !ok {
			writeErr(w, 400, "指定的 LLM 配置不存在或未设置 API Key")
			return
		}
	}
	if err := pg.UpdateConversationProfile(c.ID, req.LLMProfileID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// convByID resolves the {id} path value to a conversation (404 if absent).
func (s *Server) convByID(w http.ResponseWriter, r *http.Request) (*db.DB, *db.Conversation, bool) {
	pg := s.pg(w)
	if pg == nil {
		return nil, nil, false
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad conversation id")
		return nil, nil, false
	}
	c, err := pg.GetConversation(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return nil, nil, false
	}
	if c == nil {
		writeErr(w, 404, "conversation not found")
		return nil, nil, false
	}
	return pg, c, true
}

func (s *Server) pgRenameConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		Title  *string `json:"title"`
		Pinned *bool   `json:"pinned"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if req.Title == nil && req.Pinned == nil {
		writeErr(w, 400, "至少需要提供 title 或 pinned")
		return
	}
	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			writeErr(w, 400, "标题不能为空")
			return
		}
		if utf8.RuneCountInString(title) > maxConversationTitleRunes {
			writeErr(w, 400, fmt.Sprintf("标题最多 %d 个字符", maxConversationTitleRunes))
			return
		}
		req.Title = &title
	}
	updated, err := pg.UpdateConversation(c.ID, db.ConversationPatch{Title: req.Title, Pinned: req.Pinned})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "conversation not found")
		return
	}
	writeJSON(w, 200, updated)
}

func (s *Server) pgDeleteConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	s.cancelConversation(c.ID)
	s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == c.ID })
	if err := pg.DeleteConversation(c.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": c.ID})
}

const maxConversationDeleteBatch = 100

type conversationDeleteItem struct {
	ID    int64  `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) cancelConversation(id int64) {
	busyKey := s.convBusyKey(id)
	s.chatMu.Lock()
	cancel := s.chatCancel[busyKey]
	s.chatMu.Unlock()
	if cancel != nil {
		cancel(agent.AbortChatStoppedByUser)
	}
}

// pgDeleteConversationsBatch deletes up to 100 selected conversations in one
// database statement. Missing ids are reported per item so a stale list does not
// hide what was actually removed.
func (s *Server) pgDeleteConversationsBatch(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var request struct {
		IDs []int64 `json:"ids"`
	}
	if !decodeConversationRequest(w, r, &request) {
		return
	}
	ids := make([]int64, 0, len(request.IDs))
	seen := make(map[int64]struct{}, len(request.IDs))
	for _, id := range request.IDs {
		if id <= 0 {
			writeErr(w, http.StatusBadRequest, "对话 id 无效")
			return
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(ids) > maxConversationDeleteBatch {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("ids 数量必须为 1-%d", maxConversationDeleteBatch))
		return
	}
	for _, id := range ids {
		s.cancelConversation(id)
		s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == id })
	}
	deleted, err := pg.DeleteConversations(ids)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	deletedSet := make(map[int64]struct{}, len(deleted))
	for _, id := range deleted {
		deletedSet[id] = struct{}{}
	}
	items := make([]conversationDeleteItem, 0, len(ids))
	for _, id := range ids {
		_, ok := deletedSet[id]
		item := conversationDeleteItem{ID: id, OK: ok}
		if !ok {
			item.Error = "conversation not found"
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) convBusyKey(id int64) string { return "conv-" + strconv.FormatInt(id, 10) }

// pgConversationMessages returns steps after ?since=cursor plus whether a turn is
// still running (so the client knows to keep polling). Same item shape as the task
// activity stream, so the frontend transcript renderer is reused verbatim.
func (s *Server) pgConversationMessages(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 200)
	s.chatMu.Lock()
	running := s.chatBusy[s.convBusyKey(c.ID)]
	s.chatMu.Unlock()

	// Incremental tail: ?since=N returns steps after id N (ASC) — used by the live
	// poll and the post-send fetch. A generous cap so a burst is never dropped.
	if sv := q.Get("since"); sv != "" {
		since, _ := strconv.ParseInt(sv, 10, 64)
		items, cursor, err := pg.ConvActivityList(c.ID, since, max(limit, 1000))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": activityDTOs(items), "cursor": cursor, "running": running, "hasMore": false})
		return
	}

	// History page (reverse pagination): no ?since → the latest page; ?before=N →
	// the page of older steps ending before id N. hasMore lets the client stop
	// loading earlier history once the top of the thread is reached.
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	items, hasMore, err := pg.ConvActivityPage(c.ID, before, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cursor := before
	if n := len(items); n > 0 {
		cursor = items[n-1].ID
	}
	writeJSON(w, 200, map[string]any{"items": activityDTOs(items), "cursor": cursor, "running": running, "hasMore": hasMore})
}

// pgConversationMsgDetail lazily returns one step's full detail blob.
func (s *Server) pgConversationMsgDetail(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	seq, ok := pathInt(r, "seq")
	if !ok {
		writeErr(w, 400, "bad seq")
		return
	}
	detail, err := pg.ConvActivityDetail(c.ID, seq)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"detail": detail})
}

// pgStopConversation aborts the in-flight run for one conversation (manual stop —
// the run/stop button in the chat UI).
func (s *Server) pgStopConversation(w http.ResponseWriter, r *http.Request) {
	_, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	busyKey := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	cancel := s.chatCancel[busyKey]
	s.chatMu.Unlock()
	if cancel == nil {
		writeJSON(w, 200, map[string]any{"status": "idle"}) // nothing running
		return
	}
	cancel(agent.AbortChatStoppedByUser)
	writeJSON(w, 200, map[string]any{"status": "stopping"})
}

// pgSendConversationMessage persists the human turn, then runs the agent in the
// background (steps stream to conversation_activities, polled by the client). One
// in-flight turn per conversation.
func (s *Server) pgSendConversationMessage(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		Message     string           `json:"message"`
		Attachments []chatAttachment `json:"attachments,omitempty"` // 方式1 上传的文件(路径相对会话工作目录)
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" && len(req.Attachments) == 0 {
		writeErr(w, 400, "消息不能为空")
		return
	}
	agentMessage, ok := s.prepareChatMentionMessage(w, msg)
	if !ok {
		return
	}
	// Same resolution as the background runner: honour the agent binding / this
	// conversation's chosen profile before falling back to the global config, so a
	// conversation that picked a valid LLM is not rejected just because no global
	// config is active.
	if s.resolveChatAgent(c) == nil {
		writeErr(w, 503, s.chatUnavailableReason())
		return
	}

	busyKey := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		writeErr(w, 409, "该会话正在处理上一条消息，请稍候")
		return
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()

	// persist + float the human turn; auto-title the thread from the first message.
	// Worker is the agent key (not "user") so the transcript stays a single lane
	// (no worker chips) — the kind='user' already right-aligns it as a human bubble.
	// With attachments, Detail carries {text, attachments} JSON so the transcript
	// renders attachment cards; without, Detail is the full text (Summary is truncated,
	// so the transcript lazy-loads Detail to show the message untruncated).
	ua := userActivityWithAttachments(c.AgentKey, msg, req.Attachments)
	ua.Summary = firstLine(msg, 200)
	if ua.Detail == "" {
		ua.Detail = msg
	}
	if _, err := pg.AppendConvActivity(c.ID, ua); err != nil {
		log.Printf("[conv %d] append user msg failed: %v", c.ID, err)
	}
	if c.Title == "" || c.Title == "新对话" {
		title := firstLine(msg, 40)
		if title == "" {
			title = "附件消息"
		}
		_ = pg.RenameConversation(c.ID, title)
	}
	_ = pg.TouchConversation(c.ID)

	// Append the uploaded files' ABSOLUTE paths so the ChatAgent opens them with its
	// Read/Bash tools. baseDir = the agent's per-session CWD (<workDir>/sessions/
	// conv-<id>/), matching chatUpload's landing dir and agent/chat.go's sessionWorkDir
	// — busyKey == convBusyKey(c.ID) == "conv-<id>" == that session id.
	baseDir := filepath.Join(s.m.dir, "sessions", busyKey)
	s.runConversation(c, composeAgentMessage(agentMessage, req.Attachments, baseDir), busyKey)
	writeJSON(w, 202, map[string]any{"status": "accepted"})
}

// runConversation runs ONE agent turn on a conversation in a background goroutine
// (each conversation is independent → parallel). Steps stream to
// conversation_activities. busyKey clears when the run ends (best-effort
// in-flight marker).
func (s *Server) runConversation(c *db.Conversation, msg, busyKey string) {
	s.runConversationWithDone(c, msg, busyKey, nil)
}

// runConversationWithDone is runConversation plus a completion callback. The
// protocol agent uses it to mark a case paused when the orchestration turn ends
// without all six gates passing.
func (s *Server) runConversationWithDone(c *db.Conversation, msg, busyKey string, done func()) {
	ctx, cancel := s.conversationRunContext(c.ID, busyKey)
	go func() {
		s.runConversationTurn(ctx, cancel, c, msg, busyKey)
		if done != nil {
			done()
		}
	}()
}

// Register cancellation before returning 202, so an immediate stop/delete cannot
// miss a background goroutine which has not started yet.
func (s *Server) conversationRunContext(id int64, busyKey string) (context.Context, context.CancelCauseFunc) {
	// Per-run cancellable context so a manual stop (pgStopConversation) can abort
	// just this session. Registered under chatMu so the stop handler can find it.
	ctx, cancel := context.WithCancelCause(withConvID(s.ctx, id))
	s.chatMu.Lock()
	s.chatCancel[busyKey] = cancel
	s.chatMu.Unlock()
	return ctx, cancel
}

func (s *Server) runConversationTurn(ctx context.Context, cancel context.CancelCauseFunc, c *db.Conversation, msg, busyKey string) {
	defer func() {
		cancel(agent.AbortChatTurnFinished)
		s.chatMu.Lock()
		delete(s.chatBusy, busyKey)
		delete(s.chatCancel, busyKey)
		s.chatMu.Unlock()
	}()
	if ctx.Err() != nil {
		return
	}
	// precedence: the conversation agent's own binding → this conversation's pin → global.
	ca := s.resolveChatAgent(c)
	if ca == nil {
		return
	}
	if strings.HasPrefix(c.AgentKey, "protocol") {
		// Orchestrator and phase agents only execute inside a case-scoped
		// delegation, where the authorization policy is attached. A detached
		// chat must not become an unrestricted shell.
		mode, cb, disallowed := s.protocolMainPolicy()
		ca = ca.WithPermission(mode, cb, disallowed)
	}
	pg := s.m.pg
	maxTurns := s.agentMaxTurns(c.AgentKey)
	maxDuration := time.Duration(s.agentRunSeconds(c.AgentKey)) * time.Second
	if maxDuration > 0 {
		var cancelHard context.CancelFunc
		ctx, cancelHard = agent.WithHardRunTimeout(ctx, maxDuration)
		defer cancelHard()
	}
	webSearch := false
	if a, err := pg.GetAgentByKey(c.AgentKey); err == nil && a != nil {
		webSearch = a.WebSearch
	}
	sessionID := s.convBusyKey(c.ID) // "conv-<id>" transcript session
	ctx = llmrec.WithWorker(ctx, c.AgentKey)
	ctx = llmrec.WithSession(ctx, sessionID)
	emit := func(rec db.Activity) {
		if _, err := pg.AppendConvActivity(c.ID, rec); err != nil {
			log.Printf("[conv %d] append activity failed: %v", c.ID, err)
		}
	}
	// On a manual stop ctx is cancelled; Chat already emits a clean "已手动停止"
	// step, so skip the raw-error entry — only surface genuine failures.
	if _, err := ca.Chat(ctx, c.AgentKey, sessionID, msg, maxTurns, maxDuration, webSearch, emit); err != nil {
		if ctx.Err() == nil {
			_, _ = pg.AppendConvActivity(c.ID, db.Activity{Worker: c.AgentKey, Kind: "text", IsError: true,
				Summary: "（出错：" + err.Error() + "）", Detail: err.Error()})
		}
	}
	_ = pg.TouchConversation(c.ID)
}

func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return s
}
