package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (s *Server) auditRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") ||
			r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions ||
			strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}
		aw := &auditResponseWriter{ResponseWriter: w}
		next.ServeHTTP(aw, r)
		status := aw.status
		if status == 0 {
			status = http.StatusOK
		}
		p, _ := principalFrom(r.Context())
		_ = s.insertAudit(r, p, status, nil)
	})
}

func (s *Server) auditAuth(r *http.Request, username, role, action string, success bool) {
	detail, _ := json.Marshal(map[string]any{"action": action, "success": success})
	status := http.StatusOK
	if !success {
		status = http.StatusUnauthorized
	}
	_ = s.insertAudit(r, principal{Username: username, Role: role}, status, detail)
}

func (s *Server) insertAudit(r *http.Request, p principal, status int, detail json.RawMessage) error {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	if detail == nil {
		detail = json.RawMessage(`{}`)
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	var uid *int64
	if p.ID > 0 {
		uid = &p.ID
	}
	return s.m.pg.InsertAudit(&db.AuditEntry{
		UserID: uid, Username: p.Username, Role: p.Role,
		Method: r.Method, Path: r.URL.Path, Status: status, IP: ip, Detail: detail,
	})
}
