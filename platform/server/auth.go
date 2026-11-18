package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/protocol-agent/db"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash" // legacy single-admin source; migrated to users once
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	minPasswordRunes = 8
	maxPasswordBytes = 72
)

const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

type principal struct {
	ID       int64
	Username string
	Role     string
}

type principalKey struct{}

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalKey{}).(principal)
	return p, ok
}

func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

func validateUsername(username string) string {
	if username == "" || len(username) > 64 {
		return "用户名长度须为 1–64"
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			continue
		}
		return "用户名只能包含字母、数字、下划线、点和短横线"
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

type authClaims struct {
	UserID int64  `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func signJWT(key []byte, u *db.User) (string, error) {
	claims := authClaims{
		UserID: u.ID,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

func parseJWT(tokenStr string, key []byte) (*authClaims, error) {
	claims := &authClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return key, nil
	})
	if err != nil || !t.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("protocol_agent_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

func roleAllows(role, method, path string) bool {
	if role == "admin" {
		return true
	}
	if strings.HasPrefix(path, "/api/users") || strings.HasPrefix(path, "/api/audit") {
		return false
	}
	// Approval decisions are admin-only; creating requests and reading status
	// stay available to operators (campaign_runner checks status itself).
	if strings.HasPrefix(path, "/api/protocol/approvals/") && method == http.MethodPost {
		return false
	}
	// Raw completion spends LLM quota; admin-only (used by the vuln_knowledge
	// bulk classifier).
	if path == "/api/llm/complete" && method == http.MethodPost {
		return false
	}
	if role == "operator" {
		return true
	}
	if role == "viewer" {
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
			return true
		}
		return path == "/api/auth/change-password"
	}
	return false
}

// requireAuth validates the JWT, loads the current user (so role/disable changes
// take effect immediately), and enforces route-level RBAC.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			// Only login/status/init are public. change-password still goes through
			// this handler but is allowed below via roleAllows.
			if p == "/api/auth/login" || p == "/api/auth/status" || p == "/api/auth/init" || p == "/api/health" {
				h.ServeHTTP(w, r)
				return
			}
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		claims, err := parseJWT(tok, s.jwtKey)
		if err != nil {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		pg := s.m.pg
		if pg == nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		u, err := pg.GetUserByUsername(claims.Subject)
		if err != nil {
			writeErr(w, 503, errDataSourceUnavailable)
			return
		}
		if u == nil || !u.Enabled {
			writeErr(w, 401, "用户不存在或已禁用")
			return
		}
		if !roleAllows(u.Role, r.Method, p) {
			detail, _ := json.Marshal(map[string]any{"action": "rbac_denied", "method": r.Method, "path": p})
			_ = s.insertAudit(r, principal{ID: u.ID, Username: u.Username, Role: u.Role}, 403, detail)
			writeErr(w, 403, "当前角色无权执行此操作")
			return
		}
		h.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), principal{
			ID: u.ID, Username: u.Username, Role: u.Role,
		})))
	})
}

func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	n, err := pg.CountUsers()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": n > 0})
}

// POST /api/auth/init creates the first admin. The old single-admin password
// setting is migrated into users at startup; this is only for fresh databases.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	n, err := pg.CountUsers()
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if n > 0 {
		writeErr(w, 403, "管理员已初始化")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Username) == "" {
		req.Username = "protocol"
	}
	if msg := validateUsername(req.Username); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	u, err := pg.CreateUser(req.Username, string(hash), "admin")
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	tok, err := signJWT(s.jwtKey, u)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.auditAuth(r, u.Username, u.Role, "init", true)
	writeJSON(w, 200, map[string]any{"token": tok, "user": u})
}

func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	u, err := pg.GetUserAuth(strings.TrimSpace(req.Username))
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if u == nil || !u.Enabled || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		s.auditAuth(r, strings.TrimSpace(req.Username), "", "login", false)
		writeErr(w, 401, "用户名或密码错误")
		return
	}
	tok, err := signJWT(s.jwtKey, &u.User)
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	s.auditAuth(r, u.Username, u.Role, "login", true)
	writeJSON(w, 200, map[string]any{"token": tok, "user": &u.User})
}

func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFrom(r.Context())
	if !ok {
		writeErr(w, 401, "未授权")
		return
	}
	writeJSON(w, 200, map[string]any{"id": p.ID, "username": p.Username, "role": p.Role})
}

func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	p, ok := principalFrom(r.Context())
	if !ok {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	u, err := pg.GetUserAuth(p.Username)
	if err != nil || u == nil {
		writeErr(w, 401, "用户不存在")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.OldPassword)) != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	h := string(hash)
	if _, err := pg.UpdateUser(u.ID, nil, nil, &h); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}
