package server

import (
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var validRoles = map[string]bool{"admin": true, "operator": true, "viewer": true}

func (s *Server) pgListUsers(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	users, err := pg.ListUsers()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"users": users})
}

func (s *Server) pgCreateUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if msg := validateUsername(strings.TrimSpace(req.Username)); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	if !validRoles[req.Role] {
		req.Role = "operator"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	u, err := pg.CreateUser(strings.TrimSpace(req.Username), string(hash), req.Role)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) pgUpdateUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	target, err := pg.GetUserByID(id)
	if err != nil || target == nil {
		writeErr(w, 404, "用户不存在")
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Enabled  *bool   `json:"enabled"`
		Password *string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	me, _ := principalFrom(r.Context())
	if req.Role != nil && !validRoles[*req.Role] {
		writeErr(w, 400, "角色必须是 admin/operator/viewer")
		return
	}
	if target.ID == me.ID && req.Enabled != nil && !*req.Enabled {
		writeErr(w, 400, "不能禁用当前登录用户")
		return
	}
	// Refuse to remove the last enabled admin.
	if target.Role == "admin" && target.Enabled {
		demote := req.Role != nil && *req.Role != "admin"
		disable := req.Enabled != nil && !*req.Enabled
		if demote || disable {
			n, _ := pg.CountEnabledAdmins()
			if n <= 1 {
				writeErr(w, 400, "不能移除最后一个启用的管理员")
				return
			}
		}
	}
	var hash *string
	if req.Password != nil {
		if msg := validatePassword(*req.Password); msg != "" {
			writeErr(w, 400, msg)
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeErr(w, 500, "密码加密失败")
			return
		}
		hs := string(h)
		hash = &hs
	}
	u, err := pg.UpdateUser(id, req.Role, req.Enabled, hash)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) pgDeleteUser(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	me, _ := principalFrom(r.Context())
	if id == me.ID {
		writeErr(w, 400, "不能删除当前登录用户")
		return
	}
	target, err := pg.GetUserByID(id)
	if err != nil || target == nil {
		writeErr(w, 404, "用户不存在")
		return
	}
	if target.Role == "admin" && target.Enabled {
		n, _ := pg.CountEnabledAdmins()
		if n <= 1 {
			writeErr(w, 400, "不能删除最后一个启用的管理员")
			return
		}
	}
	if err := pg.DeleteUser(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) pgListAudit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	items, total, err := pg.ListAudit(limit, offset)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total})
}
