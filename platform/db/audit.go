package db

import (
	"encoding/json"
	"time"
)

type AuditEntry struct {
	ID       int64           `json:"id"`
	TS       time.Time       `json:"ts"`
	UserID   *int64          `json:"user_id,omitempty"`
	Username string          `json:"username"`
	Role     string          `json:"role"`
	Method   string          `json:"method"`
	Path     string          `json:"path"`
	Status   int             `json:"status"`
	IP       string          `json:"ip"`
	Detail   json.RawMessage `json:"detail,omitempty"`
}

func (d *DB) InsertAudit(e *AuditEntry) error {
	if e.Detail == nil {
		e.Detail = json.RawMessage(`{}`)
	}
	var uid any
	if e.UserID != nil && *e.UserID > 0 {
		uid = *e.UserID
	}
	_, err := d.Exec(`INSERT INTO audit_log(user_id,username,role,method,path,status,ip,detail)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uid, e.Username, e.Role, e.Method, e.Path, e.Status, e.IP, string(e.Detail))
	return err
}

func (d *DB) ListAudit(limit, offset int) ([]*AuditEntry, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(`SELECT id,ts,user_id,COALESCE(username,''),COALESCE(role,''),COALESCE(method,''),COALESCE(path,''),status,COALESCE(ip,''),detail
FROM audit_log ORDER BY ts DESC,id DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []*AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var uid *int64
		var detail []byte
		if err := rows.Scan(&e.ID, &e.TS, &uid, &e.Username, &e.Role, &e.Method, &e.Path, &e.Status, &e.IP, &detail); err != nil {
			return nil, 0, err
		}
		e.UserID = uid
		e.Detail = json.RawMessage(detail)
		out = append(out, &e)
	}
	return out, total, rows.Err()
}
