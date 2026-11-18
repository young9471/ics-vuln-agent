package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserAuth is the internal login view; PasswordHash never leaves the server.
type UserAuth struct {
	User
	PasswordHash string
}

var ErrUserNotFound = errors.New("用户不存在")
var ErrUsernameTaken = errors.New("用户名已存在")

const userCols = `id,username,role,enabled,created_at,updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (d *DB) CountEnabledAdmins() (int, error) {
	var n int
	err := d.QueryRow(`SELECT count(*) FROM users WHERE role='admin' AND enabled`).Scan(&n)
	return n, err
}

func (d *DB) ListUsers() ([]*User, error) {
	rows, err := d.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (d *DB) GetUserByUsername(username string) (*User, error) {
	u, err := scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserByID(id int64) (*User, error) {
	u, err := scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *DB) GetUserAuth(username string) (*UserAuth, error) {
	var u UserAuth
	err := d.QueryRow(`SELECT `+userCols+`,password_hash FROM users WHERE lower(username)=lower($1)`, strings.TrimSpace(username)).
		Scan(&u.ID, &u.Username, &u.Role, &u.Enabled, &u.CreatedAt, &u.UpdatedAt, &u.PasswordHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (d *DB) CreateUser(username, passwordHash, role string) (*User, error) {
	u, err := scanUser(d.QueryRow(`INSERT INTO users(username,password_hash,role,enabled)
VALUES($1,$2,$3,true) RETURNING `+userCols, strings.TrimSpace(username), passwordHash, role))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "unique") {
		return nil, ErrUsernameTaken
	}
	return u, err
}

func (d *DB) UpdateUser(id int64, role *string, enabled *bool, passwordHash *string) (*User, error) {
	cur, err := scanUser(d.QueryRow(`SELECT `+userCols+` FROM users WHERE id=$1`, id))
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	if role != nil {
		cur.Role = *role
	}
	if enabled != nil {
		cur.Enabled = *enabled
	}
	if passwordHash != nil {
		if _, err := d.Exec(`UPDATE users SET password_hash=$2 WHERE id=$1`, id, *passwordHash); err != nil {
			return nil, err
		}
	}
	return scanUser(d.QueryRow(`UPDATE users SET role=$2,enabled=$3 WHERE id=$1 RETURNING `+userCols, id, cur.Role, cur.Enabled))
}

func (d *DB) DeleteUser(id int64) error {
	res, err := d.Exec(`DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// MigrateLegacyAdmin copies the old single-admin password hash into users once.
// The settings row is left untouched so a rollback to the older build still works.
func (d *DB) MigrateLegacyAdmin() error {
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		// Users are now the source of truth; drop the legacy hash so deleting all
		// users cannot resurrect the old admin on a later restart.
		_, _ = d.Exec(`DELETE FROM settings WHERE key='auth.password_hash'`)
		return nil
	}
	hash, ok, err := d.GetSetting("auth.password_hash")
	if err != nil || !ok || strings.TrimSpace(hash) == "" {
		return err
	}
	if _, err = d.Exec(`INSERT INTO users(username,password_hash,role,enabled)
VALUES('protocol',$1,'admin',true) ON CONFLICT DO NOTHING`, hash); err != nil {
		return err
	}
	_, _ = d.Exec(`DELETE FROM settings WHERE key='auth.password_hash'`)
	return nil
}
