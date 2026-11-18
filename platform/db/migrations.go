package db

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type schemaMigration struct {
	Version int64
	Name    string
	Up      string
	Down    string
}

func loadMigrations() ([]schemaMigration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, err
	}
	byVersion := map[int64]*schemaMigration{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".sql")
		direction := ""
		switch {
		case strings.HasSuffix(base, ".up"):
			direction, base = "up", strings.TrimSuffix(base, ".up")
		case strings.HasSuffix(base, ".down"):
			direction, base = "down", strings.TrimSuffix(base, ".down")
		default:
			continue
		}
		parts := strings.SplitN(base, "_", 2)
		version, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || version <= 0 {
			continue
		}
		item := byVersion[version]
		if item == nil {
			item = &schemaMigration{Version: version}
			byVersion[version] = item
		}
		if len(parts) > 1 {
			item.Name = parts[1]
		}
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		if direction == "up" {
			item.Up = string(body)
		} else {
			item.Down = string(body)
		}
	}
	out := make([]schemaMigration, 0, len(byVersion))
	for _, item := range byVersion {
		if strings.TrimSpace(item.Up) == "" {
			return nil, fmt.Errorf("migration %04d has no up script", item.Version)
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

func ensureMigrationTable(ctx context.Context, execer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	_, err := execer.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	return err
}

// applyMigrations runs every unapplied numbered migration. schema.sql remains
// the idempotent baseline for existing installations; new DDL should land here.
func applyMigrations(ctx context.Context, conn *sql.Conn) error {
	if err := ensureMigrationTable(ctx, conn); err != nil {
		return err
	}
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	applied := map[int64]bool{}
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var version int64
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return err
		}
		applied[version] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, migration := range migrations {
		if applied[migration.Version] {
			continue
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migration.Up); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %04d %s: %w", migration.Version, migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations(version,name,applied_at) VALUES ($1,$2,now())`,
			migration.Version, migration.Name); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaMigrationStatus returns applied versions, newest first.
func (d *DB) SchemaMigrationStatus(ctx context.Context) ([]map[string]any, error) {
	if err := ensureMigrationTable(ctx, d.DB); err != nil {
		return nil, err
	}
	rows, err := d.QueryContext(ctx, `SELECT version,name,applied_at FROM schema_migrations ORDER BY version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var version int64
		var name string
		var applied time.Time
		if err := rows.Scan(&version, &name, &applied); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"version": version, "name": name, "applied_at": applied})
	}
	return out, rows.Err()
}

// MigrateDown rolls migrations back above target using their .down.sql files.
// It is explicit and destructive: callers should back up first.
func (d *DB) MigrateDown(ctx context.Context, target int64) error {
	return withSchemaMigrationLock(ctx, d.DB, func(conn *sql.Conn) error {
		if err := ensureMigrationTable(ctx, conn); err != nil {
			return err
		}
		applied := map[int64]bool{}
		rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var version int64
			if err := rows.Scan(&version); err != nil {
				rows.Close()
				return err
			}
			applied[version] = true
		}
		if err := rows.Close(); err != nil {
			return err
		}
		migrations, err := loadMigrations()
		if err != nil {
			return err
		}
		for i := len(migrations) - 1; i >= 0; i-- {
			m := migrations[i]
			if m.Version <= target || !applied[m.Version] {
				continue
			}
			if strings.TrimSpace(m.Down) == "" {
				return fmt.Errorf("migration %04d has no down script", m.Version)
			}
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, m.Down); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("rollback %04d %s: %w", m.Version, m.Name, err)
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM schema_migrations WHERE version=$1`, m.Version); err != nil {
				_ = tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
		}
		return nil
	})
}
