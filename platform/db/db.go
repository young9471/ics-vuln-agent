// Package db is the PostgreSQL data source for Protocol Agent (取代旧 graph 单文件 SQLite)。
// 它打开连接、应用 schema、并 seed 内置 agent 与变量目录。
package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/protocol-agent/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = 7337741001

// maxOpenConns 是连接池上限，见 Open 里的说明。取值远低于 PostgreSQL 默认的
// max_connections=100，同时远高于应用自身的嵌套取连接深度（启动期的 schema
// advisory lock 会在持有一条连接的同时让 seedBuiltins 另取连接），不会自锁。
const maxOpenConns = 32

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection. Running pg_advisory_lock through *sql.DB is incorrect because a
// later schema or unlock call may use a different pooled PostgreSQL session.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) (err error) {
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		if _, unlockErr := conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, schemaMigrationLockKey); unlockErr != nil && err == nil {
			err = fmt.Errorf("advisory unlock: %w", unlockErr)
		}
	}()
	return action(conn)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env PROTOCOL_AGENT_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	if err := ensureDatabase(dsn); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// database/sql 默认不限制连接数：池里没有空闲连接时会无条件新建，一路顶到
	// PostgreSQL 的 max_connections（默认 100）才被拒，于是高峰期的查询拿到的是
	// `FATAL: sorry, too many clients already` 这种**错误**。封顶之后超额查询改为
	// 排队等待空闲连接——同样的负载下变成变慢而不是报错，调用方不必再去区分
	// "读不到"和"没有"。maxOpenConns 要留出余量给 psql / reset-password.sh 以及
	// 可能并存的其他实例；若 max_connections 调低过，这里也要跟着往下调。
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxOpenConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if err := applySchemaWithRetry(context.Background(), conn, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := applyMigrations(context.Background(), conn); err != nil {
			return fmt.Errorf("apply migrations: %w", err)
		}
		// Catch drift between schema.sql and migrations (e.g. an index referencing
		// a column added later by a migration) before serving traffic.
		if err := d.verifySchema(); err != nil {
			return fmt.Errorf("verify schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		if err := d.MigrateLegacyAdmin(); err != nil {
			return fmt.Errorf("migrate legacy admin: %w", err)
		}
		if err := d.CleanupLegacyBrowserTools(); err != nil {
			return fmt.Errorf("cleanup legacy browser tools: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// verifySchema confirms that objects introduced by migrations exist after the
// schema + migration pass. schema.sql is an idempotent baseline for existing
// installations while migrations carry post-baseline DDL; this check catches
// ordering drift between the two before the server starts serving.
func (d *DB) verifySchema() error {
	requiredColumns := map[string][]string{
		"protocol_probes":         {"probe_key"},
		"protocol_function_codes": {"semantic", "code_key"},
		"protocol_frames":         {"frame_key"},
		"protocol_field_maps":     {"map_key"},
	}
	for table, cols := range requiredColumns {
		rows, err := d.Query(`SELECT column_name FROM information_schema.columns
WHERE table_schema='public' AND table_name=$1`, table)
		if err != nil {
			return err
		}
		have := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			have[name] = true
		}
		rows.Close()
		for _, col := range cols {
			if !have[col] {
				return fmt.Errorf("schema drift: column %s.%s missing", table, col)
			}
		}
	}
	for _, index := range []string{"uq_protocol_probes_key", "uq_protocol_codes_key"} {
		var exists bool
		if err := d.QueryRow(`SELECT EXISTS(
SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname=$1)`, index).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("schema drift: index %s missing", index)
		}
	}
	return nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // 建行时的默认交互式 shell 开关；ON CONFLICT 不覆盖用户后续手动开关
	runSeconds            *int // 建行时的单次 run 墙钟上限(秒)；nil=用种子默认(1200)，0=不限时
}

type promptVar struct{ name, desc, example, source string }

// intp 返回 v 的指针，用于给 builtinAgent 可选字段(如 runSeconds)显式取值。
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). 内置工具不入库；这里只 seed agent + 变量目录。
var builtinAgents = []builtinAgent{
	// 智能体主控：经对话页驱动，P1-P6 协议逆向，启用漏洞挖掘后续 P7-P9。
	{"protocol", "工控脆弱性分析与利用", "assistant", "工控系统脆弱性分析与利用智能体主控：P1-P6 私有协议逆向 → P7 漏洞面测绘 → P8 验证与 Fuzz → P9 EXP 与报告；按准出门推进，解释 findings，完成语义定名与报告定稿。", nil, false, nil},
	// 阶段子 Agent：由主控 agent 通过 protocol_delegate_phase 调度。
	// role=subagent（builtin=true）→ 不出现在聊天页，只在 Agent 管理里可编辑。
	{"protocol_p1", "P1 资产侦察", "subagent", "定位上位机安装目录中的通信承载体、端口与配置线索，产出 comm_assets。", nil, false, nil},
	{"protocol_p2", "P2 流量获取", "subagent", "获取或导入覆盖协议生命周期的 pcap，判定 live/static 模式并记录流量证据。", nil, false, nil},
	{"protocol_p3", "P3 流量分析", "subagent", "仅依据 pcap/流量推断功能码语义、帧格式与字段划分，写 traffic 级证据。", nil, false, nil},
	{"protocol_p4", "P4 静态分析", "subagent", "仅依据上位机通信文件（DLL/EXE/.NET/配置）推断功能码语义、帧格式与字段划分，写 static 级证据。", nil, false, nil},
	{"protocol_p5", "P5 交叉验证", "subagent", "对 P3 流量结论与 P4 静态结论交叉佐证并合并重写最终结果，再按授权动态验证或降级。", nil, false, nil},
	{"protocol_p6", "P6 文档交付", "subagent", "消费交叉佐证结果做功能码定名与证据分级，生成四份交付文档。", nil, false, nil},
	// V2 漏洞挖掘阶段（PLAN-V2）：P7 测绘与假设、P8 验证与 Fuzz、P9 EXP 与报告。
	{"protocol_p7", "P7 漏洞面测绘", "subagent", "构建设备能力画像、查询漏洞情报、跑直判类确定性检测，产出适用性三态与结构化假设。", nil, false, nil},
	{"protocol_p8", "P8 验证与Fuzz", "subagent", "对 destructive 假设走审批后确定性验证（verify），对模糊类假设执行灰盒 Fuzz campaign 并汇总崩溃证据。", nil, false, intp(7200)},
	{"protocol_p9", "P9 EXP与报告", "subagent", "汇总定级全部漏洞结论，生成可复现 EXP 脚本与漏洞报告（含证据回溯与关联 CVE）。", nil, false, nil},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, COALESCE($6, 1200))
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	return nil
}
