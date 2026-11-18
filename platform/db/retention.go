package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RetentionPolicy controls destructive cleanup. Zero means "keep forever"; all
// values are opt-in so a fresh install never deletes data by surprise.
type RetentionPolicy struct {
	LLMRecordsDays    int
	LLMUsageDays      int
	ToolUsageDays     int
	ProtocolEventDays int
	PcapDays          int
}

func retentionDays(env string) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(env)))
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

func RetentionPolicyFromEnv() RetentionPolicy {
	return RetentionPolicy{
		LLMRecordsDays:    retentionDays("PROTOCOL_AGENT_RETENTION_LLM_RECORDS_DAYS"),
		LLMUsageDays:      retentionDays("PROTOCOL_AGENT_RETENTION_LLM_USAGE_DAYS"),
		ToolUsageDays:     retentionDays("PROTOCOL_AGENT_RETENTION_TOOL_USAGE_DAYS"),
		ProtocolEventDays: retentionDays("PROTOCOL_AGENT_RETENTION_PROTOCOL_EVENTS_DAYS"),
		PcapDays:          retentionDays("PROTOCOL_AGENT_RETENTION_PCAP_DAYS"),
	}
}

func (p RetentionPolicy) Enabled() bool {
	return p.LLMRecordsDays > 0 || p.LLMUsageDays > 0 || p.ToolUsageDays > 0 ||
		p.ProtocolEventDays > 0 || p.PcapDays > 0
}

func deleteOlderThan(ctx context.Context, d *DB, table, column string, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	res, err := d.ExecContext(ctx, fmt.Sprintf(
		`DELETE FROM %s WHERE %s < now() - make_interval(days => $1)`, table, column), days)
	if err != nil {
		return 0, fmt.Errorf("retention %s: %w", table, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ApplyRetention deletes expired ledger/event rows and returns affected counts.
// Pcap files are handled by the server because their paths are workspace-local.
func (d *DB) ApplyRetention(ctx context.Context, p RetentionPolicy) (map[string]int64, error) {
	out := map[string]int64{}
	var err error
	if out["llm_records"], err = deleteOlderThan(ctx, d, "llm_records", "ts", p.LLMRecordsDays); err != nil {
		return out, err
	}
	if out["llm_usage"], err = deleteOlderThan(ctx, d, "llm_usage", "ts", p.LLMUsageDays); err != nil {
		return out, err
	}
	if out["tool_usage"], err = deleteOlderThan(ctx, d, "tool_usage", "ts", p.ToolUsageDays); err != nil {
		return out, err
	}
	if out["protocol_events"], err = deleteOlderThan(ctx, d, "protocol_events", "created_at", p.ProtocolEventDays); err != nil {
		return out, err
	}
	return out, nil
}
