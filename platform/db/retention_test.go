package db

import "testing"

func TestRetentionPolicyFromEnv(t *testing.T) {
	t.Setenv("PROTOCOL_AGENT_RETENTION_LLM_RECORDS_DAYS", "30")
	t.Setenv("PROTOCOL_AGENT_RETENTION_LLM_USAGE_DAYS", "180")
	t.Setenv("PROTOCOL_AGENT_RETENTION_TOOL_USAGE_DAYS", "0")
	t.Setenv("PROTOCOL_AGENT_RETENTION_PROTOCOL_EVENTS_DAYS", "90")
	t.Setenv("PROTOCOL_AGENT_RETENTION_PCAP_DAYS", "7")
	p := RetentionPolicyFromEnv()
	if p.LLMRecordsDays != 30 || p.LLMUsageDays != 180 || p.ToolUsageDays != 0 || p.ProtocolEventDays != 90 || p.PcapDays != 7 {
		t.Fatalf("policy=%+v", p)
	}
	if !p.Enabled() {
		t.Fatal("policy should be enabled")
	}
}

func TestRetentionPolicyDisabledByDefault(t *testing.T) {
	for _, key := range []string{
		"PROTOCOL_AGENT_RETENTION_LLM_RECORDS_DAYS", "PROTOCOL_AGENT_RETENTION_LLM_USAGE_DAYS",
		"PROTOCOL_AGENT_RETENTION_TOOL_USAGE_DAYS", "PROTOCOL_AGENT_RETENTION_PROTOCOL_EVENTS_DAYS",
		"PROTOCOL_AGENT_RETENTION_PCAP_DAYS",
	} {
		t.Setenv(key, "")
	}
	if RetentionPolicyFromEnv().Enabled() {
		t.Fatal("retention must be disabled by default")
	}
}
