package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProtocolCaseQuotaBytes(t *testing.T) {
	t.Setenv("PROTOCOL_AGENT_CASE_DISK_QUOTA_MB", "0")
	if got := protocolCaseQuotaBytes(); got != 0 {
		t.Fatalf("0 should disable quota, got %d", got)
	}
	t.Setenv("PROTOCOL_AGENT_CASE_DISK_QUOTA_MB", "2")
	if got := protocolCaseQuotaBytes(); got != 2<<20 {
		t.Fatalf("quota=%d", got)
	}
	t.Setenv("PROTOCOL_AGENT_CASE_DISK_QUOTA_MB", "bad")
	if got := protocolCaseQuotaBytes(); got != defaultCaseQuotaMB<<20 {
		t.Fatalf("invalid value should use default, got %d", got)
	}
}

func TestDirUsageBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.bin"), make([]byte, 1024), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dirUsageBytes(dir); got != 1024 {
		t.Fatalf("dirUsageBytes=%d", got)
	}
}
