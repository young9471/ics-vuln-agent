package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateProtocolCaseMode(t *testing.T) {
	dir := t.TempDir()
	pcap := filepath.Join(dir, "session.pcapng")
	if err := os.WriteFile(pcap, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		mode    string
		ip      string
		cfg     map[string]any
		base    string
		wantErr bool
	}{
		{"live with ip", "live", "192.168.1.20", nil, "", false},
		{"live without ip", "live", "  ", nil, "", true},
		{
			"static with existing pcap", "static", "",
			map[string]any{"golden_artifacts": map[string]any{"pcap_codesys": pcap}}, "", false,
		},
		{"static without pcap", "static", "", map[string]any{}, "", true},
		{
			"static with missing file", "static", "",
			map[string]any{"golden_artifacts": map[string]any{"pcap_codesys": filepath.Join(dir, "missing.pcapng")}}, "", true,
		},
		{"static relative rejected at create", "static", "", map[string]any{"pcap": "session.pcapng"}, "", true},
		{"static relative resolved at update", "static", "", map[string]any{"pcap": "session.pcapng"}, dir, false},
		{"invalid mode", "hybrid", "192.168.1.20", nil, "", true},
	}
	for _, tc := range cases {
		err := validateProtocolCaseMode(tc.mode, tc.ip, tc.cfg, tc.base)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
	}
}