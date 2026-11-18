package server

import "testing"

func TestAuthorizeProtocolBash(t *testing.T) {
	cases := []struct {
		auth, phase, cmd string
		ok               bool
	}{
		{"read-only", "P5", "python tools/client_harness.py --spec wago --host 1.2.3.4 identify", true},
		{"read-only", "P5", "python tools/client_harness.py --spec wago --host 1.2.3.4 code 0x0106", false},
		{"read-only", "P5", "python custom_probe.py", false},
		{"read-only", "P5", "python tools/capture.py watch --host 1.2.3.4 --out a.pcapng", true},
		{"read-only", "P5", "python tools/probe_dsl.py --spec p.json --dry-run", true},
		{"read-only", "P5", "python tools/probe_dsl.py --spec p.json --execute", false},
		// A denied command cannot hide behind an allowed segment.
		{"read-only", "P5", "python tools/client_harness.py --spec wago --host 1.2.3.4 identify; python custom_probe.py", false},
		{"read-only", "P5", "python tools/client_harness.py --spec wago --host 1.2.3.4 identify && curl http://1.2.3.4/x", false},
		{"read-only", "P5", "python tools/client_harness.py identify $(python custom_probe.py)", false},
		{"read-only", "P5", `bash -c "python tools/client_harness.py identify"`, false},
		// The whitelist anchors on the script token, not a substring.
		{"read-only", "P5", "python evil.py --arg tools/client_harness.py identify", false},
		{"read-only", "P1", `python -c "import urllib.request; urllib.request.urlopen('http://1.2.3.4')"`, false},
		{"read-only", "P1", "python tools/recon_pe.py --root C:/app --out findings.json", true},
		{"read-only", "P1", "curl http://1.2.3.4/write", false},
		{"read-only", "P1", `python -c "import socket; s=socket.create_connection(('1.2.3.4',502))"`, false},
		{"write", "P5", "python tools/client_harness.py --spec wago --host 1.2.3.4 code 0x0106", true},
		{"write", "P5", "python tools/probe_dsl.py --spec p.json --execute", true},
		{"write", "P5", "reboot", false},
		{"destructive", "P5", "reboot", true},
	}
	for _, tc := range cases {
		ok, reason := authorizeProtocolBash(tc.auth, tc.phase, tc.cmd)
		if ok != tc.ok {
			t.Fatalf("%s/%s %q => %v (%s), want %v", tc.auth, tc.phase, tc.cmd, ok, reason, tc.ok)
		}
	}
}

func TestProtocolPathInside(t *testing.T) {
	dir := t.TempDir()
	if !protocolPathInside([]byte(`{"file_path":"sub/a.py"}`), dir) {
		t.Fatal("relative path should be inside")
	}
	if protocolPathInside([]byte(`{"file_path":"../evil.py"}`), dir) {
		t.Fatal("parent path must be rejected")
	}
}
