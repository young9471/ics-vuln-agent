package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeCaptureFilter(t *testing.T) {
	cases := []struct {
		raw, deviceIP, want string
	}{
		{"", "192.168.1.20", "host 192.168.1.20 and not arp and not icmp"},
		{"", "", "not arp and not icmp"},
		{"192.168.1.20", "", "host 192.168.1.20 and not arp and not icmp"},
		{" 192.168.1.20 ", "10.0.0.2", "host 192.168.1.20 and not arp and not icmp"},
		{"plc01.example.local", "", "host plc01.example.local and not arp and not icmp"},
		{"fe80::1", "", "host fe80::1 and not arp and not icmp"},
		{"tcp port 502", "", "tcp port 502"},
		{"host 10.0.0.5 and not arp", "", "host 10.0.0.5 and not arp"},
		{"502", "", "502"},
	}
	for _, tc := range cases {
		if got := normalizeCaptureFilter(tc.raw, tc.deviceIP); got != tc.want {
			t.Fatalf("normalizeCaptureFilter(%q,%q)=%q want %q", tc.raw, tc.deviceIP, got, tc.want)
		}
	}
}

func TestCaptureLogTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.log")
	body := "Capturing on 'WLAN'\n\ntshark: Invalid capture filter \"x\".\n0 packets captured\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := captureLogTail(path, 2)
	if !strings.Contains(got, "Invalid capture filter") || !strings.Contains(got, "0 packets captured") {
		t.Fatalf("tail missing lines: %q", got)
	}
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("tail should be trimmed: %q", got)
	}
}