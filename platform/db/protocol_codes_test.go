package db

import "testing"

func TestCodeKeyFor(t *testing.T) {
	tests := []struct {
		raw  string
		code int
		want string
	}{
		{"0x58/0x39", 0x58, "0x58/0x39"},
		{"0x58/0x0a", 0x58, "0x58/0xa"},
		{"0x0058", 0x58, "0x58"},
		{"88", 88, "0x58"},
		{" 0x5A ", 0x5a, "0x5a"},
		{"", 0x58, "0x58"},
	}
	for _, tt := range tests {
		if got := codeKeyFor(tt.raw, tt.code); got != tt.want {
			t.Fatalf("codeKeyFor(%q, %#x)=%q want %q", tt.raw, tt.code, got, tt.want)
		}
	}
}
