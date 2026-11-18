package server

import "testing"

func TestRoleAllows(t *testing.T) {
	cases := []struct {
		role, method, path string
		want               bool
	}{
		{"admin", "POST", "/api/users", true},
		{"admin", "GET", "/api/audit", true},
		{"operator", "POST", "/api/protocol/cases", true},
		{"operator", "POST", "/api/users", false},
		{"operator", "GET", "/api/audit", false},
		{"viewer", "GET", "/api/protocol/cases", true},
		{"viewer", "POST", "/api/protocol/cases", false},
		{"viewer", "POST", "/api/auth/change-password", true},
		{"viewer", "GET", "/api/users", false},
		{"unknown", "GET", "/api/protocol/cases", false},
	}
	for _, c := range cases {
		if got := roleAllows(c.role, c.method, c.path); got != c.want {
			t.Fatalf("%s %s %s => %v, want %v", c.role, c.method, c.path, got, c.want)
		}
	}
}
