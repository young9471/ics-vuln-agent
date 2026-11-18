package db

import (
	"testing"
)

func TestProbeKeyForIsStableAndOutcomeInsensitive(t *testing.T) {
	base := map[string]any{
		"kind": "p5-live", "spec": "codesys", "host": "192.168.1.20",
		"port": 2455, "action": "code 0x0106", "code": "0x0106",
		"request": "0106", "response": "", "status": "pending", "grade": "live",
	}
	first := probeKeyFor(base)
	if first == "" {
		t.Fatal("probe key must not be empty")
	}
	// Outcome changes (status/grade/reason/created_at) must not change identity.
	updated := map[string]any{}
	for k, v := range base {
		updated[k] = v
	}
	updated["status"] = "ok"
	updated["grade"] = "live"
	updated["reason"] = "verified"
	updated["created_at"] = "2026-11-05T12:00:00Z"
	if got := probeKeyFor(updated); got != first {
		t.Fatalf("outcome change must keep identity: %s != %s", got, first)
	}
	// A different action is a different probe.
	other := map[string]any{}
	for k, v := range base {
		other[k] = v
	}
	other["action"] = "code 0x0107"
	if got := probeKeyFor(other); got == first {
		t.Fatal("different action must derive a different key")
	}
}
