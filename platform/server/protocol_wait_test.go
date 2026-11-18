package server

import "testing"

func TestAnyPhaseFinished(t *testing.T) {
	cases := []struct {
		name    string
		initial []string
		current []string
		want    bool
	}{
		{"nothing started", nil, nil, false},
		{"still all running", []string{"P1", "P2"}, []string{"P1", "P2"}, false},
		{"one finished", []string{"P1", "P2"}, []string{"P1"}, true},
		{"both finished", []string{"P1", "P2"}, nil, true},
		{"unrelated finishing does not count", []string{"P1"}, []string{"P1", "P3"}, false},
	}
	for _, tc := range cases {
		if got := anyPhaseFinished(tc.initial, tc.current); got != tc.want {
			t.Fatalf("%s: anyPhaseFinished(%v,%v)=%v want %v", tc.name, tc.initial, tc.current, got, tc.want)
		}
	}
}

func TestEffectiveReturnOnAny(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		running  int
		explicit *bool
		want     bool
	}{
		{"default single phase waits all", 1, nil, false},
		{"default multi phase returns on any", 2, nil, true},
		{"explicit false wins", 2, &no, false},
		{"explicit true wins", 1, &yes, true},
	}
	for _, tc := range cases {
		if got := effectiveReturnOnAny(tc.running, tc.explicit); got != tc.want {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func phaseItem(phase, status string, passed bool) map[string]any {
	return map[string]any{"phase": phase, "status": status, "passed": passed}
}

func TestProtocolReadyPhases(t *testing.T) {
	cases := []struct {
		name  string
		items []map[string]any
		want  []string
	}{
		{
			"fresh case waits for P1/P2 but they are running",
			[]map[string]any{phaseItem("P1", "running", false), phaseItem("P2", "running", false)},
			nil,
		},
		{
			"P2 passed unlocks P3 while P1 runs",
			[]map[string]any{phaseItem("P1", "running", false), phaseItem("P2", "done", true), phaseItem("P3", "pending", false)},
			[]string{"P3"},
		},
		{
			"P1+P2 passed unlock both P3 and P4",
			[]map[string]any{phaseItem("P1", "pass", true), phaseItem("P2", "done", true)},
			[]string{"P3", "P4"},
		},
		{
			"failed P1 is offered as retry",
			[]map[string]any{phaseItem("P1", "fail", false), phaseItem("P2", "done", true)},
			[]string{"P1", "P3"},
		},
		{
			"P3 running does not block P4",
			[]map[string]any{phaseItem("P1", "pass", true), phaseItem("P2", "done", true), phaseItem("P3", "running", false)},
			[]string{"P4"},
		},
		{
			"P3+P4 passed unlock P5",
			[]map[string]any{phaseItem("P1", "pass", true), phaseItem("P2", "pass", true), phaseItem("P3", "pass", true), phaseItem("P4", "pass", true)},
			[]string{"P5"},
		},
		{
			"P5 passed unlocks P6",
			[]map[string]any{phaseItem("P1", "pass", true), phaseItem("P2", "pass", true), phaseItem("P3", "pass", true), phaseItem("P4", "pass", true), phaseItem("P5", "pass", true)},
			[]string{"P6"},
		},
	}
	for _, tc := range cases {
		got := protocolReadyPhases(tc.items, false)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: got %v want %v", tc.name, got, tc.want)
			}
		}
	}
}
func TestProtocolPhasePrerequisiteError(t *testing.T) {
	if err := protocolPhasePrerequisiteError("P3", map[string]string{"P2": "pass"}); err != nil {
		t.Fatalf("P3 should start after P2 passes: %v", err)
	}
	if err := protocolPhasePrerequisiteError("P6", map[string]string{"P5": "fail"}); err == nil {
		t.Fatal("P6 must not start while P5 gate failed")
	}
	if err := protocolPhasePrerequisiteError("P6", map[string]string{"P5": "running"}); err == nil {
		t.Fatal("P6 must not start while P5 is running")
	}
	if err := protocolPhasePrerequisiteError("P6", map[string]string{"P5": "pass"}); err != nil {
		t.Fatalf("P6 should start after P5 passes: %v", err)
	}
}

func TestProtocolReadyPhasesVulnEnabled(t *testing.T) {
	base := []map[string]any{
		phaseItem("P1", "pass", true), phaseItem("P2", "pass", true),
		phaseItem("P3", "pass", true), phaseItem("P4", "pass", true),
		phaseItem("P5", "pass", true), phaseItem("P6", "pass", true),
	}
	// Pure reverse-engineering cases never see P7+.
	if got := protocolReadyPhases(base, false); len(got) != 0 {
		t.Fatalf("vuln disabled: P7+ must not be offered, got %v", got)
	}
	// Opt-in cases chain P7 -> P8 -> P9 after gate F.
	if got := protocolReadyPhases(base, true); len(got) != 1 || got[0] != "P7" {
		t.Fatalf("vuln enabled: want [P7], got %v", got)
	}
	withP7 := append(append([]map[string]any(nil), base...), phaseItem("P7", "pass", true))
	if got := protocolReadyPhases(withP7, true); len(got) != 1 || got[0] != "P8" {
		t.Fatalf("after P7: want [P8], got %v", got)
	}
	if err := protocolPhasePrerequisiteError("P8", map[string]string{"P7": "fail"}); err == nil {
		t.Fatal("P8 must not start while P7 gate failed")
	}
	if err := protocolPhasePrerequisiteError("P9", map[string]string{"P7": "pass", "P8": "pass"}); err != nil {
		t.Fatalf("P9 should start after P7+P8 pass: %v", err)
	}
}
