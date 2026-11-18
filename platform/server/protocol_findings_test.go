package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRunFindings(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func countSection(t *testing.T, path, section string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	var list []json.RawMessage
	if err := json.Unmarshal(m[section], &list); err != nil {
		t.Fatal(err)
	}
	return len(list)
}

func TestMergeProtocolRunFindingsParallelSections(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(canonical, []byte(`{"schema":"x","comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"probes":[],"notes":[],"phases":[],"pitfalls_hit":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p1 := writeRunFindings(t, dir, "p1.json", `{"comm_assets":[{"path":"a.dll","score":9}],"notes":[{"kind":"p1"}],"phases":[{"phase":"P1","status":"done"}]}`)
	p2 := writeRunFindings(t, dir, "p2.json", `{"streams":[{"pcap":"a.pcapng","stream":1,"protocol":"tcp"}],"notes":[{"kind":"p2"}],"phases":[{"phase":"P2","status":"done"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p1, "P1"); err != nil {
		t.Fatal(err)
	}
	if err := mergeProtocolRunFindings(nil, 0, dir, p2, "P2"); err != nil {
		t.Fatal(err)
	}
	for section, want := range map[string]int{"comm_assets": 1, "streams": 1, "notes": 2, "phases": 2} {
		if got := countSection(t, canonical, section); got != want {
			t.Fatalf("%s=%d, want %d", section, got, want)
		}
	}
	p3 := writeRunFindings(t, dir, "p3.json", `{"frame_formats":[{"frame_key":"f1","frames":3,"header_size":8}],"field_maps":[{"map_key":"m1","fields":[]}],"notes":[{"kind":"p3"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p3, "P3"); err != nil {
		t.Fatal(err)
	}
	if got := countSection(t, canonical, "comm_assets"); got != 1 {
		t.Fatalf("P3 merge clobbered assets: %d", got)
	}
	if got := countSection(t, canonical, "frame_formats"); got != 1 {
		t.Fatalf("frames=%d, want 1", got)
	}
	// Retry P1: its owned section is replaced, notes stay deduplicated.
	p1b := writeRunFindings(t, dir, "p1b.json", `{"comm_assets":[{"path":"b.dll","score":8},{"path":"c.dll","score":7}],"notes":[{"kind":"p1"},{"kind":"p1b"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p1b, "P1"); err != nil {
		t.Fatal(err)
	}
	if got := countSection(t, canonical, "comm_assets"); got != 2 {
		t.Fatalf("assets=%d, want 2", got)
	}
	if got := countSection(t, canonical, "notes"); got != 4 {
		t.Fatalf("notes=%d, want 4 (p1,p2,p3,p1b)", got)
	}
}

func TestMergeKeepsTrafficAndStaticEvidence(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(canonical, []byte(`{"schema":"x","comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"probes":[],"notes":[],"phases":[],"pitfalls_hit":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// P3 and P4 run in parallel from the same empty canonical snapshot.
	p3 := writeRunFindings(t, dir, "p3.json", `{"frame_formats":[{"key":"f-traffic","frames":3,"header_size":8,"source":"traffic"}],"field_maps":[{"key":"m-traffic","source":"traffic","fields":[]}],"function_codes":[{"layer":"traffic","code":"0x01","label":"read","source":"traffic","evidence":"pcap frame 4"}]}`)
	p4 := writeRunFindings(t, dir, "p4.json", `{"frame_formats":[{"key":"f-static","frames":0,"header_size":8,"source":"static"}],"field_maps":[{"key":"m-static","source":"static","fields":[]}],"function_codes":[{"layer":"static-extract","code":"0x01","label":"read var","source":"static-instruction","rva":"0x1000","evidence":"rva 0x1000"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p3, "P3"); err != nil {
		t.Fatal(err)
	}
	if err := mergeProtocolRunFindings(nil, 0, dir, p4, "P4"); err != nil {
		t.Fatal(err)
	}
	if got := countSection(t, canonical, "function_codes"); got != 2 {
		t.Fatalf("function_codes=%d, want 2 (traffic + static)", got)
	}
	if got := countSection(t, canonical, "frame_formats"); got != 2 {
		t.Fatalf("frame_formats=%d, want 2 (traffic + static)", got)
	}
	if got := countSection(t, canonical, "field_maps"); got != 2 {
		t.Fatalf("field_maps=%d, want 2 (traffic + static)", got)
	}
	// Re-running P3 replaces its own traffic entry without touching P4's one.
	p3b := writeRunFindings(t, dir, "p3b.json", `{"function_codes":[{"layer":"traffic","code":"0x01","label":"read updated","source":"traffic","evidence":"pcap frame 9"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p3b, "P3"); err != nil {
		t.Fatal(err)
	}
	if got := countSection(t, canonical, "function_codes"); got != 2 {
		t.Fatalf("function_codes=%d after P3 retry, want 2", got)
	}
}

func TestMergeP5FinalizesIntermediateSections(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(canonical, []byte(`{"schema":"x","comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"probes":[],"notes":[],"phases":[],"pitfalls_hit":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p3 := writeRunFindings(t, dir, "p3.json", `{"frame_formats":[{"key":"f-traffic","frames":3,"source":"traffic"}],"function_codes":[{"layer":"traffic","code":"0x01","label":"read","source":"traffic"}]}`)
	p4 := writeRunFindings(t, dir, "p4.json", `{"frame_formats":[{"key":"f-static","frames":0,"source":"static"}],"function_codes":[{"layer":"static-extract","code":"0x01","label":"read var","source":"static-instruction","rva":"0x1000"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p3, "P3"); err != nil {
		t.Fatal(err)
	}
	if err := mergeProtocolRunFindings(nil, 0, dir, p4, "P4"); err != nil {
		t.Fatal(err)
	}
	// P5 rewrites the sections into one final record per code/frame and appends
	// the final session model.
	p5 := writeRunFindings(t, dir, "p5.json", `{"function_codes":[{"layer":"final","code":"0x01","label":"read","source":"traffic+static","verdict":"matched","grade":"traffic"}],"frame_formats":[{"key":"f-final","frames":3,"source":"traffic","verdict":"matched"}],"probes":[{"kind":"p5-live","status":"ok","grade":"live"}],"notes":[{"kind":"session-model-final","payload":{"transitions":[]}}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, p5, "P5"); err != nil {
		t.Fatal(err)
	}
	for section, want := range map[string]int{
		"function_codes": 1, "frame_formats": 1, "probes": 1,
	} {
		if got := countSection(t, canonical, section); got != want {
			t.Fatalf("%s=%d, want %d (P5 must replace intermediate entries)", section, got, want)
		}
	}
	b, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "session-model-final") {
		t.Fatal("final session model note was not merged")
	}
}

func TestMergeRejectsForeignSection(t *testing.T) {
	dir := t.TempDir()
	canonical := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(canonical, []byte(`{"schema":"x","comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"probes":[],"notes":[],"phases":[],"pitfalls_hit":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := writeRunFindings(t, dir, "p1.json", `{"comm_assets":[{"path":"a.dll","score":1}],"function_codes":[{"code":"0x01","evidence":"x"}]}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, run, "P1"); err == nil {
		t.Fatal("P1 writing function_codes should be rejected")
	}
}

func TestMergeRejectsMalformedFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), []byte(`{"comm_assets":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := writeRunFindings(t, dir, "bad.json", `{"comm_assets":{"path":"x"}}`)
	if err := mergeProtocolRunFindings(nil, 0, dir, run, "P1"); err == nil {
		t.Fatal("non-array comm_assets should be rejected")
	}
}
