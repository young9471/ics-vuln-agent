package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/protocol-agent/db"
)

func gateCase(t *testing.T, findings string) (*Runner, *db.ProtocolCase, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), []byte(findings), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Runner{}, &db.ProtocolCase{ID: 1}, dir
}

func TestGateRequiresLiveOrDocumentedDegradation(t *testing.T) {
	failed := `{"probes":[{"kind":"p5-live","status":"failed","grade":"live"}]}`
	r, c, dir := gateCase(t, failed)
	if g := r.EvaluateGate(c, dir, "P5"); g.Passed {
		t.Fatal("failed probe must not pass gate E")
	}
	// A P5 run also needs cross-evidence and final merged records.
	liveNoRecon := `{"probes":[{"kind":"p5-live","status":"ok","grade":"live"}]}`
	r, c, dir = gateCase(t, liveNoRecon)
	if g := r.EvaluateGate(c, dir, "P5"); g.Passed {
		t.Fatal("live probe without reconciliation/final records must not pass gate E")
	}
	live := `{"probes":[{"kind":"p5-live","status":"ok","grade":"live"}],
	  "notes":[{"kind":"code-reconciliation","pairs":[{"code":"0x01","verdict":"matched"}]}],
	  "function_codes":[{"code":"0x01","verdict":"matched","source":"traffic+static","label":"read"}]}`
	r, c, dir = gateCase(t, live)
	if g := r.EvaluateGate(c, dir, "P5"); !g.Passed {
		t.Fatalf("live probe + reconciliation + final record should pass: %+v", g)
	}
	degraded := `{"probes":[{"kind":"p5-degraded","status":"offline","grade":"inferred","reason":"device offline"}],
	  "notes":[{"kind":"code-reconciliation","payload":{"pairs":[{"code":"0x02","verdict":"traffic-only"}]}}],
	  "frame_formats":[{"magic":"aa","header_size":8,"frames":3,"verdict":"traffic-only"}]}`
	r, c, dir = gateCase(t, degraded)
	if g := r.EvaluateGate(c, dir, "P5"); !g.Passed {
		t.Fatalf("documented degradation should pass: %+v", g)
	}
}

func TestGateRequiresTrafficOutputOrStateMachine(t *testing.T) {
	framesOnly := `{"frame_formats":[{"magic":"aa","header_size":8,"frames":3}]}`
	r, c, dir := gateCase(t, framesOnly)
	if g := r.EvaluateGate(c, dir, "P3"); g.Passed {
		t.Fatal("frames alone must not pass gate C anymore")
	}
	withCodes := `{"frame_formats":[{"magic":"aa","header_size":8,"frames":3}],"function_codes":[{"code":"0x01","source":"traffic","evidence":"pcap frame 4"}]}`
	r, c, dir = gateCase(t, withCodes)
	if g := r.EvaluateGate(c, dir, "P3"); !g.Passed {
		t.Fatalf("frames + traffic codes should pass: %+v", g)
	}
	withSession := `{"frame_formats":[{"magic":"aa","header_size":8,"frames":3}],"notes":[{"kind":"session-model","payload":{}}]}`
	r, c, dir = gateCase(t, withSession)
	if g := r.EvaluateGate(c, dir, "P3"); !g.Passed {
		t.Fatalf("frames + session model should pass: %+v", g)
	}
}

func TestGateRequiresSourcedCodesAndConfirmedFrames(t *testing.T) {
	badCodes := `{"function_codes":[{"code":"0x01","evidence":""}]}`
	r, c, dir := gateCase(t, badCodes)
	if g := r.EvaluateGate(c, dir, "P4"); g.Passed {
		t.Fatal("code without evidence must not pass gate D")
	}
	goodCodes := `{"function_codes":[{"code":"0x01","source":"static-instruction","rva":"0x1000","instruction":"mov byte ptr [eax], 0x01","evidence":"dll RVA 0x1000"}]}`
	r, c, dir = gateCase(t, goodCodes)
	if g := r.EvaluateGate(c, dir, "P4"); !g.Passed {
		t.Fatalf("sourced code should pass: %+v", g)
	}
	weakCodes := `{"function_codes":[{"code":"0x01","source":"static-instruction","rva":"0x1000"},{"code":"0x02","evidence":"unlocated"}]}`
	r, c, dir = gateCase(t, weakCodes)
	if g := r.EvaluateGate(c, dir, "P4"); g.Passed {
		t.Fatal("less than 60% sourced codes must not pass gate D")
	}
	badFrames := `{"frame_formats":[{"magic":"aa","frames":0}]}`
	r, c, dir = gateCase(t, badFrames)
	if g := r.EvaluateGate(c, dir, "P3"); g.Passed {
		t.Fatal("zero-frame format must not pass gate C")
	}
	goodFrames := `{"frame_formats":[{"magic":"aa","header_size":8,"frames":3}],"function_codes":[{"code":"0x01","source":"traffic","evidence":"pcap frame 3"}]}`
	r, c, dir = gateCase(t, goodFrames)
	if g := r.EvaluateGate(c, dir, "P3"); !g.Passed {
		t.Fatalf("confirmed frame + traffic output should pass: %+v", g)
	}
}

func TestGateDCountsStaticCodesOnly(t *testing.T) {
	trafficOnly := `{"function_codes":[{"code":"0x01","source":"traffic","traffic_hits":3},{"code":"0x02","source":"traffic","evidence":"pcap frame 2"}]}`
	r, c, dir := gateCase(t, trafficOnly)
	if g := r.EvaluateGate(c, dir, "P4"); g.Passed {
		t.Fatal("traffic-only codes must not satisfy the static gate")
	}
	mixed := `{"function_codes":[{"code":"0x01","source":"traffic","traffic_hits":3},{"code":"0x02","source":"static-instruction","rva":"0x1000"}]}`
	r, c, dir = gateCase(t, mixed)
	g := r.EvaluateGate(c, dir, "P4")
	if !g.Passed {
		t.Fatalf("one static instruction code should pass gate D: %+v", g)
	}
	if got := g.Evidence["static_codes"]; got != 1 {
		t.Fatalf("static_codes=%v, want 1 (traffic-only code must be excluded)", got)
	}
}

func TestGateRejectsMalformedFindings(t *testing.T) {
	r, c, dir := gateCase(t, `{"comm_assets":{"path":"a"}}`)
	if g := r.EvaluateGate(c, dir, "P1"); g.Passed || g.Evidence["validation_error"] == nil {
		t.Fatalf("malformed findings should fail with validation error: %+v", g)
	}
}

// Static (offline) cases must not be required to run campaigns: no device, no
// packets — gate H only demands terminal hypothesis states; fuzz hypotheses
// land as inconclusive/fuzz-deferred-live. Live cases still need ≥1 campaign.
func TestGateHStaticVsLiveCampaignRequirement(t *testing.T) {
	allTerminal := `{"vuln_hypotheses":[
		{"id":"H-1","state":"confirmed"},
		{"id":"H-2","state":"inconclusive","verdict":"fuzz-deferred-live"}]}`
	r, c, dir := gateCase(t, allTerminal)
	c.Mode = "static"
	if g := r.EvaluateGate(c, dir, "P8"); !g.Passed {
		t.Fatalf("static case with terminal hypotheses should pass gate H without campaigns: %+v", g)
	}
	r, c, dir = gateCase(t, allTerminal)
	c.Mode = "live"
	if g := r.EvaluateGate(c, dir, "P8"); g.Passed {
		t.Fatal("live case without campaigns must not pass gate H")
	}
	withCampaign := `{"vuln_hypotheses":[{"id":"H-1","state":"confirmed"}],"campaigns":[{"campaign_id":"C-1"}]}`
	r, c, dir = gateCase(t, withCampaign)
	c.Mode = "live"
	if g := r.EvaluateGate(c, dir, "P8"); !g.Passed {
		t.Fatalf("live case with campaigns should pass: %+v", g)
	}
	pending := `{"vuln_hypotheses":[{"id":"H-1","state":"pending"}]}`
	r, c, dir = gateCase(t, pending)
	c.Mode = "static"
	if g := r.EvaluateGate(c, dir, "P8"); g.Passed {
		t.Fatal("static case with non-terminal hypotheses must not pass gate H")
	}
}

func TestCodeEvidenceKinds(t *testing.T) {
	instruction, traffic := codeEvidenceKinds(map[string]any{
		"source": "static-instruction + pcap cross-check", "rva": "0x5972", "traffic_hits": 1,
	})
	if !instruction || !traffic {
		t.Fatalf("expected instruction+traffic, got %v/%v", instruction, traffic)
	}
	instruction, traffic = codeEvidenceKinds(map[string]any{"evidence": "unlocated"})
	if instruction || traffic {
		t.Fatalf("bare evidence must not count: %v/%v", instruction, traffic)
	}
	for _, ev := range []string{"WBCComm.dll@1002f5bb", "MbComms.dll!0x091b1", "RVA 0x5972"} {
		instruction, traffic = codeEvidenceKinds(map[string]any{"evidence": ev})
		if !instruction || traffic {
			t.Fatalf("legacy address evidence %q not recognized: %v/%v", ev, instruction, traffic)
		}
	}
}

func TestReportPrefixAndEvidenceRefs(t *testing.T) {
	if got := reportPrefix("01_通信文件清单与架构"); got != "01" {
		t.Fatalf("reportPrefix=%q", got)
	}
	if got := reportPrefix("03 帧格式详解"); got != "03" {
		t.Fatalf("reportPrefix=%q", got)
	}
	if got := reportPrefix("010_extra"); got != "" {
		t.Fatalf("numeric suffix should not be a prefix: %q", got)
	}
	idx := newEvidenceIndex()
	idx.ids["asset"][1] = true
	idx.ids["code"][42] = true
	idx.addKey("asset", `C:/app/comm.dll`)
	idx.addKey("code", "0x106")
	idx.addKey("frame", "tpkt+service")
	idx.addKey("field", "m1")
	refs, invalid := collectEvidenceRefs(
		"see [code:42], [asset:1], [code:99], [code:0x0106], [asset:C:/app/comm.dll], [frame:tpkt+service], [field:m1]",
		idx)
	if len(refs) != 6 || invalid != 1 {
		t.Fatalf("refs=%v invalid=%d", refs, invalid)
	}
}

func TestReconciliationAudit(t *testing.T) {
	data := map[string]json.RawMessage{
		"function_codes": json.RawMessage(`[
			{"code":"0x01","verdict":"matched"},
			{"code":"0x02","verdict":"traffic-only"}
		]`),
		"notes": json.RawMessage(`[
			{"kind":"code-reconciliation","pairs":[
				{"code":"0x1","verdict":"matched"},
				{"code":"0x02","verdict":"static-only"}
			]}
		]`),
	}
	codes, pairs, missing, mismatched := reconciliationAudit(data)
	if codes != 2 || pairs != 2 || missing != 0 || mismatched != 1 {
		t.Fatalf("codes=%d pairs=%d missing=%d mismatched=%d", codes, pairs, missing, mismatched)
	}
	// A final code without any pair is uncovered.
	data["notes"] = json.RawMessage(`[{"kind":"code-reconciliation","pairs":[]}]`)
	_, _, missing, _ = reconciliationAudit(data)
	if missing != 2 {
		t.Fatalf("missing=%d want 2 when pairs are absent", missing)
	}
}

func TestReportSemanticAudit(t *testing.T) {
	findings := &db.ProtocolFindings{
		Codes: []*db.ProtocolFunctionCode{
			{ID: 1, CodeKey: "0x1", Grade: "traffic", Payload: json.RawMessage(`{"verdict":"matched"}`)},
			{ID: 2, CodeKey: "0x2", Grade: "live", Payload: json.RawMessage(`{"verdict":"conflicting"}`)},
			{ID: 3, CodeKey: "0x3", Grade: "static"},
		},
		Probes: []*db.ProtocolProbe{{ID: 1745, ProbeKey: "abc123"}},
	}
	idx := buildEvidenceIndex(findings)
	doc := "## 功能码表\n证据 [code:0x1] [code:2]"
	codes, covered, liveCodes, conflicts, degraded, issues := reportSemanticAudit(doc, findings, idx)
	if codes != 3 || covered != 2 || liveCodes != 1 || conflicts != 1 || degraded != 0 {
		t.Fatalf("codes=%d covered=%d live=%d conflicts=%d degraded=%d", codes, covered, liveCodes, conflicts, degraded)
	}
	if len(issues) != 2 {
		t.Fatalf("expected live-probe and conflict-marker issues, got %v", issues)
	}
	doc = "## 功能码表（待验证）\n[code:0x1] [code:0x2] [probe:1745]"
	_, _, _, _, _, issues = reportSemanticAudit(doc, findings, idx)
	if len(issues) != 0 {
		t.Fatalf("complete evidence should pass, got %v", issues)
	}

	// A documented degradation must be stated explicitly rather than implied live.
	findings.Probes = append(findings.Probes, &db.ProtocolProbe{
		ID: 2000, ProbeKey: "deg", Kind: "p5-degraded", Status: "offline",
		Payload: json.RawMessage(`{"reason":"device offline"}`),
	})
	_, _, _, _, degraded, issues = reportSemanticAudit(doc, findings, idx)
	if degraded != 1 || len(issues) != 1 {
		t.Fatalf("degraded=%d issues=%v, want one degradation issue", degraded, issues)
	}
	_, _, _, _, _, issues = reportSemanticAudit(doc+" 降级/离线", findings, idx)
	if len(issues) != 0 {
		t.Fatalf("explicit degradation note should pass, got %v", issues)
	}
}

func TestPreferReportUsesApprovedThenLatest(t *testing.T) {
	now := time.Now()
	olderLong := &db.ProtocolReport{DocType: "01_old", Content: strings.Repeat("x", 1000), Version: 1, UpdatedAt: now.Add(-time.Hour)}
	latestShort := &db.ProtocolReport{DocType: "01_new", Content: "short", Version: 1, UpdatedAt: now}
	if !preferReport(latestShort, olderLong) {
		t.Fatal("latest updated report must beat a longer stale variant")
	}
	approvedOld := &db.ProtocolReport{DocType: "01_approved", Content: "short", Version: 2, ApprovedVersion: 2, UpdatedAt: now.Add(-2 * time.Hour)}
	if !preferReport(approvedOld, latestShort) {
		t.Fatal("currently-approved report must win over a newer unapproved one")
	}
}

func TestReconciliationAuditCanonicalSynonyms(t *testing.T) {
	data := map[string]json.RawMessage{
		"function_codes": json.RawMessage(`[
			{"code":"0x2101","verdict":"confirmed"},
			{"code":"0x110b","verdict":"unverified"},
			{"code":"0x1003(hyp)","verdict":"refuted"}
		]`),
		"notes": json.RawMessage(`[{"kind":"code-reconciliation","items":[
			{"code":"0x2101","verdict":"matched"},
			{"code":"0x110b","verdict":"consistent"},
			{"code":"0x1003(hyp)","verdict":"consistent"}
		]}]`),
	}
	codes, pairs, missing, mismatched := reconciliationAudit(data)
	if codes != 3 || pairs != 3 || missing != 0 || mismatched != 0 {
		t.Fatalf("codes=%d pairs=%d missing=%d mismatched=%d", codes, pairs, missing, mismatched)
	}
}

func TestInvalidEvidenceRefs(t *testing.T) {
	findings := &db.ProtocolFindings{
		Codes:  []*db.ProtocolFunctionCode{{ID: 1, CodeKey: "0x1"}},
		Frames: []*db.ProtocolFrame{{ID: 2, FrameKey: "traffic-frame"}},
		Fields: []*db.ProtocolFieldMap{{ID: 3, MapKey: "static-request"}},
		Probes: []*db.ProtocolProbe{{ID: 4, ProbeKey: "probe-key"}},
	}
	content := "[code:0x1] [frame:traffic-frame] [field:static-request] " +
		"[probe:probe-key] [probe:0x2101] [frame:tcp:5562 client->plc]"
	bad := InvalidEvidenceRefs(content, findings)
	if len(bad) != 2 {
		t.Fatalf("invalid refs=%v want 2", bad)
	}
}
