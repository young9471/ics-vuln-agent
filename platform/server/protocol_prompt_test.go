package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/protocol-agent/db"
)

func TestSubagentPromptAutoSpec(t *testing.T) {
	c := &db.ProtocolCase{ID: 1, Name: "case"}
	p := buildProtocolSubagentPrompt(c, "P5", "", "", 1, t.TempDir(), "findings.json", "tools", "python", "tshark", "", "")
	if !strings.Contains(p, "auto（未指定") {
		t.Fatal("empty spec should be rendered as auto")
	}
	if !strings.Contains(p, "findings_path") {
		t.Fatal("findings_path missing")
	}
}

func TestSubagentPromptIncludesAnalyzerContext(t *testing.T) {
	c := &db.ProtocolCase{ID: 1, Name: "case"}
	block := "- analyzer_bundle: C:\\bundle\n- ghidra_analyze: C:\\bundle\\analyzeHeadless.bat\n"
	p := buildProtocolSubagentPrompt(c, "P4", "", "", 1, t.TempDir(), "findings.json", "tools", "python", "tshark", "", block)
	if !strings.Contains(p, "analyzer_bundle: C:\\bundle") {
		t.Fatal("analyzer bundle missing from P4 prompt")
	}
	if !strings.Contains(p, "ghidra_analyze: C:\\bundle\\analyzeHeadless.bat") {
		t.Fatal("ghidra path missing from P4 prompt")
	}
}

func TestMasterPromptVulnAware(t *testing.T) {
	base := &db.ProtocolCase{ID: 1, Name: "case"}
	p6 := buildProtocolAgentPrompt(base, "tools", "python", "tshark")
	if !strings.Contains(p6, "P1→P6") || strings.Contains(p6, "P1→P9") {
		t.Fatal("default case should target P1-P6 only")
	}
	if strings.Contains(p6, "V2 漏洞挖掘阶段") {
		t.Fatal("vuln rules must not leak into non-vuln cases")
	}

	vuln := &db.ProtocolCase{ID: 2, Name: "vuln-case", Config: []byte(`{"vuln_enabled":true}`)}
	p9 := buildProtocolAgentPrompt(vuln, "tools", "python", "tshark")
	if !strings.Contains(p9, "P1→P9") || !strings.Contains(p9, "V2 漏洞挖掘阶段") {
		t.Fatal("vuln-enabled case should get P7-P9 instructions")
	}
	if !strings.Contains(p9, "P6 通过后启动 P7") {
		t.Fatal("resume guidance (P6 → P7) missing")
	}
}

func TestPhaseNextHintVulnAware(t *testing.T) {
	if h := protocolPhaseNextHint("P6", true, false); !strings.Contains(h, "六阶段全部通过") {
		t.Fatalf("non-vuln P6 pass hint wrong: %s", h)
	}
	if h := protocolPhaseNextHint("P6", true, true); !strings.Contains(h, "执行 P7") {
		t.Fatalf("vuln P6 pass hint should point to P7: %s", h)
	}
	for _, ph := range []string{"P7", "P8", "P9"} {
		if h := protocolPhaseNextHint(ph, false, true); !strings.Contains(h, "门 "+protocolPhaseGate(ph)) {
			t.Fatalf("%s fail hint missing gate guidance: %s", ph, h)
		}
	}
	if h := protocolPhaseNextHint("P9", true, true); !strings.Contains(h, "P1-P9 全部通过") {
		t.Fatalf("P9 pass hint wrong: %s", h)
	}
}
