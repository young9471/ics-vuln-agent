package agent

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestProtocolP4PromptGhidraGuidance(t *testing.T) {
	p := BuiltinPromptSeeds()["protocol_p4"]
	for _, want := range []string{
		"复杂场景",
		"dotnet_analyze.py",
		"ghidra_analyze.py",
		"--append --timeout 600",
		"timeout_ms=600000",
		"ghidra-skipped",
		"RVA/VA/指令字节",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("P4 prompt missing %q", want)
		}
	}
}

func TestProtocolP1P4KnowledgeAndCacheGuidance(t *testing.T) {
	if p := BuiltinPromptSeeds()["protocol_p1"]; !strings.Contains(p, "protocol_lookup_knowledge") {
		t.Fatal("P1 prompt missing knowledge lookup")
	}
	p := BuiltinPromptSeeds()["protocol_p4"]
	for _, want := range []string{"protocol_lookup_knowledge", "SHA256"} {
		if !strings.Contains(p, want) {
			t.Fatalf("P4 prompt missing %q", want)
		}
	}
}

func TestProtocolP6PromptRequiresEvidenceRefs(t *testing.T) {
	p := BuiltinPromptSeeds()["protocol_p6"]
	for _, want := range []string{
		"01_通信文件清单与架构",
		"[asset:<id>]",
		"[code:<id>]",
		"[frame:<id>]",
		"[field:<id>]",
		"至少 8 个有效 ID",
		"推断/未验证",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("P6 prompt missing %q", want)
		}
	}
}

func TestProtocolPromptBudget(t *testing.T) {
	seeds := BuiltinPromptSeeds()
	total := 0
	for key, prompt := range seeds {
		n := utf8.RuneCountInString(prompt)
		total += n
		limit := 2200
		if key == "protocol" {
			limit = 1900
		}
		if n > limit {
			t.Fatalf("%s prompt is %d chars, budget %d; consolidate instead of appending", key, n, limit)
		}
	}
	if total > 13500 {
		// Budget scaled with the V2 agent set: 10000 covered the seven P1-P6
		// prompts; P7-P9 add three more agents under the same per-prompt cap.
		t.Fatalf("protocol prompts total %d chars, budget 13500; consolidate instead of appending", total)
	}
}

func TestProtocolP2PromptCaptureFirst(t *testing.T) {
	p := BuiltinPromptSeeds()["protocol_p2"]
	for _, want := range []string{
		"不要在本机磁盘上搜索",
		"pcaps/",
		"capture.py watch",
		"H1",
		"status=partial",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("P2 prompt missing %q", want)
		}
	}
}

func TestProtocolP5PromptExecutesByAuthorization(t *testing.T) {
	p := BuiltinPromptSeeds()["protocol_p5"]
	for _, want := range []string{
		"案例 authorization 就是操作者的 H2 授权范围",
		"不能降级成纯只读",
		"下载、启动/停止",
		"--execute",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("P5 prompt missing %q", want)
		}
	}
}

func TestProtocolPromptsRespectCaseMode(t *testing.T) {
	p2 := BuiltinPromptSeeds()["protocol_p2"]
	for _, want := range []string{
		"mode=live",
		"mode=static",
		"禁止启动",
	} {
		if !strings.Contains(p2, want) {
			t.Fatalf("P2 prompt missing %q", want)
		}
	}
	p5 := BuiltinPromptSeeds()["protocol_p5"]
	for _, want := range []string{
		"mode=static",
		"不连接设备",
		"p5-degraded",
	} {
		if !strings.Contains(p5, want) {
			t.Fatalf("P5 prompt missing %q", want)
		}
	}
	main := BuiltinPromptSeeds()["protocol"]
	if !strings.Contains(main, "P2 按案例 mode 执行") || !strings.Contains(main, "交叉佐证") {
		t.Fatal("main prompt missing mode or cross-evidence rules")
	}
}

func TestProtocolPromptsSplitTrafficAndStaticAnalysis(t *testing.T) {
	p3 := BuiltinPromptSeeds()["protocol_p3"]
	for _, want := range []string{
		"P3「流量分析」",
		"source=\"traffic\"",
		"function_codes",
		"不要读 P4 静态",
	} {
		if !strings.Contains(p3, want) {
			t.Fatalf("P3 prompt missing %q", want)
		}
	}
	p4 := BuiltinPromptSeeds()["protocol_p4"]
	for _, want := range []string{
		"P4「静态分析」",
		"source=\"static\"",
		"frames=0",
		"field_maps",
		"不要读 P3 流量",
	} {
		if !strings.Contains(p4, want) {
			t.Fatalf("P4 prompt missing %q", want)
		}
	}
	p5 := BuiltinPromptSeeds()["protocol_p5"]
	for _, want := range []string{
		"交叉佐证",
		"code-reconciliation",
		"single-source",
		"session-model-final",
		"verdict",
	} {
		if !strings.Contains(p5, want) {
			t.Fatalf("P5 prompt missing %q", want)
		}
	}
	p6 := BuiltinPromptSeeds()["protocol_p6"]
	for _, want := range []string{
		"code-reconciliation",
		"待验证",
		"最终合并",
	} {
		if !strings.Contains(p6, want) {
			t.Fatalf("P6 prompt missing %q", want)
		}
	}
}
