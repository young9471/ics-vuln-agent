package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveProtocolAnalyzersFromBundle(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "analyzers")
	writeTestFile(t, filepath.Join(bundle, "ilspycmd", "ilspycmd.exe"))
	writeTestFile(t, filepath.Join(bundle, "ghidra", "ghidra_test", "support", "analyzeHeadless.bat"))

	info := resolveProtocolAnalyzers(filepath.Join(root, "tools"), bundle, "")
	if info.BundleDir != bundle {
		t.Fatalf("bundle = %q, want %q", info.BundleDir, bundle)
	}
	if info.ILSpyPath == "" {
		t.Fatal("ilspycmd in bundle was not resolved")
	}
	if info.GhidraPath == "" {
		t.Fatal("analyzeHeadless in bundle was not resolved")
	}
	block := info.promptBlock()
	for _, want := range []string{"analyzer_bundle:", "ilspycmd:", "ghidra_analyze:", "Ghidra"} {
		if !strings.Contains(block, want) {
			t.Fatalf("prompt block missing %q:\n%s", want, block)
		}
	}
}

func TestAnalyzerPromptBlockUnavailable(t *testing.T) {
	block := (protocolAnalyzerInfo{}).promptBlock()
	if !strings.Contains(block, "analyzer_bundle: 未找到") {
		t.Fatalf("missing fallback bundle notice:\n%s", block)
	}
	if !strings.Contains(block, "ghidra_analyze: 未安装") {
		t.Fatalf("missing fallback Ghidra notice:\n%s", block)
	}
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
}
