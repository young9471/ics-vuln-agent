package config

import (
	"os"
	"path/filepath"
	"strings"
)

// AnalyzerBundleDir locates the optional offline analyzer bundle. Priority:
// PROTOCOL_AGENT_ANALYZER_BUNDLE, then the standard offline/analyzers-win-x64 location
// beside the platform directory. Empty means no bundle is installed.
func AnalyzerBundleDir() string {
	if v := strings.TrimSpace(os.Getenv("PROTOCOL_AGENT_ANALYZER_BUNDLE")); v != "" {
		if isAnalyzerBundle(v) {
			return v
		}
	}
	base := BaseDir()
	candidates := []string{
		filepath.Join(base, "..", "offline", "analyzers-win-x64"),
		filepath.Join(base, "offline", "analyzers-win-x64"),
		filepath.Join(base, "..", "analyzers-win-x64"),
	}
	for _, c := range candidates {
		if isAnalyzerBundle(c) {
			if abs, err := filepath.Abs(c); err == nil {
				return abs
			}
			return c
		}
	}
	return ""
}

func isAnalyzerBundle(dir string) bool {
	markers := []string{
		filepath.Join(dir, "dotnet", "dotnet.exe"),
		filepath.Join(dir, "ilspycmd", "ilspycmd.exe"),
		filepath.Join(dir, "jdk", "bin", "java.exe"),
	}
	for _, m := range markers {
		if st, err := os.Stat(m); err == nil && !st.IsDir() {
			return true
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "ghidra", "*", "support", "analyzeHeadless.bat"))
	return len(matches) > 0
}
