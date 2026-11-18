package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/protocol-agent/config"
)

// protocolAnalyzerInfo is the static-analysis toolchain handed to a phase
// sub-agent. The toolchain page and a running agent used to resolve tools
// independently, which let the UI say "available" while the agent's shell could
// not find the same binary. Resolving once here keeps the prompt honest.
type protocolAnalyzerInfo struct {
	BundleDir  string
	ILSpyPath  string
	GhidraPath string
	JavaHome   string
	DotnetRoot string
	GhidraHome string
}

func (s *Server) protocolAnalyzerInfo() protocolAnalyzerInfo {
	return resolveProtocolAnalyzers(s.protocolToolsDir(), config.AnalyzerBundleDir(), os.Getenv("GHIDRA_HOME"))
}

// resolveProtocolAnalyzers checks the same locations as the toolchain page:
// tools/bin, the optional offline bundle, GHIDRA_HOME, and PATH. It returns
// absolute paths so the agent can call them directly instead of guessing.
func resolveProtocolAnalyzers(toolsDir, bundleDir, ghidraHome string) protocolAnalyzerInfo {
	info := protocolAnalyzerInfo{
		BundleDir:  strings.TrimSpace(bundleDir),
		JavaHome:   strings.TrimSpace(os.Getenv("JAVA_HOME")),
		DotnetRoot: strings.TrimSpace(os.Getenv("DOTNET_ROOT")),
		GhidraHome: strings.TrimSpace(ghidraHome),
	}

	var ilspy []string
	if toolsDir != "" {
		ilspy = append(ilspy,
			filepath.Join(toolsDir, "bin", "ilspycmd.exe"),
			filepath.Join(toolsDir, "bin", "ilspycmd"),
			filepath.Join(toolsDir, "ilspycmd.exe"),
			filepath.Join(toolsDir, "ilspycmd"),
		)
	}
	if info.BundleDir != "" {
		ilspy = append(ilspy,
			filepath.Join(info.BundleDir, "ilspycmd", "ilspycmd.exe"),
			filepath.Join(info.BundleDir, "ilspycmd", "ilspycmd"),
		)
	}
	info.ILSpyPath = firstExecutablePath(ilspy...)
	if info.ILSpyPath == "" {
		for _, name := range []string{"ilspycmd", "ilspycmd.exe"} {
			if p, err := exec.LookPath(name); err == nil {
				info.ILSpyPath = p
				break
			}
		}
	}

	var ghidra []string
	if info.GhidraHome != "" {
		ghidra = append(ghidra,
			filepath.Join(info.GhidraHome, "support", "analyzeHeadless.bat"),
			filepath.Join(info.GhidraHome, "support", "analyzeHeadless"),
		)
	}
	if info.BundleDir != "" {
		ghidra = append(ghidra,
			filepath.Join(info.BundleDir, "ghidra", "ghidra_12.2_PUBLIC", "support", "analyzeHeadless.bat"),
		)
		for _, pattern := range []string{
			filepath.Join(info.BundleDir, "ghidra", "*", "support", "analyzeHeadless.bat"),
			filepath.Join(info.BundleDir, "ghidra", "*", "support", "analyzeHeadless"),
		} {
			matches, _ := filepath.Glob(pattern)
			sort.Strings(matches)
			ghidra = append(ghidra, matches...)
		}
	}
	info.GhidraPath = firstExecutablePath(ghidra...)
	if info.GhidraPath == "" {
		for _, name := range []string{"analyzeHeadless", "analyzeHeadless.bat"} {
			if p, err := exec.LookPath(name); err == nil {
				info.GhidraPath = p
				break
			}
		}
	}
	return info
}

func firstExecutablePath(candidates ...string) string {
	for _, p := range candidates {
		if executableExists(p) {
			return p
		}
	}
	return ""
}

// promptBlock is injected into the P4 task header. Keep it factual: the agent
// should know what is installed, what each backend is for, and that the Python
// wrappers auto-discover the bundle themselves.
func (a protocolAnalyzerInfo) promptBlock() string {
	lines := []string{
		"- analyzer_bundle: " + valueOr(a.BundleDir, "未找到"),
		"- ilspycmd: " + valueOr(a.ILSpyPath, "未安装（仅 .NET 程序集需要）"),
		"- ghidra_analyze: " + valueOr(a.GhidraPath, "未安装（复杂原生 PE/ELF 将回退到 capstone）"),
	}
	var env []string
	if a.JavaHome != "" {
		env = append(env, "JAVA_HOME="+a.JavaHome)
	}
	if a.DotnetRoot != "" {
		env = append(env, "DOTNET_ROOT="+a.DotnetRoot)
	}
	if a.GhidraHome != "" {
		env = append(env, "GHIDRA_HOME="+a.GhidraHome)
	}
	if len(env) > 0 {
		lines = append(lines, "- analyzer_env: "+strings.Join(env, "; "))
	}
	lines = append(lines,
		"- 说明: ilspycmd 只适用于 .NET；Ghidra 适用于原生 PE/ELF 的复杂 xref/符号恢复。",
		"- 说明: ghidra_analyze.py 和 dotnet_analyze.py 会自动发现离线分析器包，不依赖 PATH。",
	)
	return strings.Join(lines, "\n") + "\n"
}

func valueOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
