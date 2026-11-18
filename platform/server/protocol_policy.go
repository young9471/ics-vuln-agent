package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/protocol-agent/db"
)

// Protocol agents run with ModeDefault instead of bypass: every non-read-only
// tool reaches the policy callback, which enforces the case authorization.
// This is a technical guard on top of the prompt rules.

var (
	protocolNetworkClients = regexp.MustCompile(`(?i)\b(nc|ncat|netcat|socat|telnet|ssh|scp|ftp|tftp|curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b`)
	protocolDestructive    = regexp.MustCompile(`(?i)(\bmkfs(\.\w+)?\b|\bdd\s+if=|\bformat\s+[a-z]:|factory\s*reset|\berase\b|\bflash\b|\breboot\b|\bshutdown\b|\breg\s+delete\b)`)
	protocolShellSocket    = regexp.MustCompile(`(?i)\b(python|py|python3)\b[^\n]*(\bsocket\b|\bpyserial\b|\bparamiko\b|\bmodbus\b|\brequests\.|\burllib\b|\bhttp\.client\b|\bhttpx\b|\bwebsocket|\bftplib\b|\bsmtplib\b|\basyncio\.open_connection)`)
	// Inline interpreters make the command text impossible to reason about;
	// read-only phases must run vetted script files instead.
	protocolInlineInterpreter = regexp.MustCompile(`(?i)(^|\s)(python3?|py)(\.exe)?\s+-[cm]\b|\bpowershell(\.exe)?\b[^\n]*\s-(c|command)\b|\bcmd(\.exe)?\s+/c\b|\b(bash|sh)\s+-c\b|\bnode(\.exe)?\s+-e\b`)
)

var protocolSafeTools = map[string]bool{
	"Read": true, "LS": true, "Glob": true, "Grep": true,
	"TodoWrite": true, "Skill": true, "TaskOutput": true, "TaskStop": true,
	"TaskList": true, "Monitor": true, "Sleep": true, "WebFetch": true, "WebSearch": true,
}

var protocolBrowserReadTools = map[string]bool{
	"browser_navigate": true, "browser_navigate_back": true, "browser_snapshot": true,
	"browser_take_screenshot": true, "browser_console_messages": true,
	"browser_network_requests": true, "browser_network_request": true,
	"browser_tabs": true, "browser_wait_for": true, "browser_find": true, "browser_close": true,
}

func (s *Server) protocolMainPolicy() (permission.Mode, permission.CanUseTool, []string) {
	deny := func(_ context.Context, toolName string, _ json.RawMessage, _ permission.Context) permission.Decision {
		return permission.Denied("协议主控只负责编排，不允许直接使用 " + toolName + "；请把执行交给阶段子 Agent。")
	}
	return permission.ModeDefault, deny, []string{"Bash", "Write", "Edit", "NotebookEdit"}
}

func (s *Server) protocolSubagentPolicy(c *db.ProtocolCase, phase, workdir string) (permission.Mode, permission.CanUseTool, []string) {
	auth := strings.ToLower(strings.TrimSpace(c.Authorization))
	if auth == "" {
		auth = "read-only"
	}
	phase = strings.ToUpper(strings.TrimSpace(phase))
	wdAbs, _ := filepath.Abs(workdir)
	deny := func(tool, reason string) permission.Decision {
		msg := fmt.Sprintf("授权级别 %s 拒绝 %s：%s", auth, tool, reason)
		s.emitProtocolEvent(c.ID, phase, "error", "授权拒绝: "+msg, map[string]any{
			"authorization": auth, "tool": tool, "reason": reason,
		})
		return permission.Denied(msg)
	}
	allow := func() permission.Decision { return permission.Allowed() }

	cb := func(_ context.Context, toolName string, input json.RawMessage, _ permission.Context) permission.Decision {
		if protocolSafeTools[toolName] {
			return allow()
		}
		switch toolName {
		case "Write", "Edit", "MultiEdit", "NotebookEdit":
			if !protocolPathInside(input, wdAbs) {
				return deny(toolName, "只能写入案例工作目录，禁止修改安装目录或系统路径")
			}
			return allow()
		case "Bash":
			var in struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal(input, &in)
			ok, reason := authorizeProtocolBash(auth, phase, in.Command)
			if !ok {
				return deny("Bash", reason)
			}
			return allow()
		}
		if strings.HasPrefix(toolName, "mcp__browser__") {
			short := strings.TrimPrefix(toolName, "mcp__browser__")
			if auth == "read-only" && !protocolBrowserReadTools[short] {
				return deny(toolName, "浏览器交互可能改变设备/网页状态；read-only 只允许导航、快照和读取")
			}
			return allow()
		}
		// Unknown non-read-only tool: fail closed.
		return deny(toolName, "该工具未被授权列表允许")
	}
	return permission.ModeDefault, cb, nil
}

func protocolPathInside(input json.RawMessage, workdir string) bool {
	var in struct {
		FilePath string `json:"file_path"`
	}
	_ = json.Unmarshal(input, &in)
	if strings.TrimSpace(in.FilePath) == "" {
		return false
	}
	p := in.FilePath
	if !filepath.IsAbs(p) {
		p = filepath.Join(workdir, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(workdir, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

// authorizeProtocolBash is a command-level guard. Read-only commands are split
// into shell segments and each segment must pass on its own, so an allowed
// prefix cannot smuggle a denied command behind ;, &&, |, backticks or $(...).
// The P5 read-only whitelist is anchored to the interpreter + script token.
// Arbitrary Python can still evade text matching in write+ phases, so production
// deployments must additionally isolate device-network egress.
func authorizeProtocolBash(auth, phase, command string) (bool, string) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return false, "命令为空"
	}
	if auth == "destructive" || auth == "full" {
		return true, ""
	}
	if protocolDestructive.MatchString(cmd) {
		return false, "命令包含复位/擦除/刷写/关机等破坏性动作，需要 destructive 或 full 授权"
	}
	if auth == "write" {
		return true, ""
	}

	// read-only
	for _, seg := range splitShellSegments(cmd) {
		if ok, reason := authorizeReadOnlySegment(phase, seg); !ok {
			return false, reason
		}
	}
	return true, ""
}

func authorizeReadOnlySegment(phase, segment string) (bool, string) {
	seg := strings.TrimSpace(segment)
	if seg == "" {
		return true, ""
	}
	low := strings.ToLower(seg)
	if protocolInlineInterpreter.MatchString(seg) {
		return false, "read-only 下禁止内联解释器（python -c/-m、powershell -Command、cmd /c、bash -c、node -e）；请把脚本写入案例工作目录后执行"
	}
	if strings.EqualFold(strings.TrimSpace(phase), "P5") {
		switch {
		case startsWithScript(seg, "client_harness.py"):
			for _, action := range []string{"identify", "hello", "poll", "info"} {
				if regexp.MustCompile(`\b` + action + `\b`).MatchString(low) {
					return true, ""
				}
			}
			return false, "P5 read-only 只允许 client_harness identify/hello/poll/info；code/session 或自定义探针需要 write 及以上授权"
		case startsWithScript(seg, "probe_dsl.py"):
			if strings.Contains(low, "--execute") {
				return false, "P5 read-only 只允许 probe_dsl.py --dry-run；--execute 需要 write 及以上授权"
			}
			return true, ""
		case startsWithScript(seg, "capture.py"):
			return true, "" // passive capture or TCP connect probe
		case startsWithExe(seg, "tshark", "capinfos", "editcap"):
			return true, ""
		}
		return false, "P5 read-only 只允许只读 client_harness 动作和被动抓包；自定义探针/脚本需要 write 及以上授权"
	}
	if protocolNetworkClients.MatchString(seg) {
		return false, "read-only 下禁止 nc/socat/ssh/telnet/curl 等可发送任意数据的网络客户端"
	}
	if protocolShellSocket.MatchString(seg) {
		return false, "read-only 下禁止内联 Python 网络/socket 代码；请使用只读脚本或提高授权"
	}
	return true, ""
}

// splitShellSegments splits a command on unquoted shell separators, including
// command substitution, so every executable segment is authorized separately.
func splitShellSegments(cmd string) []string {
	cmd = strings.ReplaceAll(cmd, "$(", "; ")
	cmd = strings.ReplaceAll(cmd, "<(", "; ")
	cmd = strings.ReplaceAll(cmd, ">(", "; ")
	var out []string
	var b strings.Builder
	var quote rune
	for _, r := range cmd {
		if quote != 0 {
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			b.WriteRune(r)
		case ';', '\n', '|', '&', '`':
			if seg := strings.TrimSpace(b.String()); seg != "" {
				out = append(out, seg)
			}
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if seg := strings.TrimSpace(b.String()); seg != "" {
		out = append(out, seg)
	}
	return out
}

func tokenBase(tok string) string {
	tok = strings.Trim(tok, `"'`)
	tok = strings.ReplaceAll(tok, "\\", "/")
	if i := strings.LastIndex(tok, "/"); i >= 0 {
		tok = tok[i+1:]
	}
	return strings.ToLower(tok)
}

func isPythonExe(tok string) bool {
	switch tokenBase(tok) {
	case "python", "python3", "py", "python.exe", "py.exe":
		return true
	}
	return false
}

// startsWithScript requires the first executable token to be a Python
// interpreter and its first positional argument to be one of names.
func startsWithScript(seg string, names ...string) bool {
	fields := strings.Fields(seg)
	if len(fields) == 0 || !isPythonExe(fields[0]) {
		return false
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "-") {
			continue
		}
		base := tokenBase(f)
		for _, name := range names {
			if base == name {
				return true
			}
		}
		return false
	}
	return false
}

func startsWithExe(seg string, names ...string) bool {
	fields := strings.Fields(seg)
	if len(fields) == 0 {
		return false
	}
	base := tokenBase(fields[0])
	for _, name := range names {
		if base == name || base == name+".exe" {
			return true
		}
	}
	return false
}
