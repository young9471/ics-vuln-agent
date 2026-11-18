// Package protocol anchors protocol-case workspaces and evaluates the
// deterministic phase gates. Analysis itself is performed by the protocol main
// agent and its P1-P9 sub-agents; this package never runs a phase on its own.
package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

var phaseOrder = []string{"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9"}

var gateOf = map[string]string{"P1": "A", "P2": "B", "P3": "C", "P4": "D", "P5": "E", "P6": "F", "P7": "G", "P8": "H", "P9": "I"}

// Runner owns the fixed paths a case needs: the work directory, the Python tool
// directory, and the resolved interpreter/tshark executables handed to the
// sub-agents so they do not have to rediscover them.
type Runner struct {
	db       *db.DB
	toolsDir string
	runsDir  string
	python   string
	tshark   string
	spec     string
}

func New(d *db.DB, toolsDir, runsDir, python, tshark, spec string) *Runner {
	// Windows' CreateProcess (used by the agents' Bash/Python tools) does not
	// reliably resolve a bare "tshark"/"python" through PATH; resolve once to an
	// absolute path so sub-agents can call the executable directly.
	if p, err := exec.LookPath(tshark); err == nil {
		tshark = p
	} else {
		for _, p := range []string{
			`C:\Program Files\Wireshark\tshark.exe`,
			`C:\Program Files (x86)\Wireshark\tshark.exe`,
		} {
			if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
				tshark = p
				break
			}
		}
	}
	if p, err := exec.LookPath(python); err == nil {
		python = p
	}
	return &Runner{db: d, toolsDir: toolsDir, runsDir: runsDir, python: python, tshark: tshark, spec: spec}
}

// Workdir returns the case work directory, creating it on demand. It is the
// stable anchor for findings.json, pcaps/, docs/ and uploaded artifacts.
func (r *Runner) Workdir(c *db.ProtocolCase) string {
	if c == nil {
		return r.runsDir
	}
	if w := strings.TrimSpace(c.Workdir); w != "" {
		_ = os.MkdirAll(w, 0o755)
		return w
	}
	w := filepath.Join(r.runsDir, fmt.Sprintf("case-%d", c.ID))
	_ = os.MkdirAll(w, 0o755)
	return w
}

// Pcaps returns the same case pcap set the P2 gate uses.
func (r *Runner) Pcaps(c *db.ProtocolCase) []string {
	if c == nil {
		return nil
	}
	return r.collectPcaps(c, parseConfig(c.Config), r.Workdir(c))
}

func (r *Runner) ToolsDir() string { return r.toolsDir }
func (r *Runner) RunsDir() string  { return r.runsDir }
func (r *Runner) Python() string   { return r.python }
func (r *Runner) Tshark() string   { return r.tshark }
func (r *Runner) Spec() string     { return r.spec }

// ActivePhaseOrder returns the phases this case must complete. V2 vulnerability
// phases (P7-P9) only count when the case opted in via config.vuln_enabled, so
// pure reverse-engineering cases keep their P1-P6 completion semantics.
func (r *Runner) ActivePhaseOrder(caseID int64) []string {
	order := phaseOrder
	if c, err := r.db.GetProtocolCase(caseID); err == nil && c != nil {
		if enabled, _ := parseConfig(c.Config)["vuln_enabled"].(bool); !enabled {
			order = phaseOrder[:6]
		}
	}
	return order
}

// AllPhasesPass reports whether every phase is currently pass. The agent-driven
// path updates one phase per delegation, so it needs this explicit check to
// decide when the case is complete.
func (r *Runner) AllPhasesPass(caseID int64) bool {
	phases, err := r.db.ListProtocolPhases(caseID)
	if err != nil {
		return false
	}
	passed := map[string]bool{}
	for _, p := range phases {
		if p.Status == "pass" {
			passed[p.Phase] = true
		}
	}
	for _, p := range r.ActivePhaseOrder(caseID) {
		if !passed[p] {
			return false
		}
	}
	return true
}

// collectPcaps returns every existing pcap referenced by the case config or
// uploaded into <workdir>/pcaps. Gate B uses the same list the agents see.
func (r *Runner) collectPcaps(c *db.ProtocolCase, cfg map[string]any, workdir string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(workdir, p)
		}
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			return
		}
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	if p := configString(cfg["pcap"]); p != "" {
		add(p)
	}
	if gold, ok := cfg["golden_artifacts"].(map[string]any); ok {
		keys := make([]string, 0, len(gold))
		for k := range gold {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if strings.Contains(strings.ToLower(k), "pcap") || strings.HasSuffix(strings.ToLower(strAny(gold[k])), ".pcap") || strings.HasSuffix(strings.ToLower(strAny(gold[k])), ".pcapng") {
				add(strAny(gold[k]))
			}
		}
	}
	if entries, err := os.ReadDir(filepath.Join(workdir, "pcaps")); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			low := strings.ToLower(e.Name())
			if strings.HasSuffix(low, ".pcap") || strings.HasSuffix(low, ".pcapng") || strings.HasSuffix(low, ".cap") {
				add(filepath.Join(workdir, "pcaps", e.Name()))
			}
		}
	}
	return out
}

func (r *Runner) readFindings(workdir string) map[string]json.RawMessage {
	b, err := os.ReadFile(filepath.Join(workdir, "findings.json"))
	if err != nil {
		return map[string]json.RawMessage{}
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil {
		return map[string]json.RawMessage{}
	}
	return obj
}

func parseConfig(raw json.RawMessage) map[string]any {
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return out
}

// ParseCaseConfig exposes the case-config decoding for the server layer (e.g.
// the vuln_enabled opt-in check for P7-P9).
func ParseCaseConfig(raw json.RawMessage) map[string]any { return parseConfig(raw) }

func configString(v any) string { return strings.TrimSpace(strAny(v)) }

func objectList(raw json.RawMessage) []map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out []map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func strAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func intAny(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}
