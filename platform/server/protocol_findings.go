package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/protocol-agent/db"
	"github.com/Autumn-27/protocol-agent/protocol"
)

var protocolFindingsLocks sync.Map

// lockProtocolFindings serializes section merges for one case workdir. Parallel
// sub-agents write their own findings files; only this merge touches the
// canonical findings.json.
func lockProtocolFindings(workdir string) func() {
	key := filepath.Clean(workdir)
	v, _ := protocolFindingsLocks.LoadOrStore(key, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// prepareProtocolRunFindings creates an isolated findings file for one sub-agent
// run, seeded with the current canonical findings. The sub-agent only edits this
// file; the server merges it back when the run finishes.
func prepareProtocolRunFindings(workdir, runID string) (string, error) {
	ensureProtocolFindingsFile(workdir)
	runDir := filepath.Join(workdir, ".runs", safeRunDirName(runID))
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", err
	}
	unlock := lockProtocolFindings(workdir)
	b, err := os.ReadFile(filepath.Join(workdir, "findings.json"))
	unlock()
	if err != nil {
		b = []byte(`{"schema":"protocol-agent/findings/v1","phases":[],"comm_assets":[],"streams":[],"frame_formats":[],"field_maps":[],"function_codes":[],"pitfalls_hit":[],"probes":[],"notes":[]}`)
	}
	dst := filepath.Join(runDir, "findings.json")
	return dst, os.WriteFile(dst, b, 0o600)
}

func safeRunDirName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "run"
	}
	return b.String()
}

// mergeProtocolRunFindings merges one run's findings into the canonical file
// under a per-case lock and mirrors the result into PostgreSQL.
func mergeProtocolRunFindings(pg *db.DB, caseID int64, workdir, runPath, phase string) error {
	unlock := lockProtocolFindings(workdir)
	defer unlock()

	canonPath := filepath.Join(workdir, "findings.json")
	canon := map[string]json.RawMessage{}
	if b, err := os.ReadFile(canonPath); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &canon)
	}
	if canon == nil {
		canon = map[string]json.RawMessage{}
	}
	for _, k := range []string{"schema", "created"} {
		if len(canon[k]) == 0 {
			canon[k] = json.RawMessage(`""`)
		}
	}

	run := map[string]json.RawMessage{}
	if b, err := os.ReadFile(runPath); err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, &run)
	}
	// P5 is the only phase that owns final verdicts and probe/frame/field keys.
	// Normalize its contract before validation so the canonical file and the
	// DB projection use the same values the gate will compare.
	if strings.EqualFold(strings.TrimSpace(phase), "P5") {
		protocol.NormalizeP5Findings(run)
	}
	// Repair known agent-output drift before validating/merging: drop kind-less
	// notes, unwrap double-nested state-machine payloads, normalize field keys.
	if st := protocol.NormalizeFindingsMap(canon); st != (protocol.NormalizeStats{}) {
		log.Printf("[protocol-findings %s] canonical normalized: dropped=%d unwrapped=%d deduped=%d capped=%d fields=%d",
			phase, st.DroppedNotes, st.NormalizedNotes, st.DedupedNotes, st.CappedNotes, st.NormalizedFields)
	}
	if st := protocol.NormalizeFindingsMap(run); st != (protocol.NormalizeStats{}) {
		log.Printf("[protocol-findings %s] run normalized: dropped=%d unwrapped=%d deduped=%d capped=%d fields=%d",
			phase, st.DroppedNotes, st.NormalizedNotes, st.DedupedNotes, st.CappedNotes, st.NormalizedFields)
	}
	if err := protocol.ValidateFindingsMap(run); err != nil {
		return fmt.Errorf("findings 校验失败: %w", err)
	}
	if err := checkProtocolSectionOwnership(phase, canon, run); err != nil {
		return err
	}
	for _, k := range []string{"schema", "created"} {
		if v, ok := run[k]; ok && len(v) > 0 && len(canon[k]) <= 2 {
			canon[k] = v
		}
	}

	replace := map[string][]string{
		"P1": {"comm_assets"},
		"P2": {},
		"P3": {},
		"P4": {},
		// P5 finalizes the cross-validated results: its merged sections supersede
		// the intermediate P3 traffic and P4 static entries.
		"P5": {"probes", "function_codes", "frame_formats", "field_maps"},
		"P6": {},
	}
	for _, section := range replace[strings.ToUpper(strings.TrimSpace(phase))] {
		if raw, ok := run[section]; ok && len(raw) > 0 {
			canon[section] = raw
		}
	}
	// P3 (traffic) and P4 (static) may run in parallel and both describe code/
	// frame/field evidence. Merge by provenance-aware identity so neither side
	// clobbers the other.
	canon["function_codes"] = mergeRawList(canon["function_codes"], run["function_codes"], codeIdentity, true)
	canon["frame_formats"] = mergeRawList(canon["frame_formats"], run["frame_formats"], frameIdentity, true)
	canon["field_maps"] = mergeRawList(canon["field_maps"], run["field_maps"], fieldMapIdentity, true)
	// Streams may be produced by P2 or P3; merge by pcap+stream so parallel runs
	// do not clobber each other's entries.
	canon["streams"] = mergeRawList(canon["streams"], run["streams"], streamIdentity, true)
	// Notes/phases/pitfalls are append-only, deduplicated.
	canon["notes"] = mergeRawList(canon["notes"], run["notes"], rawIdentity, false)
	// Re-prune after appending so duplicate/stale notes from repeated runs do
	// not accumulate without bound.
	if st := protocol.PruneNotes(canon); st != (protocol.NormalizeStats{}) {
		log.Printf("[protocol-findings %s] notes pruned: dropped=%d unwrapped=%d deduped=%d capped=%d",
			phase, st.DroppedNotes, st.NormalizedNotes, st.DedupedNotes, st.CappedNotes)
	}
	canon["phases"] = mergeRawList(canon["phases"], run["phases"], phaseIdentity, true)
	canon["pitfalls_hit"] = mergeRawList(canon["pitfalls_hit"], run["pitfalls_hit"], rawIdentity, false)
	// V2 (P7-P9) sections: object sections replace wholesale (each run
	// re-surveys); id-keyed arrays upsert so hypothesis state transitions and
	// EXP registrations survive across runs. Ownership is enforced above.
	if raw, ok := run["device_profile"]; ok && len(raw) > 2 {
		canon["device_profile"] = raw
	}
	if raw, ok := run["vuln_surface"]; ok && len(raw) > 2 {
		canon["vuln_surface"] = raw
	}
	canon["vuln_hypotheses"] = mergeRawList(canon["vuln_hypotheses"], run["vuln_hypotheses"], idIdentity, true)
	canon["campaigns"] = mergeRawList(canon["campaigns"], run["campaigns"], idIdentity, true)
	canon["crash_samples"] = mergeRawList(canon["crash_samples"], run["crash_samples"], rawIdentity, false)
	canon["exploit_assets"] = mergeRawList(canon["exploit_assets"], run["exploit_assets"], idIdentity, true)
	canon["updated"] = json.RawMessage(`"` + time.Now().Format("2006-01-02T15:04:05") + `"`)

	if err := protocol.ValidateFindingsMap(canon); err != nil {
		return fmt.Errorf("合并后 findings 校验失败: %w", err)
	}
	out, err := json.MarshalIndent(canon, "", "  ")
	if err != nil {
		return err
	}
	tmp := canonPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, canonPath); err != nil {
		// Windows may refuse to replace an open target; the per-workdir lock makes
		// the remove+rename fallback safe for writers.
		_ = os.Remove(canonPath)
		if err := os.Rename(tmp, canonPath); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if pg != nil {
		if err := pg.ReplaceProtocolFindings(caseID, out); err != nil {
			return err
		}
	}
	return nil
}

// mergeRawList appends or upserts JSON array items. When replaceExisting is
// true, an item with the same identity replaces the earlier one in place;
// otherwise duplicates are dropped.
func mergeRawList(a, b json.RawMessage, identity func(json.RawMessage) string, replaceExisting bool) json.RawMessage {
	if len(b) == 0 {
		return a
	}
	var left, right []json.RawMessage
	_ = json.Unmarshal(a, &left)
	if err := json.Unmarshal(b, &right); err != nil {
		return a
	}
	index := make(map[string]int, len(left))
	for i, item := range left {
		index[identity(item)] = i
	}
	for _, item := range right {
		key := identity(item)
		if i, ok := index[key]; ok {
			if replaceExisting {
				left[i] = item
			}
			continue
		}
		index[key] = len(left)
		left = append(left, item)
	}
	out, _ := json.Marshal(left)
	return out
}

func rawIdentity(raw json.RawMessage) string {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err == nil {
		return b.String()
	}
	return string(raw)
}

// idIdentity keys V2 list items (hypotheses/campaigns/exploits) by their "id"
// field so re-runs update in place instead of duplicating.
func idIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		if s := findingStr(m, "id"); s != "" {
			return s
		}
	}
	return string(raw)
}

func streamIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		return fmt.Sprint(m["pcap"]) + "#" + fmt.Sprint(m["stream"])
	}
	return string(raw)
}

// findingStr returns the first non-empty string field from a findings item.
func findingStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// codeIdentity keeps traffic (P3) and static (P4) evidence for the same code
// side by side instead of overwriting each other.
func codeIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	return findingStr(m, "layer") + "#" + findingStr(m, "code") + "#" +
		strings.ToLower(findingStr(m, "source"))
}

func frameIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	if key := findingStr(m, "key", "frame_key"); key != "" {
		return "key#" + key + "#" + strings.ToLower(findingStr(m, "source"))
	}
	return fmt.Sprint(
		findingStr(m, "stream"), "#", findingStr(m, "magic"), "#", findingStr(m, "alt_magic"), "#",
		findingStr(m, "header_size"), "#", findingStr(m, "len_offset"), "#",
		findingStr(m, "len_size"), "#", findingStr(m, "endian"), "#",
		strings.ToLower(findingStr(m, "source")))
}

func fieldMapIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return string(raw)
	}
	if key := findingStr(m, "key", "map_key"); key != "" {
		return "key#" + key + "#" + strings.ToLower(findingStr(m, "source"))
	}
	return fmt.Sprint(
		findingStr(m, "direction"), "#", fmt.Sprint(m["frame_len"]), "#",
		strings.ToLower(findingStr(m, "source")))
}

func phaseIdentity(raw json.RawMessage) string {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		return fmt.Sprint(m["phase"])
	}
	return string(raw)
}

func checkProtocolSectionOwnership(phase string, canon, run map[string]json.RawMessage) error {
	allowed := map[string]map[string]bool{
		"P1": {"comm_assets": true},
		"P2": {"streams": true},
		"P3": {"frame_formats": true, "field_maps": true, "streams": true, "function_codes": true},
		"P4": {"function_codes": true, "frame_formats": true, "field_maps": true},
		"P5": {"probes": true, "function_codes": true, "frame_formats": true, "field_maps": true},
		"P6": {},
		// V2: P7 拥有画像与假设；P8 更新假设终态并记录 campaign 结果；P9 写 EXP 登记。
		"P7": {"device_profile": true, "vuln_surface": true, "vuln_hypotheses": true},
		"P8": {"vuln_hypotheses": true, "vuln_surface": true, "campaigns": true, "crash_samples": true},
		"P9": {"exploit_assets": true},
	}
	common := map[string]bool{"schema": true, "created": true, "updated": true, "notes": true, "phases": true, "pitfalls_hit": true}
	owned := allowed[strings.ToUpper(strings.TrimSpace(phase))]
	for key, raw := range run {
		if common[key] || owned[key] || rawEmpty(raw) {
			continue
		}
		if !rawEqual(canon[key], raw) {
			return fmt.Errorf("阶段 %s 不允许写入 section %s；各阶段只能修改自己负责的 findings section", phase, key)
		}
	}
	return nil
}

func rawEmpty(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]" || s == "{}" || s == `""`
}

func rawEqual(a, b json.RawMessage) bool {
	var av, bv any
	if json.Unmarshal(a, &av) == nil && json.Unmarshal(b, &bv) == nil {
		return reflect.DeepEqual(av, bv)
	}
	var ab, bb bytes.Buffer
	if json.Compact(&ab, a) != nil || json.Compact(&bb, b) != nil {
		return string(a) == string(b)
	}
	return ab.String() == bb.String()
}

func syncProtocolFindingsFile(pg *db.DB, caseID int64, workdir string) error {
	path := filepath.Join(workdir, "findings.json")
	unlock := lockProtocolFindings(workdir)
	defer unlock()
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if st := protocol.NormalizeFindingsMap(m); st != (protocol.NormalizeStats{}) {
		log.Printf("[protocol-findings sync] canonical normalized: dropped_notes=%d unwrapped_notes=%d field_items=%d",
			st.DroppedNotes, st.NormalizedNotes, st.NormalizedFields)
		if out, err := json.MarshalIndent(m, "", "  "); err == nil {
			_ = os.WriteFile(path, out, 0o600)
			b = out
		}
	}
	return pg.ReplaceProtocolFindings(caseID, b)
}
