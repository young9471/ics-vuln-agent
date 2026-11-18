package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

// GateResult is the deterministic verdict for one phase. The main orchestrator
// uses it after a sub-agent returns; the sub-agent's own "pass" claim is never
// trusted without this check.
type GateResult struct {
	Phase    string         `json:"phase"`
	Gate     string         `json:"gate"`
	Status   string         `json:"status"` // pass|fail
	Passed   bool           `json:"passed"`
	Detail   string         `json:"detail"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// EvaluateGate reads the current findings.json (and reports table) and applies
// the same gate rules as the deterministic pipeline. It does not run any tool.
func (r *Runner) EvaluateGate(c *db.ProtocolCase, workdir, phase string) GateResult {
	res := GateResult{Phase: phase, Gate: gateOf[phase], Status: "fail", Evidence: map[string]any{}}
	if err := ValidateFindingsFile(workdir); err != nil {
		res.Detail = "findings 校验失败: " + err.Error()
		res.Evidence["validation_error"] = err.Error()
		return res
	}
	data := r.readFindings(workdir)
	switch phase {
	case "P1":
		assets := objectList(data["comm_assets"])
		scored := 0
		for _, a := range assets {
			if intAny(a["score"]) > 0 && strings.TrimSpace(strAny(a["path"])) != "" {
				scored++
			}
		}
		res.Evidence["scored_assets"] = scored
		res.Evidence["total_assets"] = len(assets)
		res.Detail = plural(scored, "个通信嫌疑资产（得分>0）")
		res.Passed = scored >= 1
	case "P2":
		pcaps := r.collectPcaps(c, parseConfig(c.Config), workdir)
		var totalBytes int64
		for _, p := range pcaps {
			if st, err := os.Stat(p); err == nil {
				totalBytes += st.Size()
			}
		}
		res.Evidence["pcaps"] = len(pcaps)
		res.Evidence["pcap_bytes"] = totalBytes
		res.Detail = plural(len(pcaps), "个可用 pcap")
		res.Passed = len(pcaps) >= 1 && totalBytes > 0
	case "P3":
		frames := objectList(data["frame_formats"])
		fields := objectList(data["field_maps"])
		confirmed := 0
		for _, f := range frames {
			if intAny(f["frames"]) > 0 && (intAny(f["header_size"]) > 0 || strings.TrimSpace(strAny(f["magic"])) != "") {
				confirmed++
			}
		}
		trafficCodes := 0
		for _, fc := range objectList(data["function_codes"]) {
			origin := strings.ToLower(strAny(fc["source"]) + " " + strAny(fc["layer"]))
			if strings.Contains(origin, "traffic") {
				trafficCodes++
			}
		}
		sessionModels := 0
		for _, n := range objectList(data["notes"]) {
			if strings.EqualFold(strings.TrimSpace(strAny(n["kind"])), "session-model") {
				sessionModels++
			}
		}
		res.Evidence["frame_formats"] = len(frames)
		res.Evidence["confirmed_frames"] = confirmed
		res.Evidence["field_maps"] = len(fields)
		res.Evidence["traffic_codes"] = trafficCodes
		res.Evidence["session_models"] = sessionModels
		res.Detail = fmt.Sprintf("%d 个确认帧格式（零重同步），%d 个流量功能码，%d 条会话状态机",
			confirmed, trafficCodes, sessionModels)
		// P3 must produce analysis beyond framing: at least one traffic-inferred
		// function code or a session state machine.
		res.Passed = confirmed >= 1 && (trafficCodes >= 1 || sessionModels >= 1)
	case "P4":
		// P4 is static-only: count codes with instruction-level provenance and
		// ignore traffic-only codes (those belong to P3's traffic analysis).
		codes := objectList(data["function_codes"])
		static, instruction, sourced := 0, 0, 0
		for _, fc := range codes {
			if strings.TrimSpace(strAny(fc["code"])) == "" {
				continue
			}
			hasInstruction, hasTraffic := codeEvidenceKinds(fc)
			if hasTraffic && !hasInstruction {
				continue
			}
			static++
			if hasInstruction {
				instruction++
				sourced++
			}
		}
		ratio := 0.0
		if static > 0 {
			ratio = float64(sourced) / float64(static)
		}
		res.Evidence["function_codes"] = len(codes)
		res.Evidence["static_codes"] = static
		res.Evidence["instruction_codes"] = instruction
		res.Evidence["sourced_ratio"] = ratio
		res.Detail = fmt.Sprintf("%d/%d 个静态功能码有指令级出处（%.0f%%）", sourced, static, ratio*100)
		res.Passed = static >= 1 && sourced >= 1 && ratio >= minCodeEvidenceRatio
	case "P5":
		probes := objectList(data["probes"])
		verified, degraded := 0, 0
		for _, p := range probes {
			status := strings.ToLower(strings.TrimSpace(strAny(p["status"])))
			grade := strings.ToLower(strings.TrimSpace(strAny(p["grade"])))
			kind := strings.ToLower(strings.TrimSpace(strAny(p["kind"])))
			switch status {
			case "ok", "success", "pass", "passed", "verified", "done":
				if grade == "live" {
					verified++
				}
			}
			if strings.Contains(kind, "degraded") && (status == "offline" || status == "skipped") && strings.TrimSpace(strAny(p["reason"])) != "" {
				degraded++
			}
		}
		res.Evidence["probes"] = len(probes)
		res.Evidence["verified_live_probes"] = verified
		res.Evidence["documented_degradations"] = degraded
		reconciliationNotes, reconciliationPairs := 0, 0
		for _, n := range objectList(data["notes"]) {
			if !strings.EqualFold(strings.TrimSpace(strAny(n["kind"])), "code-reconciliation") {
				continue
			}
			reconciliationNotes++
			reconciliationPairs += protocolNotePairs(n)
		}
		finalRecords := 0
		for _, section := range []string{"function_codes", "frame_formats", "field_maps"} {
			for _, item := range objectList(data[section]) {
				if strings.TrimSpace(strAny(item["verdict"])) != "" {
					finalRecords++
				}
			}
		}
		res.Evidence["reconciliation_notes"] = reconciliationNotes
		res.Evidence["reconciliation_pairs"] = reconciliationPairs
		res.Evidence["final_records"] = finalRecords
		auditCodes, auditPairs, auditMissing, auditMismatched := reconciliationAudit(data)
		res.Evidence["final_codes"] = auditCodes
		res.Evidence["reconciliation_covered"] = auditPairs
		res.Evidence["reconciliation_missing"] = auditMissing
		res.Evidence["reconciliation_mismatched"] = auditMismatched
		res.Detail = fmt.Sprintf("%d 条 live 验证 / %d 条有原因的静态降级；交叉佐证 %d 条（%d 对），最终记录 %d 条；最终码 %d 个，覆盖缺失 %d、结论不一致 %d",
			verified, degraded, reconciliationNotes, reconciliationPairs, finalRecords, auditCodes, auditMissing, auditMismatched)
		// A P5 run must cross-check traffic vs static evidence, leave final
		// merged records, and every final code must appear in the reconciliation
		// pairs with the same verdict.
		res.Passed = (verified >= 1 || degraded >= 1) && reconciliationPairs >= 1 && finalRecords >= 1 &&
			auditMissing == 0 && auditMismatched == 0
	case "P6":
		res = r.evaluateReportGate(c, workdir, res)
	case "P7":
		// Gate G: the survey is complete — capability matrix built, every
		// sub-template settled (no unknowns left), and every deterministic
		// hypothesis carries a verdict.
		profile := objectSection(data["device_profile"])
		surface := objectSection(data["vuln_surface"])
		matrix, _ := profile["matrix"].(map[string]any)
		applic, _ := surface["applicability"].(map[string]any)
		summary, _ := applic["summary"].(map[string]any)
		capsPresent := 0
		for _, row := range matrix {
			if m, ok := row.(map[string]any); ok {
				for _, via := range []string{"protocol", "service", "physical"} {
					if list, ok := m[via].([]any); ok && len(list) > 0 {
						capsPresent++
						break
					}
				}
			}
		}
		unknown := intAny(summary["unknown"])
		applicable := intAny(summary["applicable"])
		notApplicable := intAny(summary["not_applicable"])
		hypotheses := objectList(data["vuln_hypotheses"])
		pending := 0
		for _, h := range hypotheses {
			if strings.EqualFold(strings.TrimSpace(strAny(h["detection"])), "deterministic") &&
				strAny(h["state"]) == "pending" {
				pending++
			}
		}
		res.Evidence["capabilities_present"] = capsPresent
		res.Evidence["unknown_subtemplates"] = unknown
		res.Evidence["applicable"] = applicable
		res.Evidence["not_applicable"] = notApplicable
		res.Evidence["deterministic_pending"] = pending
		res.Detail = fmt.Sprintf("能力矩阵 %d 项；适用性 applicable=%d / not_applicable=%d / unknown=%d；直判类待裁决 %d 条",
			capsPresent, applicable, notApplicable, unknown, pending)
		res.Passed = capsPresent >= 1 && applic != nil && unknown == 0 &&
			(applicable+notApplicable) > 0 && pending == 0
	case "P8":
		// Gate H: every applicable hypothesis reached a terminal state; every
		// confirmed crash carries a minimized sample and a reproduction rate.
		// Static (offline) cases never execute campaigns — no device — so the
		// campaign count requirement only applies to live mode; fuzz hypotheses
		// land as inconclusive/fuzz-deferred-live instead.
		hypotheses := objectList(data["vuln_hypotheses"])
		terminal, confirmed := 0, 0
		for _, h := range hypotheses {
			switch strings.TrimSpace(strAny(h["state"])) {
			case "confirmed", "falsified", "inconclusive", "enforced", "not_applicable":
				terminal++
				if strAny(h["state"]) == "confirmed" {
					confirmed++
				}
			}
		}
		crashes := objectList(data["crash_samples"])
		crashesOK := 0
		for _, cr := range crashes {
			if strings.TrimSpace(strAny(cr["minimized_hex"])) != "" && strings.Contains(strAny(cr["repro"]), "/3") {
				crashesOK++
			}
		}
		campaigns := len(objectList(data["campaigns"]))
		isStatic := strings.EqualFold(strings.TrimSpace(c.Mode), "static")
		res.Evidence["hypotheses"] = len(hypotheses)
		res.Evidence["terminal_states"] = terminal
		res.Evidence["confirmed"] = confirmed
		res.Evidence["campaigns"] = campaigns
		res.Evidence["crashes_documented"] = crashesOK
		res.Evidence["mode"] = map[bool]string{true: "static", false: "live"}[isStatic]
		if isStatic {
			res.Detail = fmt.Sprintf("假设终态 %d/%d（confirmed=%d；static 模式不执行 campaign，fuzz 类 deferred-live）",
				terminal, len(hypotheses), confirmed)
			res.Passed = len(hypotheses) > 0 && terminal == len(hypotheses)
		} else {
			res.Detail = fmt.Sprintf("假设终态 %d/%d（confirmed=%d），campaign %d 个，崩溃留档 %d 条",
				terminal, len(hypotheses), confirmed, campaigns, crashesOK)
			res.Passed = len(hypotheses) > 0 && terminal == len(hypotheses) && campaigns >= 1
		}
	case "P9":
		// Gate I: every confirmed write/destructive finding has a registered
		// exploit and the vuln report doc landed.
		hypotheses := objectList(data["vuln_hypotheses"])
		exploits := objectList(data["exploit_assets"])
		confirmedTotal := 0
		exploitOf := map[string]bool{}
		for _, e := range exploits {
			exploitOf[strings.TrimSpace(strAny(e["hypothesis"]))] = true
		}
		needExploit, covered := 0, 0
		for _, h := range hypotheses {
			if strAny(h["state"]) != "confirmed" {
				continue
			}
			confirmedTotal++
			if r := strAny(h["risk"]); r == "write" || r == "destructive" {
				needExploit++
				if exploitOf[strings.TrimSpace(strAny(h["id"]))] {
					covered++
				}
			}
		}
		reportOK := false
		if rows, err := r.db.ListProtocolReports(c.ID); err == nil {
			for _, rep := range rows {
				if strings.HasPrefix(rep.DocType, "05") {
					reportOK = true
					break
				}
			}
		}
		res.Evidence["confirmed"] = confirmedTotal
		res.Evidence["need_exploit"] = needExploit
		res.Evidence["exploits_registered"] = len(exploits)
		res.Evidence["vuln_report"] = reportOK
		res.Detail = fmt.Sprintf("EXP 登记 %d 条；write/destructive 确认项 %d/%d 有 EXP；漏洞报告 %v",
			len(exploits), covered, needExploit, reportOK)
		res.Passed = (needExploit == covered) && reportOK && len(exploits)+len(hypotheses) > 0
	}
	if res.Passed {
		res.Status = "pass"
	}
	return res
}

func plural(n int, unit string) string {
	return strconv.Itoa(n) + " " + unit
}

// objectSection decodes an object-valued findings section (e.g. device_profile).
func objectSection(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// protocolNotePairs reads the reconciliation list from either the note's top
// level or its payload. Agents have used both "pairs" and "items" keys.
func protocolNotePairs(n map[string]any) int {
	return len(reconciliationList(n))
}

// reconciliationList extracts pairs/items from a reconciliation note, accepting
// both top-level and payload-nested shapes.
func reconciliationList(n map[string]any) []any {
	for _, key := range []string{"pairs", "items"} {
		if arr, ok := n[key].([]any); ok {
			return arr
		}
	}
	if payload, ok := n["payload"].(map[string]any); ok {
		for _, key := range []string{"pairs", "items"} {
			if arr, ok := payload[key].([]any); ok {
				return arr
			}
		}
	}
	return nil
}

const minCodeEvidenceRatio = 0.6

var (
	evidenceRefPattern = regexp.MustCompile(`\[(asset|code|frame|field|probe):([^\]\r\n]+)\]`)
	// Address spellings used by older P4 output that predates the structured
	// rva/instruction fields: dll@1002f5bb, dll!0x091b1, RVA 0x5972.
	instructionAddressPattern = regexp.MustCompile(`(?i)(?:@[0-9a-f]{4,}|![0-9a-fx]{4,}|\brva\s*[:=]?\s*0x[0-9a-f]+|\bva\s*[:=]?\s*0x[0-9a-f]+)`)
)

// codeEvidenceKinds classifies a function code as having instruction-level or
// traffic-level provenance. A bare evidence string is not enough: it must point
// at a binary address/instruction or a pcap/frame hit.
func codeEvidenceKinds(fc map[string]any) (instruction, traffic bool) {
	source := strings.ToLower(strAny(fc["source"]))
	evidence := strings.ToLower(strAny(fc["evidence"]))
	if strings.TrimSpace(strAny(fc["rva"])) != "" ||
		strings.TrimSpace(strAny(fc["va"])) != "" ||
		strings.TrimSpace(strAny(fc["instruction"])) != "" ||
		strings.TrimSpace(strAny(fc["instruction_bytes"])) != "" ||
		strings.Contains(source, "static-instruction") ||
		instructionAddressPattern.MatchString(evidence) ||
		strings.Contains(evidence, "instruction") {
		instruction = true
	}
	if intAny(fc["traffic_hits"]) > 0 ||
		strings.Contains(source, "traffic") ||
		strings.Contains(evidence, "pcap") ||
		strings.Contains(evidence, "frame") {
		traffic = true
	}
	return instruction, traffic
}

type requiredReportSpec struct {
	Prefix        string
	Name          string
	RefType       string
	KeywordGroups [][]string
}

var requiredProtocolReports = []requiredReportSpec{
	{"01", "通信文件清单与架构", "asset", [][]string{{"通信"}, {"架构", "文件清单"}}},
	{"02", "功能码表", "code", [][]string{{"功能码"}, {"证据", "出处", "等级"}}},
	{"03", "帧格式详解", "frame", [][]string{{"帧"}, {"字段", "长度", "mbap"}}},
	{"04", "字段划分", "field", [][]string{{"字段"}, {"偏移", "offset", "长度"}}},
}

func (r *Runner) evaluateReportGate(c *db.ProtocolCase, workdir string, res GateResult) GateResult {
	reports, err := r.db.ListProtocolReports(c.ID)
	if err != nil {
		res.Detail = "读取交付文档失败: " + err.Error()
		return res
	}
	res.Evidence["reports"] = len(reports)
	if len(reports) == 0 {
		count := 0
		if entries, readErr := os.ReadDir(filepath.Join(workdir, "docs")); readErr == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".md") {
					count++
				}
			}
		}
		res.Evidence["docs_on_disk"] = count
		res.Detail = "报告未同步到数据库；四份文档必须通过 protocol_write_report 或 sync 入库"
		return res
	}

	findings, err := r.db.GetProtocolFindings(c.ID)
	if err != nil {
		res.Detail = "读取 findings 证据索引失败: " + err.Error()
		return res
	}
	valid := buildEvidenceIndex(findings)

	byPrefix := map[string]*db.ProtocolReport{}
	for _, rep := range reports {
		prefix := reportPrefix(rep.DocType)
		if prefix == "" {
			prefix = reportPrefix(rep.Title)
		}
		if prefix == "" {
			continue
		}
		if old := byPrefix[prefix]; old == nil || preferReport(rep, old) {
			byPrefix[prefix] = rep
		}
	}

	issues := []string{}
	missingRefs := []string{}
	totalRefs := map[string]bool{}
	invalidRefs := 0
	for _, spec := range requiredProtocolReports {
		rep := byPrefix[spec.Prefix]
		if rep == nil {
			issues = append(issues, "缺少 "+spec.Prefix+" "+spec.Name)
			continue
		}
		content := rep.Content
		if len([]rune(content)) < 300 {
			issues = append(issues, spec.Prefix+" 内容过短")
		}
		if markdownHeadingCount(content) < 2 {
			issues = append(issues, spec.Prefix+" 缺少章节标题")
		}
		for _, group := range spec.KeywordGroups {
			if !containsAny(content, group) {
				issues = append(issues, fmt.Sprintf("%s 缺少章节关键词 %s", spec.Prefix, strings.Join(group, "/")))
				break
			}
		}
		refs, invalid := collectEvidenceRefs(content, valid)
		invalidRefs += invalid
		haveRequired := 0
		for ref := range refs {
			totalRefs[ref] = true
			if strings.HasPrefix(ref, spec.RefType+":") {
				haveRequired++
			}
		}
		if haveRequired == 0 {
			missingRefs = append(missingRefs, fmt.Sprintf("%s 缺少 [%s:<id>] 引用", spec.Prefix, spec.RefType))
		}
	}
	if len(totalRefs) < 8 {
		issues = append(issues, fmt.Sprintf("有效证据 ID 引用不足（%d/8）", len(totalRefs)))
	}
	if invalidRefs > 0 {
		issues = append(issues, fmt.Sprintf("有 %d 个引用不在本案例 findings 中", invalidRefs))
	}
	issues = append(issues, missingRefs...)

	// Semantic consistency beyond section keywords: the code table must cover
	// the final findings, live-verified codes need probe evidence, and
	// conflicting reconciliation results must be marked as unverified.
	if rep := byPrefix["02"]; rep != nil {
		codes, covered, liveCodes, conflicts, degraded, semIssues := reportSemanticAudit(rep.Content, findings, valid)
		res.Evidence["report_codes"] = codes
		res.Evidence["report_codes_covered"] = covered
		res.Evidence["report_live_codes"] = liveCodes
		res.Evidence["report_conflicting_codes"] = conflicts
		res.Evidence["report_degraded_probes"] = degraded
		issues = append(issues, semIssues...)
	}

	res.Evidence["evidence_refs"] = len(totalRefs)
	res.Evidence["invalid_refs"] = invalidRefs
	if len(missingRefs) > 0 {
		res.Evidence["missing_refs"] = missingRefs
	}
	if len(issues) > 0 {
		res.Detail = strings.Join(issues, "；")
		return res
	}
	res.Detail = fmt.Sprintf("四份文档齐全，章节与证据引用校验通过（%d 个有效 ID）", len(totalRefs))
	res.Passed = true
	return res
}

// evidenceIndex accepts both row IDs ([code:42]) and stable business keys
// ([code:0x106], [asset:<path>], [frame:<frame_key>], [field:<map_key>],
// [probe:<probe_key>]). Business keys survive findings re-syncs and resets;
// numeric IDs remain supported for compatibility with existing reports.
type evidenceIndex struct {
	ids  map[string]map[int64]bool
	keys map[string]map[string]bool
}

func newEvidenceIndex() *evidenceIndex {
	idx := &evidenceIndex{ids: map[string]map[int64]bool{}, keys: map[string]map[string]bool{}}
	for _, kind := range []string{"asset", "code", "frame", "field", "probe"} {
		idx.ids[kind] = map[int64]bool{}
		idx.keys[kind] = map[string]bool{}
	}
	return idx
}

func (idx *evidenceIndex) addKey(kind, key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	if kind == "code" {
		key = strings.ToLower(db.CodeKeyFor(key, 0))
	}
	idx.keys[kind][key] = true
}

func buildEvidenceIndex(f *db.ProtocolFindings) *evidenceIndex {
	idx := newEvidenceIndex()
	if f == nil {
		return idx
	}
	for _, a := range f.Assets {
		idx.ids["asset"][a.ID] = true
		idx.addKey("asset", a.Path)
	}
	for _, c := range f.Codes {
		idx.ids["code"][c.ID] = true
		idx.addKey("code", c.CodeKey)
	}
	for _, fr := range f.Frames {
		idx.ids["frame"][fr.ID] = true
		idx.addKey("frame", fr.FrameKey)
	}
	for _, fm := range f.Fields {
		idx.ids["field"][fm.ID] = true
		idx.addKey("field", fm.MapKey)
	}
	for _, p := range f.Probes {
		idx.ids["probe"][p.ID] = true
		idx.addKey("probe", p.ProbeKey)
	}
	return idx
}

func collectEvidenceRefs(content string, idx *evidenceIndex) (map[string]bool, int) {
	refs, invalid := collectEvidenceRefsDetailed(content, idx)
	return refs, len(invalid)
}

func collectEvidenceRefsDetailed(content string, idx *evidenceIndex) (map[string]bool, []string) {
	refs := map[string]bool{}
	invalid := []string{}
	for _, m := range evidenceRefPattern.FindAllStringSubmatch(content, -1) {
		kind := m[1]
		raw := strings.TrimSpace(m[2])
		if raw == "" {
			invalid = append(invalid, fmt.Sprintf("%s:", kind))
			continue
		}
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if !idx.ids[kind][id] {
				invalid = append(invalid, fmt.Sprintf("%s:%s", kind, raw))
				continue
			}
			refs[fmt.Sprintf("%s:%d", kind, id)] = true
			continue
		}
		key := raw
		if kind == "code" {
			key = strings.ToLower(db.CodeKeyFor(raw, 0))
		}
		if !idx.keys[kind][key] {
			invalid = append(invalid, fmt.Sprintf("%s:%s", kind, raw))
			continue
		}
		refs[fmt.Sprintf("%s:%s", kind, key)] = true
	}
	return refs, invalid
}

// InvalidEvidenceRefs returns the unique report references that cannot be
// resolved against the current findings. The report writer calls this before
// storing a document so P6 cannot persist references that Gate F would reject.
func InvalidEvidenceRefs(content string, findings *db.ProtocolFindings) []string {
	_, invalid := collectEvidenceRefsDetailed(content, buildEvidenceIndex(findings))
	if len(invalid) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(invalid))
	for _, ref := range invalid {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		out = append(out, ref)
	}
	return out
}

func reportPrefix(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '0' || s[1] < '1' || s[1] > '4' {
		return ""
	}
	if len(s) > 2 && s[2] >= '0' && s[2] <= '9' {
		return ""
	}
	return s[:2]
}

// preferReport decides which of several reports sharing a 01–04 prefix should
// be judged: the currently-approved revision wins, otherwise the most recently
// updated one. Content length is only a deterministic tie-breaker — picking the
// longest text used to let stale variants shadow the current document.
func preferReport(a, b *db.ProtocolReport) bool {
	aApproved := a.ApprovedVersion > 0 && a.ApprovedVersion == a.Version
	bApproved := b.ApprovedVersion > 0 && b.ApprovedVersion == b.Version
	if aApproved != bApproved {
		return aApproved
	}
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	return len(a.Content) > len(b.Content)
}

// reconciliationAudit compares cross-evidence pairs with the final merged code
// records. Every final code must appear in a pair with the same verdict; a
// missing verdict or pair counts as uncovered, a different verdict as mismatched.
func reconciliationAudit(data map[string]json.RawMessage) (codes, pairs, missing, mismatched int) {
	verdictByKey := map[string]string{}
	for _, fc := range objectList(data["function_codes"]) {
		key := db.CodeKeyFor(strAny(fc["code"]), intAny(fc["code"]))
		if key == "" {
			continue
		}
		verdictByKey[key] = CanonicalVerdict(strAny(fc["verdict"]))
	}
	pairByKey := map[string]string{}
	for _, n := range objectList(data["notes"]) {
		if !strings.EqualFold(strings.TrimSpace(strAny(n["kind"])), "code-reconciliation") {
			continue
		}
		for _, item := range reconciliationList(n) {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			key := db.CodeKeyFor(strAny(m["code"]), intAny(m["code"]))
			if key == "" {
				continue
			}
			pairByKey[key] = CanonicalVerdict(strAny(m["verdict"]))
		}
	}
	codes = len(verdictByKey)
	pairs = len(pairByKey)
	for key, verdict := range verdictByKey {
		pv, ok := pairByKey[key]
		if !ok || verdict == "" {
			missing++
			continue
		}
		if pv != "" && pv != verdict {
			mismatched++
		}
	}
	return
}

const minReportCodeCoverage = 0.6

// reportSemanticAudit checks that the 02 code table covers the final findings,
// that live-verified codes cite probe evidence, that conflicting reconciliation
// results are marked as unverified, and that documented degradations are stated
// explicitly instead of being presented as live results.
func reportSemanticAudit(doc string, findings *db.ProtocolFindings, idx *evidenceIndex) (codes, covered, liveCodes, conflicts, degraded int, issues []string) {
	if findings == nil || strings.TrimSpace(doc) == "" {
		return
	}
	type rec struct {
		id      int64
		key     string
		grade   string
		verdict string
	}
	byID := map[int64]rec{}
	byKey := map[string]rec{}
	for _, c := range findings.Codes {
		if c == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(c.CodeKey))
		if key == "" {
			continue
		}
		r := rec{id: c.ID, key: key, grade: strings.ToLower(strings.TrimSpace(c.Grade)), verdict: payloadVerdict(c.Payload)}
		byID[c.ID] = r
		byKey[key] = r
	}
	codes = len(byKey)
	refs, _ := collectEvidenceRefs(doc, idx)
	coveredSet := map[string]bool{}
	probeRef := false
	for ref := range refs {
		kind, val, ok := strings.Cut(ref, ":")
		if !ok {
			continue
		}
		if kind == "probe" {
			probeRef = true
			continue
		}
		if kind != "code" {
			continue
		}
		if id, err := strconv.ParseInt(val, 10, 64); err == nil {
			if r, ok := byID[id]; ok {
				coveredSet[r.key] = true
			}
		} else if r, ok := byKey[strings.ToLower(val)]; ok {
			coveredSet[r.key] = true
		}
	}
	covered = len(coveredSet)
	ratio := 0.0
	if codes > 0 {
		ratio = float64(covered) / float64(codes)
	}
	if codes > 0 && ratio < minReportCodeCoverage {
		issues = append(issues, fmt.Sprintf("02 功能码覆盖不足（%d/%d，需 ≥60%%）", covered, codes))
	}
	for _, r := range byKey {
		if r.grade == "live" {
			liveCodes++
		}
		if r.verdict == "conflicting" {
			conflicts++
		}
	}
	for _, p := range findings.Probes {
		if p == nil {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(p.Status))
		kind := strings.ToLower(strings.TrimSpace(p.Kind))
		if strings.Contains(kind, "degraded") && (status == "offline" || status == "skipped") && payloadReason(p.Payload) != "" {
			degraded++
		}
	}
	if liveCodes > 0 && !probeRef {
		issues = append(issues, fmt.Sprintf("02 含 %d 个 live 验证功能码，但未引用任何 [probe:...] 证据", liveCodes))
	}
	if conflicts > 0 && !containsAny(doc, []string{"待验证", "未验证", "冲突", "conflicting"}) {
		issues = append(issues, fmt.Sprintf("02 含 %d 个冲突结论，但未标注待验证/未验证", conflicts))
	}
	if degraded > 0 && !containsAny(doc, []string{"降级", "离线", "degraded", "offline"}) {
		issues = append(issues, fmt.Sprintf("存在 %d 条降级探针，但 02 未注明降级/离线", degraded))
	}
	return
}

func payloadReason(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return strings.TrimSpace(strAny(m["reason"]))
}

func payloadVerdict(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(strAny(m["verdict"])))
}

func markdownHeadingCount(content string) int {
	count := 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			count++
		}
	}
	return count
}

func containsAny(s string, words []string) bool {
	low := strings.ToLower(s)
	for _, w := range words {
		if strings.Contains(low, strings.ToLower(w)) {
			return true
		}
	}
	return false
}
