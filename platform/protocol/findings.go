package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateFindingsFile checks the on-disk findings structure before a gate or a
// merge trusts it. Missing files are treated as empty (the phase gate then fails
// on its own count); malformed JSON or non-object array items are hard errors.
func ValidateFindingsFile(workdir string) error {
	b, err := os.ReadFile(filepath.Join(workdir, "findings.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("findings.json 不是 JSON 对象: %w", err)
	}
	return ValidateFindingsMap(m)
}

// ValidateFindingsMap validates section shapes shared by the merge path and the
// gate path. It deliberately does not require every phase section to exist.
func ValidateFindingsMap(m map[string]json.RawMessage) error {
	arrays := []string{"comm_assets", "streams", "frame_formats", "field_maps", "function_codes", "probes", "notes", "phases", "pitfalls_hit"}
	for _, key := range arrays {
		raw, ok := m[key]
		if !ok || len(raw) == 0 || string(raw) == "null" {
			continue
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return fmt.Errorf("%s 必须是 JSON 数组: %w", key, err)
		}
		for i, item := range items {
			var obj map[string]any
			if err := json.Unmarshal(item, &obj); err != nil {
				return fmt.Errorf("%s[%d] 不是 JSON 对象: %w", key, i, err)
			}
			if err := validateProtocolFindingItem(key, obj); err != nil {
				return fmt.Errorf("%s[%d]: %w", key, i, err)
			}
		}
	}
	return nil
}

// findingIsStatic reports whether a findings item carries static-analysis
// provenance, so a no-observation entry can be told apart from a traffic one.
func findingIsStatic(obj map[string]any) bool {
	for _, key := range []string{"source", "grade", "layer"} {
		if strings.Contains(strings.ToLower(strAny(obj[key])), "static") {
			return true
		}
	}
	return false
}

func validateProtocolFindingItem(section string, obj map[string]any) error {
	switch section {
	case "comm_assets":
		if strings.TrimSpace(strAny(obj["path"])) == "" {
			return fmt.Errorf("缺少 path")
		}
	case "frame_formats":
		frames := intAny(obj["frames"])
		if frames < 0 {
			return fmt.Errorf("frames 不能为负")
		}
		// Traffic-derived frames must be observed at least once; static analysis
		// (P4) may describe an inferred layout with no observed frames but must
		// mark it as such.
		if frames == 0 && !findingIsStatic(obj) {
			return fmt.Errorf("frames 必须 > 0（流量帧）；静态推断帧需 source/grade 含 static")
		}
	case "field_maps":
		if strings.TrimSpace(strAny(obj["map_key"])) == "" && strings.TrimSpace(strAny(obj["key"])) == "" {
			return fmt.Errorf("缺少 map_key/key")
		}
	case "function_codes":
		if strings.TrimSpace(strAny(obj["code"])) == "" {
			return fmt.Errorf("缺少 code")
		}
	case "probes":
		if strings.TrimSpace(strAny(obj["status"])) == "" {
			return fmt.Errorf("缺少 status")
		}
	}
	return nil
}
