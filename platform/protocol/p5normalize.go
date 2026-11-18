package protocol

import (
	"encoding/json"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

// NormalizeP5Findings enforces the P5 output contract before the run is merged
// into canonical findings:
//
//   - final function-code verdicts and code-reconciliation verdicts use the
//     closed three-value enum (matched / conflicting / single-source);
//   - a final code inherits its reconciliation pair's canonical verdict, so
//     Gate E's exact comparison cannot fail because the model used synonyms;
//   - traffic frames get the stable key used by the DB projection;
//   - field maps keep map_key as key, and vice versa;
//   - probes get the same stable probe_key the DB projection generates.
//
// It is intentionally idempotent and only runs for P5.
func NormalizeP5Findings(m map[string]json.RawMessage) {
	if m == nil {
		return
	}

	var codes []map[string]any
	codesOK := decodeObjectMaps(m["function_codes"], &codes)
	var notes []map[string]any
	notesOK := decodeObjectMaps(m["notes"], &notes)

	pairVerdict := map[string]string{}
	if notesOK {
		notesChanged := false
		for _, note := range notes {
			if !equalFoldTrim(note["kind"], "code-reconciliation") {
				continue
			}
			if normalizeReconciliationList(note, "pairs", pairVerdict) {
				notesChanged = true
			}
			if normalizeReconciliationList(note, "items", pairVerdict) {
				notesChanged = true
			}
			if payload, ok := note["payload"].(map[string]any); ok {
				if normalizeReconciliationList(payload, "pairs", pairVerdict) {
					notesChanged = true
				}
				if normalizeReconciliationList(payload, "items", pairVerdict) {
					notesChanged = true
				}
			}
		}
		if notesChanged {
			putObjectMaps(m, "notes", notes)
		}
	}

	if codesOK {
		codesChanged := false
		for _, code := range codes {
			orig := strAny(code["verdict"])
			canonical := CanonicalVerdict(orig)
			if canonical != "" && canonical != orig {
				code["verdict"] = canonical
				codesChanged = true
			}
			key := db.CodeKeyFor(strAny(code["code"]), intAny(code["code"]))
			if pair := pairVerdict[key]; pair != "" && strAny(code["verdict"]) != pair {
				code["verdict"] = pair
				codesChanged = true
			}
		}
		if codesChanged {
			putObjectMaps(m, "function_codes", codes)
		}
	}

	var frames []map[string]any
	if decodeObjectMaps(m["frame_formats"], &frames) {
		changed := false
		for _, frame := range frames {
			if strAny(frame["key"]) == "" {
				if key := db.FrameKeyFor(frame); key != "" {
					frame["key"] = key
					changed = true
				}
			}
		}
		if changed {
			putObjectMaps(m, "frame_formats", frames)
		}
	}

	var fields []map[string]any
	if decodeObjectMaps(m["field_maps"], &fields) {
		changed := false
		for _, field := range fields {
			key := strAny(field["key"])
			mapKey := strAny(field["map_key"])
			if key == "" && mapKey != "" {
				field["key"] = mapKey
				changed = true
			}
			if mapKey == "" && key != "" {
				field["map_key"] = key
				changed = true
			}
		}
		if changed {
			putObjectMaps(m, "field_maps", fields)
		}
	}

	var probes []map[string]any
	if decodeObjectMaps(m["probes"], &probes) {
		changed := false
		for _, probe := range probes {
			key := db.ProbeKeyFor(probe)
			if key != "" && strAny(probe["probe_key"]) != key {
				probe["probe_key"] = key
				changed = true
			}
		}
		if changed {
			putObjectMaps(m, "probes", probes)
		}
	}
}

func decodeObjectMaps(raw json.RawMessage, out *[]map[string]any) bool {
	if len(raw) == 0 {
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false
	}
	return true
}

func putObjectMaps(m map[string]json.RawMessage, key string, items []map[string]any) {
	b, err := json.Marshal(items)
	if err == nil {
		m[key] = b
	}
}

func normalizeReconciliationList(container map[string]any, key string, out map[string]string) bool {
	arr, ok := container[key].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, item := range arr {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		orig := strAny(obj["verdict"])
		canonical := CanonicalVerdict(orig)
		if canonical == "" {
			continue
		}
		if canonical != orig {
			obj["verdict"] = canonical
			changed = true
		}
		if code := strAny(obj["code"]); code != "" {
			out[db.CodeKeyFor(code, 0)] = canonical
		}
	}
	return changed
}

func equalFoldTrim(v any, want string) bool {
	s, _ := v.(string)
	return strings.EqualFold(strings.TrimSpace(s), want)
}
