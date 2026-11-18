package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// NormalizeStats reports shape repairs and hygiene applied to agent findings.
type NormalizeStats struct {
	DroppedNotes     int
	NormalizedNotes  int
	DedupedNotes     int
	CappedNotes      int
	NormalizedFields int
}

const (
	// Notes are append-only across phase merges; cap growth without losing the
	// newest evidence. The gate only needs the current run's reconciliation.
	noteKindLimit  = 200
	noteTotalLimit = 1000
)

var volatileNoteKeys = map[string]bool{
	"created_at": true, "updated_at": true, "ts": true, "timestamp": true,
	"captured_at": true, "time": true,
}

// NormalizeFindingsMap repairs known agent-output shape drift in place:
//   - notes without a kind are dropped, duplicates (ignoring volatile
//     timestamps) are collapsed, and per-kind/total counts are capped;
//   - session-model-final payloads nested one level too deep are unwrapped;
//   - field-map items emitted with offset/width/kind are normalized to the
//     canonical off/size/class keys used by traffic analysis.
//
// It is idempotent: a second pass reports zero repairs.
func NormalizeFindingsMap(m map[string]json.RawMessage) NormalizeStats {
	stats := PruneNotes(m)
	if raw, ok := m["field_maps"]; ok && len(raw) > 0 {
		var items []map[string]any
		if json.Unmarshal(raw, &items) == nil {
			changed := false
			for _, fm := range items {
				fields, _ := fm["fields"].([]any)
				for _, f := range fields {
					obj, ok := f.(map[string]any)
					if !ok {
						continue
					}
					if _, has := obj["off"]; !has {
						if v, ok := obj["offset"]; ok {
							obj["off"] = v
							stats.NormalizedFields++
							changed = true
						}
					}
					if _, has := obj["size"]; !has {
						if v, ok := obj["width"]; ok {
							obj["size"] = v
							stats.NormalizedFields++
							changed = true
						}
					}
					if _, has := obj["class"]; !has {
						if v, ok := obj["kind"]; ok {
							obj["class"] = v
							changed = true
						}
					}
				}
			}
			if changed {
				if b, err := json.Marshal(items); err == nil {
					m["field_maps"] = b
				}
			}
		}
	}
	return stats
}

// PruneNotes applies note-only hygiene. Exposed separately so the merge path can
// re-run it after appending a run's notes to the canonical file.
func PruneNotes(m map[string]json.RawMessage) NormalizeStats {
	var stats NormalizeStats
	raw, ok := m["notes"]
	if !ok || len(raw) == 0 {
		return stats
	}
	var items []map[string]any
	if json.Unmarshal(raw, &items) != nil {
		return stats
	}
	out := make([]map[string]any, 0, len(items))
	index := map[string]int{}
	for _, note := range items {
		kind := strings.TrimSpace(strAny(note["kind"]))
		if kind == "" {
			stats.DroppedNotes++
			continue
		}
		if kind == "session-model-final" {
			if payload, ok := note["payload"].(map[string]any); ok {
				if inner, ok := payload["payload"].(map[string]any); ok {
					// Merge metadata from both the outer payload level and the
					// note level, so grade/phase/source are preserved.
					for k, v := range payload {
						if k == "payload" {
							continue
						}
						if _, exists := inner[k]; !exists {
							inner[k] = v
						}
					}
					for k, v := range note {
						if k == "payload" {
							continue
						}
						if _, exists := inner[k]; !exists {
							inner[k] = v
						}
					}
					note["payload"] = inner
					stats.NormalizedNotes++
				}
			}
		}
		id := noteIdentity(note)
		if idx, ok := index[id]; ok {
			out[idx] = note // newest content wins
			stats.DedupedNotes++
			continue
		}
		index[id] = len(out)
		out = append(out, note)
	}

	// Cap per kind and overall, keeping the newest entries.
	keep := make([]bool, len(out))
	perKind := map[string]int{}
	for i := len(out) - 1; i >= 0; i-- {
		kind := strings.ToLower(strings.TrimSpace(strAny(out[i]["kind"])))
		if perKind[kind] >= noteKindLimit {
			stats.CappedNotes++
			continue
		}
		perKind[kind]++
		keep[i] = true
	}
	total := 0
	for i := len(out) - 1; i >= 0; i-- {
		if !keep[i] {
			continue
		}
		if total >= noteTotalLimit {
			keep[i] = false
			stats.CappedNotes++
			continue
		}
		total++
	}
	final := make([]map[string]any, 0, total)
	for i, note := range out {
		if keep[i] {
			final = append(final, note)
		}
	}
	if stats.DroppedNotes+stats.NormalizedNotes+stats.DedupedNotes+stats.CappedNotes > 0 {
		if b, err := json.Marshal(final); err == nil {
			m["notes"] = b
		}
	}
	return stats
}

// noteIdentity dedupes the same note across phase merges while ignoring volatile
// timestamps that agents embed in payloads.
func noteIdentity(note map[string]any) string {
	kind := strings.ToLower(strings.TrimSpace(strAny(note["kind"])))
	payload := stripVolatileKeys(note["payload"])
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return kind + "|" + hex.EncodeToString(sum[:16])
}

func stripVolatileKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if volatileNoteKeys[strings.ToLower(k)] {
				continue
			}
			out[k] = stripVolatileKeys(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = stripVolatileKeys(val)
		}
		return out
	default:
		return v
	}
}
