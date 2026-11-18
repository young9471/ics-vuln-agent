package protocol

import "strings"

// Canonical verdicts returned by P5. Keep this list closed: the gate compares
// the final function-code verdict with its reconciliation pair byte-for-byte,
// so allowing free-form synonyms would make Gate E depend on model wording.
const (
	VerdictMatched      = "matched"
	VerdictConflicting  = "conflicting"
	VerdictSingleSource = "single-source"
	VerdictTrafficOnly  = "traffic-only"
	VerdictStaticOnly   = "static-only"
)

// CanonicalVerdict maps legacy/model-specific spellings onto the fixed P5
// verdict enum. Unknown values intentionally return "" so the gate treats them
// as missing rather than silently accepting a new vocabulary.
func CanonicalVerdict(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "matched", "match", "agree", "agreed", "confirmed", "confirm":
		return VerdictMatched
	case "conflicting", "conflict", "mismatch", "mismatched":
		return VerdictConflicting
	case "single-source", "single_source", "single source",
		"consistent", "unverified", "unconfirmed", "refuted", "refute":
		return VerdictSingleSource
	case "traffic-only", "traffic_only":
		return VerdictTrafficOnly
	case "static-only", "static_only":
		return VerdictStaticOnly
	default:
		return ""
	}
}

// IsCanonicalVerdict reports whether a value is one of the three P5 verdicts.
func IsCanonicalVerdict(raw string) bool {
	switch strings.TrimSpace(raw) {
	case VerdictMatched, VerdictConflicting, VerdictSingleSource,
		VerdictTrafficOnly, VerdictStaticOnly:
		return true
	default:
		return false
	}
}
