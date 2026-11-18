package protocol

import "testing"

func TestCanonicalVerdict(t *testing.T) {
	cases := map[string]string{
		"matched":       VerdictMatched,
		"confirmed":     VerdictMatched,
		"agree":         VerdictMatched,
		"conflicting":   VerdictConflicting,
		"conflict":      VerdictConflicting,
		"single-source": VerdictSingleSource,
		"consistent":    VerdictSingleSource,
		"unverified":    VerdictSingleSource,
		"refuted":       VerdictSingleSource,
		"traffic-only":  VerdictTrafficOnly,
		"static-only":   VerdictStaticOnly,
		"banana":        "",
	}
	for in, want := range cases {
		if got := CanonicalVerdict(in); got != want {
			t.Errorf("CanonicalVerdict(%q)=%q want %q", in, got, want)
		}
	}
}
