package llmrec

import (
	"context"
	"testing"

	"github.com/Autumn-27/norma/transcript"
)

func TestEffectiveSessionPrefersExplicitOverride(t *testing.T) {
	ctx := transcript.WithSessionID(context.Background(), "exp1-worker")
	if got := effectiveSession(ctx); got != "exp1-worker" {
		t.Fatalf("effectiveSession()=%q want transcript session", got)
	}
	ctx = WithSession(ctx, "  proto-9-p4-1  ")
	if got := effectiveSession(ctx); got != "proto-9-p4-1" {
		t.Fatalf("effectiveSession()=%q want explicit session", got)
	}
}

func TestWithSessionIgnoresBlank(t *testing.T) {
	ctx := transcript.WithSessionID(context.Background(), "exp1-worker")
	if got := effectiveSession(WithSession(ctx, "   ")); got != "exp1-worker" {
		t.Fatalf("blank override should preserve transcript session, got %q", got)
	}
}
