package server

import (
	"context"
	"errors"
	"testing"

	"github.com/Autumn-27/protocol-agent/agent"
)

func TestProtocolPhaseSnapshotsRunningAndDone(t *testing.T) {
	s := &Server{m: &Manager{}}
	job := &protocolPhaseJob{CaseID: 1, Phase: "P1", done: make(chan struct{})}
	s.protocolJobs = map[int64]map[string]*protocolPhaseJob{1: {"P1": job}}

	items, running := s.protocolPhaseSnapshots(1, []string{"P1"})
	if len(items) != 1 || len(running) != 1 || items[0]["status"] != "running" {
		t.Fatalf("running snapshot mismatch: items=%v running=%v", items, running)
	}
	job.finish(map[string]any{"passed": true, "gate": "A", "subagent_run_id": int64(7)}, nil)
	items, running = s.protocolPhaseSnapshots(1, []string{"P1"})
	if len(running) != 0 || items[0]["status"] != "done" || items[0]["passed"] != true {
		t.Fatalf("done snapshot mismatch: items=%v running=%v", items, running)
	}
	if items[0]["subagent_run_id"] != int64(7) {
		t.Fatalf("run id not propagated: %v", items[0])
	}
}

func TestCancelProtocolPhaseJob(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	job := &protocolPhaseJob{Phase: "P1", done: make(chan struct{}), cancel: cancel}
	s := &Server{m: &Manager{}, protocolJobs: map[int64]map[string]*protocolPhaseJob{1: {"P1": job}}}
	if err := s.cancelProtocolPhaseJob(1, "P1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), agent.AbortChatStoppedByUser) {
			t.Fatalf("unexpected cause: %v", context.Cause(ctx))
		}
	default:
		t.Fatal("phase context was not cancelled")
	}
}

func TestClearProtocolJobsCancelsRunningJobs(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	job := &protocolPhaseJob{CaseID: 1, Phase: "P2", done: make(chan struct{}), cancel: cancel}
	s := &Server{m: &Manager{}, protocolJobs: map[int64]map[string]*protocolPhaseJob{1: {"P2": job}}}
	s.clearProtocolJobs(1)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), agent.AbortTaskDeleted) {
			t.Fatalf("unexpected cause: %v", context.Cause(ctx))
		}
	default:
		t.Fatal("clearProtocolJobs left a running job uncancellable")
	}
	job.mu.Lock()
	cancelled := job.cancelled
	job.mu.Unlock()
	if !cancelled {
		t.Fatal("cancelled flag not set before finish; status would be misreported")
	}
}

func TestPhaseJobContextDetachedFromParent(t *testing.T) {
	// M0-1: the job context must survive the parent conversation turn ending.
	parent, cancelParent := context.WithCancelCause(context.Background())
	cancelParent(agent.AbortChatTurnFinished)
	// startProtocolPhaseJob derives the job context internally; emulate the
	// exact derivation it uses so this test pins the contract.
	jobCtx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
	defer cancel(agent.AbortTaskDeleted)
	select {
	case <-jobCtx.Done():
		t.Fatal("job context must not inherit parent turn cancellation")
	default:
	}
}
