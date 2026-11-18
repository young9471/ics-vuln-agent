package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupOldPcapsOnly(t *testing.T) {
	root := t.TempDir()
	pcaps := filepath.Join(root, "case-1", "pcaps")
	artifacts := filepath.Join(root, "case-1", "artifacts")
	if err := os.MkdirAll(pcaps, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	oldPcap := filepath.Join(pcaps, "old.pcapng")
	newPcap := filepath.Join(pcaps, "new.pcapng")
	oldArtifact := filepath.Join(artifacts, "old.bin")
	for _, p := range []string{oldPcap, newPcap, oldArtifact} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(oldPcap, old, old)
	_ = os.Chtimes(oldArtifact, old, old)
	n, err := cleanupOldPcaps(root, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted=%d want 1", n)
	}
	if _, err := os.Stat(oldPcap); !os.IsNotExist(err) {
		t.Fatal("old pcap should be deleted")
	}
	for _, p := range []string{newPcap, oldArtifact} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("must keep %s: %v", p, err)
		}
	}
}
