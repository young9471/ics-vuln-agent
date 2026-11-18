package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSkillDirRelativeUsesBaseDir(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfg, []byte(`{"skill_dir":"./skills"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROTOCOL_AGENT_CONFIG", cfg)
	t.Setenv("PROTOCOL_AGENT_SKILL_DIR", "")
	got := SkillDir()
	want := filepath.Join(BaseDir(), "skills")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("SkillDir=%q want %q (must not depend on CWD)", got, want)
	}
}
