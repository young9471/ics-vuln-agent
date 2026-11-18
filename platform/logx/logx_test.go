package logx

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingFileRotatesAndKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	cleanup, err := setup(dir, 120, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		log.Printf("line-%02d-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", i)
	}
	cleanup()

	entries, err := os.ReadDir(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "platform.log") {
		t.Fatalf("current log missing: %v", names)
	}
	if !strings.Contains(joined, "platform.log.1") {
		t.Fatalf("rotation did not create .1: %v", names)
	}
	if strings.Contains(joined, "platform.log.3") {
		t.Fatalf("keep=2 must not leave .3: %v", names)
	}
}