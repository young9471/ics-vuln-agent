// Package logx installs process logging: existing log.Printf lines and new
// structured slog records go to the console/DB sink plus a size-rotated file
// under <dataDir>/logs/platform.log.
package logx

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultMaxBytes = 10 << 20 // 10 MiB per file
	DefaultKeep     = 5        // rotated files kept
)

type rotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	file     *os.File
	size     int64
}

func openRotating(path string, maxBytes int64, keep int) (*rotatingFile, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if keep <= 0 {
		keep = DefaultKeep
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &rotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if st, err := os.Stat(path); err == nil {
		w.size = st.Size()
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	w.file = f
	return w, nil
}

func (w *rotatingFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return len(p), nil
	}
	if w.size+int64(len(p)) > w.maxBytes {
		w.rotate()
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFile) rotate() {
	_ = w.file.Close()
	for i := w.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	_ = os.Rename(w.path, w.path+".1")
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		w.file = nil
		return
	}
	w.file = f
	w.size = 0
}

// Close flushes and releases the file handle.
func (w *rotatingFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// Setup installs file logging next to whatever writer is currently active (the
// in-memory/DB log sink), and configures slog JSON output as well.
func Setup(dataDir string) (func(), error) {
	return setup(dataDir, DefaultMaxBytes, DefaultKeep)
}

func setup(dataDir string, maxBytes int64, keep int) (func(), error) {
	path := filepath.Join(dataDir, "logs", "platform.log")
	w, err := openRotating(path, maxBytes, keep)
	if err != nil {
		return func() {}, err
	}
	base := log.Writer()
	output := io.MultiWriter(base, w)
	// slog.SetDefault redirects the standard log package to the JSON handler
	// (Go 1.21+); restore the plain log writer afterwards so existing
	// log.Printf lines keep their text format in /logs and the log table.
	slog.SetDefault(slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: slog.LevelInfo})))
	log.SetOutput(output)
	log.SetFlags(log.LstdFlags)
	return func() { _ = w.Close() }, nil
}