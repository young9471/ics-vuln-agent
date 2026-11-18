package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type captureInterface struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type protocolCapture struct {
	CaseID    int64
	Interface string
	Filter    string
	Path      string
	Started   time.Time
	Status    string
	Error     string
	mu        sync.Mutex
	cancel    context.CancelFunc
	cmd       *exec.Cmd
	stop      bool
}

func (c *protocolCapture) snapshot() map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]any{
		"case_id": c.CaseID, "interface": c.Interface, "filter": c.Filter,
		"path": c.Path, "started_at": c.Started.Format(time.RFC3339),
		"status": c.Status, "running": c.Status == "running",
	}
	if c.Error != "" {
		out["error"] = c.Error
	}
	if st, err := os.Stat(c.Path); err == nil {
		out["bytes"] = st.Size()
	}
	return out
}

func (s *Server) captureInterfaces(ctx context.Context) ([]captureInterface, error) {
	if s.protocolRunner == nil {
		return nil, fmt.Errorf("protocol runner 不可用")
	}
	tshark := s.protocolRunner.Tshark()
	if strings.TrimSpace(tshark) == "" {
		return nil, fmt.Errorf("未配置 tshark")
	}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, tshark, "-D")
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark -D 失败: %v %s", err, strings.TrimSpace(errb.String()))
	}
	var list []captureInterface
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// "1. \Device\NPF_{...} (Ethernet)"
		id, name := line, line
		if i := strings.Index(line, "."); i > 0 {
			if _, err := strconv.Atoi(strings.TrimSpace(line[:i])); err == nil {
				id = strings.TrimSpace(line[:i])
				name = strings.TrimSpace(line[i+1:])
			}
		}
		list = append(list, captureInterface{ID: id, Name: name})
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("tshark 未发现网卡")
	}
	return list, nil
}

func (s *Server) protocolCaptureInterfaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.captureInterfaces(r.Context())
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"interfaces": list})
}

func (s *Server) protocolCaptureStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	s.captureMu.Lock()
	c := s.captures[id]
	s.captureMu.Unlock()
	if c == nil {
		writeJSON(w, 200, map[string]any{"running": false, "status": "idle"})
		return
	}
	writeJSON(w, 200, c.snapshot())
}

func (s *Server) protocolCaptureStart(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	c, err := pg.GetProtocolCase(id)
	if err != nil || c == nil {
		writeErr(w, 404, "case not found")
		return
	}
	var req struct {
		Interface       string `json:"interface"`
		Filter          string `json:"filter"`
		DurationSeconds int    `json:"duration_seconds"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(req.Interface) == "" {
		writeErr(w, 400, "请选择网卡")
		return
	}
	interfaces, err := s.captureInterfaces(r.Context())
	if err != nil {
		writeErr(w, 503, err.Error())
		return
	}
	found := false
	for _, it := range interfaces {
		if it.ID == req.Interface {
			found = true
			break
		}
	}
	if !found {
		writeErr(w, 400, "网卡不存在，请刷新列表")
		return
	}
	if err := s.checkProtocolCaseQuota(c, 0); err != nil {
		writeErr(w, 413, err.Error())
		return
	}
	duration := req.DurationSeconds
	if duration <= 0 {
		duration = 300
	}
	if duration > 3600 {
		duration = 3600
	}
	filter := normalizeCaptureFilter(req.Filter, c.DeviceIP)
	s.captureMu.Lock()
	if old := s.captures[id]; old != nil {
		old.mu.Lock()
		running := old.Status == "running"
		old.mu.Unlock()
		if running {
			s.captureMu.Unlock()
			writeErr(w, 409, "该案例已有抓包在运行")
			return
		}
	}
	dir := filepath.Join(s.protocolRunner.Workdir(c), "pcaps")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		s.captureMu.Unlock()
		writeErr(w, 500, err.Error())
		return
	}
	path := filepath.Join(dir, "capture-"+time.Now().Format("20060102-150405")+".pcapng")
	ctx, cancel := context.WithCancel(s.ctx)
	tshark := s.protocolRunner.Tshark()
	args := []string{"-i", req.Interface, "-f", filter, "-w", path, "-a", "duration:" + strconv.Itoa(duration)}
	cmd := exec.CommandContext(ctx, tshark, args...)
	logPath := filepath.Join(dir, "capture.log")
	logFile, _ := os.Create(logPath)
	cap := &protocolCapture{
		CaseID: id, Interface: req.Interface, Filter: filter, Path: path,
		Started: time.Now(), Status: "running", cancel: cancel, cmd: cmd,
	}
	s.captures[id] = cap
	s.captureMu.Unlock()

	go func() {
		var runErr error
		if logFile != nil {
			cmd.Stdout, cmd.Stderr = logFile, logFile
		}
		if err := cmd.Start(); err != nil {
			runErr = err
		} else {
			runErr = cmd.Wait()
		}
		if logFile != nil {
			_ = logFile.Close()
		}
		cap.mu.Lock()
		switch {
		case cap.stop:
			cap.Status = "stopped"
		case runErr != nil:
			cap.Status = "error"
			cap.Error = runErr.Error()
			if tail := captureLogTail(logPath, 3); tail != "" {
				cap.Error += ": " + tail
			}
		default:
			cap.Status = "done"
		}
		cap.mu.Unlock()
		cancel()
		s.emitProtocolEvent(id, "P2", "artifact", "抓包结束: "+cap.Status, map[string]any{"path": path, "error": cap.Error})
	}()
	s.emitProtocolEvent(id, "P2", "status", "后台抓包开始: "+req.Interface, map[string]any{"path": path, "filter": filter, "duration_seconds": duration})
	out := cap.snapshot()
	out["log_path"] = logPath
	writeJSON(w, 202, out)
}

var (
	captureIPv4     = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	captureIPv6     = regexp.MustCompile(`^[0-9a-fA-F:]+$`)
	captureHostname = regexp.MustCompile(`^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+$`)
)

// normalizeCaptureFilter builds a BPF filter from the dialog's single input.
// Users often type just the device address; tshark rejects that as an invalid
// capture filter, so a bare IPv4/IPv6/hostname is expanded to a host filter.
func normalizeCaptureFilter(raw, deviceIP string) string {
	f := strings.TrimSpace(raw)
	if f == "" {
		if ip := strings.TrimSpace(deviceIP); ip != "" {
			return "host " + ip + " and not arp and not icmp"
		}
		return "not arp and not icmp"
	}
	if isBareCaptureHost(f) {
		return "host " + f + " and not arp and not icmp"
	}
	return f
}

func isBareCaptureHost(f string) bool {
	if captureIPv4.MatchString(f) {
		return true
	}
	if strings.Count(f, ":") >= 2 && captureIPv6.MatchString(f) {
		return true
	}
	return captureHostname.MatchString(f)
}

// captureLogTail returns the last non-empty tshark log lines for the UI error.
func captureLogTail(path string, maxLines int) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	var tail []string
	for i := len(lines) - 1; i >= 0 && len(tail) < maxLines; i-- {
		if line := strings.TrimSpace(lines[i]); line != "" {
			tail = append([]string{line}, tail...)
		}
	}
	msg := strings.Join(tail, " | ")
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return msg
}

func (s *Server) protocolCaptureStop(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid id")
		return
	}
	s.captureMu.Lock()
	c := s.captures[id]
	s.captureMu.Unlock()
	if c == nil {
		writeErr(w, 409, "该案例没有抓包任务")
		return
	}
	c.mu.Lock()
	if c.Status != "running" {
		c.mu.Unlock()
		writeErr(w, 409, "抓包已经结束")
		return
	}
	c.stop = true
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": "stopping"})
}

// captureStatusJSON is exposed for tests.
func captureStatusJSON(c *protocolCapture) json.RawMessage {
	b, _ := json.Marshal(c.snapshot())
	return b
}
