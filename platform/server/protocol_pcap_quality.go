package server

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type pcapQuality struct {
	Path            string   `json:"path"`
	Name            string   `json:"name"`
	Bytes           int64    `json:"bytes"`
	Packets         int      `json:"packets"`
	DurationSeconds float64  `json:"duration_seconds"`
	Endpoints       int      `json:"endpoints"`
	Protocols       []string `json:"protocols"`
	Warnings        []string `json:"warnings"`
	Error           string   `json:"error,omitempty"`
}

func (s *Server) protocolPcapQuality(w http.ResponseWriter, r *http.Request) {
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
	pcaps := s.protocolRunner.Pcaps(c)
	out := make([]pcapQuality, 0, len(pcaps))
	for _, p := range pcaps {
		out = append(out, inspectPcap(r.Context(), s.protocolRunner.Tshark(), p))
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

func inspectPcap(ctx context.Context, tshark, path string) pcapQuality {
	q := pcapQuality{Path: path, Name: filepath.Base(path), Protocols: []string{}, Warnings: []string{}}
	if st, err := os.Stat(path); err == nil {
		q.Bytes = st.Size()
	}
	if strings.TrimSpace(tshark) == "" {
		q.Error = "未配置 tshark"
		return q
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, tshark, "-r", path, "-c", "20000", "-T", "fields",
		"-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
		"-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
		"-e", "frame.protocols")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		q.Error = strings.TrimSpace(stderr.String())
		if q.Error == "" {
			q.Error = err.Error()
		}
		return q
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	endpoints := map[string]bool{}
	protocols := map[string]bool{}
	var first, last float64
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for len(parts) < 8 {
			parts = append(parts, "")
		}
		q.Packets++
		if t, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
			if first == 0 || t < first {
				first = t
			}
			if t > last {
				last = t
			}
		}
		src, dst := strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		sp, dp := strings.TrimSpace(parts[3]), strings.TrimSpace(parts[4])
		if src != "" {
			endpoints[src+":"+sp] = true
		}
		if dst != "" {
			endpoints[dst+":"+dp] = true
		}
		for _, p := range strings.Split(parts[7], ":") {
			if p = strings.TrimSpace(p); p != "" {
				protocols[p] = true
			}
		}
	}
	q.DurationSeconds = last - first
	q.Endpoints = len(endpoints)
	for p := range protocols {
		q.Protocols = append(q.Protocols, p)
	}
	if q.Packets == 0 {
		q.Warnings = append(q.Warnings, "没有可读数据包")
	}
	if q.Packets > 0 && q.Packets < 10 {
		q.Warnings = append(q.Warnings, "包数过少，可能未覆盖完整会话")
	}
	if q.DurationSeconds > 0 && q.DurationSeconds < 1 {
		q.Warnings = append(q.Warnings, "捕获时长不足 1 秒")
	}
	if q.Endpoints < 2 {
		q.Warnings = append(q.Warnings, "对端端点不足，可能只有单向流量")
	}
	return q
}
