package server

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/protocol-agent/db"
)

func retentionInterval() time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv("PROTOCOL_AGENT_RETENTION_INTERVAL_MINUTES")))
	if err != nil || n < 5 {
		n = 1440
	}
	return time.Duration(n) * time.Minute
}

func (s *Server) startRetentionLoop(ctx context.Context) {
	if s.m == nil || s.m.pg == nil {
		return
	}
	policy := db.RetentionPolicyFromEnv()
	if !policy.Enabled() {
		return
	}
	interval := retentionInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.runRetention(ctx, policy)
			}
		}
	}()
	log.Printf("[retention] enabled interval=%s policy=%+v", interval, policy)
}

func (s *Server) runRetention(ctx context.Context, policy db.RetentionPolicy) {
	counts, err := s.m.pg.ApplyRetention(ctx, policy)
	if err != nil {
		log.Printf("[retention] db cleanup: %v", err)
		return
	}
	if policy.PcapDays > 0 && s.protocolRunner != nil {
		n, err := cleanupOldPcaps(s.protocolRunner.RunsDir(), policy.PcapDays, time.Now())
		if err != nil {
			log.Printf("[retention] pcap cleanup: %v", err)
		} else {
			counts["pcaps"] = int64(n)
		}
	}
	log.Printf("[retention] cleaned %v", counts)
}

// cleanupOldPcaps deletes old capture files under case workdirs/pcaps. It is
// deliberately limited to pcap extensions; artifacts and reports are untouched.
func cleanupOldPcaps(root string, days int, now time.Time) (int, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	deleted := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.Contains(filepath.ToSlash(path), "/pcaps/") {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".pcap", ".pcapng", ".cap":
		default:
			return nil
		}
		if info.ModTime().After(cutoff) {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		deleted++
		return nil
	})
	return deleted, err
}
