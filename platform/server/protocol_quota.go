package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

const defaultCaseQuotaMB int64 = 4096

// protocolCaseQuotaBytes reads PROTOCOL_AGENT_CASE_DISK_QUOTA_MB. 0 disables
// the limit; negative/blank values fall back to the default.
func protocolCaseQuotaBytes() int64 {
	raw := strings.TrimSpace(os.Getenv("PROTOCOL_AGENT_CASE_DISK_QUOTA_MB"))
	if raw == "" {
		return defaultCaseQuotaMB << 20
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return defaultCaseQuotaMB << 20
	}
	return n << 20
}

func dirUsageBytes(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

func (s *Server) checkProtocolCaseQuota(c *db.ProtocolCase, incoming int64) error {
	limit := protocolCaseQuotaBytes()
	if limit <= 0 || s.protocolRunner == nil || c == nil {
		return nil
	}
	used := dirUsageBytes(s.protocolRunner.Workdir(c))
	if incoming > 0 && used+incoming > limit {
		return fmt.Errorf("案例磁盘配额不足：已用 %d MB，本次 %d MB，上限 %d MB",
			used>>20, incoming>>20, limit>>20)
	}
	if incoming <= 0 && used >= limit {
		return fmt.Errorf("案例磁盘配额已满：已用 %d MB，上限 %d MB", used>>20, limit>>20)
	}
	return nil
}
