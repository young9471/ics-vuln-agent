package server

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Autumn-27/protocol-agent/agent"
	pgdb "github.com/Autumn-27/protocol-agent/db"
)

// Manager owns the PostgreSQL connection, data directory and process-wide LLM /
// web-search settings. The pentest task/asset/traffic subsystems are not part of
// this build.
type Manager struct {
	dir string
	pg  *pgdb.DB

	mu               sync.RWMutex
	llmRecOn         bool
	webSearchOn      bool
	webSearchBackend string
	braveKey         string
	tavilyKey        string
	webSearchProxy   string
	globalProxy      string
}

const (
	settingWebSearchOn         = "web_search_enabled"
	settingWebSearchBackend    = "web_search_backend"
	settingBraveKey            = "brave_search_api_key"
	settingTavilyKey           = "tavily_search_api_key"
	settingWebSearchProxy      = "web_search_proxy"
	settingGlobalProxy         = "global_proxy"
	settingLLMRecord           = "llm_record"
	settingLLMPoolOn           = "llm_pool_enabled"
	settingLLMPoolBindFallback = "llm_pool_bind_fallback"
	settingNoaCompaction       = "noa_compaction"
	defaultWebSearchBackend    = "ddgs"
)

func NewManager(dir, proxyAddr string) (*Manager, error) {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	dsn, source, err := pgdb.DSN()
	if err != nil {
		return nil, err
	}
	log.Printf("[pg] 数据库配置来源: %s", source)
	pg, err := pgdb.Open(dsn)
	if err != nil {
		return nil, err
	}
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		log.Printf("[llmrec] create table: %v", err)
	}
	if err := pg.EnsureLLMUsageTable(); err != nil {
		log.Printf("[llmusage] create table: %v", err)
	}
	m := &Manager{dir: dir, pg: pg}
	m.llmRecOn = pg.GetBool(settingLLMRecord, false)
	m.webSearchOn = pg.GetBool(settingWebSearchOn, false)
	if v, ok, _ := pg.GetSetting(settingWebSearchBackend); ok && v != "" {
		m.webSearchBackend = v
	} else {
		m.webSearchBackend = defaultWebSearchBackend
	}
	if v, ok, _ := pg.GetSetting(settingBraveKey); ok {
		m.braveKey = v
	}
	if v, ok, _ := pg.GetSetting(settingTavilyKey); ok {
		m.tavilyKey = v
	}
	if v, ok, _ := pg.GetSetting(settingWebSearchProxy); ok {
		m.webSearchProxy = v
	}
	if v, ok, _ := pg.GetSetting(settingGlobalProxy); ok {
		m.globalProxy = strings.TrimSpace(v)
	}
	return m, nil
}

func (m *Manager) PG() *pgdb.DB { return m.pg }
func (m *Manager) Dir() string  { return m.dir }
func (m *Manager) Close() error {
	if m.pg != nil {
		return m.pg.Close()
	}
	return nil
}

func (m *Manager) GlobalProxy() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.globalProxy
}

func (m *Manager) ProxyAddr() string   { return m.GlobalProxy() }
func (m *Manager) ProxyCACert() string { return "" }

func (m *Manager) WebSearchOpts() agent.WebSearchOpts {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return agent.WebSearchOpts{
		Enabled:   m.webSearchOn,
		Backend:   m.webSearchBackend,
		BraveKey:  m.braveKey,
		TavilyKey: m.tavilyKey,
		Proxy:     m.webSearchProxy,
	}
}

func (m *Manager) LLMRecordEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.llmRecOn
}

func (m *Manager) SetLLMRecordEnabled(on bool) error {
	if err := m.pg.SetBool(settingLLMRecord, on); err != nil {
		return err
	}
	m.mu.Lock()
	m.llmRecOn = on
	m.mu.Unlock()
	return nil
}

func (m *Manager) NoaCompactionEnabled() bool {
	return m.pg.GetBool(settingNoaCompaction, false)
}

func (m *Manager) SetNoaCompaction(on bool) error {
	return m.pg.SetBool(settingNoaCompaction, on)
}

func (m *Manager) LLMPoolEnabled() bool {
	return m.pg.GetBool(settingLLMPoolOn, false)
}
func (m *Manager) SetLLMPoolEnabled(on bool) error {
	return m.pg.SetBool(settingLLMPoolOn, on)
}
func (m *Manager) LLMPoolBindFallback() bool {
	return m.pg.GetBool(settingLLMPoolBindFallback, false)
}
func (m *Manager) SetLLMPoolBindFallback(on bool) error {
	return m.pg.SetBool(settingLLMPoolBindFallback, on)
}
