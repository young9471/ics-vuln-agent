package server

import (
	"context"
	"log"
	"sync"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/protocol-agent/agent"
	"github.com/Autumn-27/protocol-agent/config"
	"github.com/Autumn-27/protocol-agent/llmpool"
	"github.com/Autumn-27/protocol-agent/protocol"
)

// BuildVersion is injected at build time (-X main.version=<tag>).
var BuildVersion = "dev"

// Server exposes the protocol tool plus the general Agent/MCP/Skill/tool/LLM
// infrastructure. The pentest task engine is not started.
type Server struct {
	m   *Manager
	ctx context.Context

	skillDir string
	jwtKey   []byte

	cfgMu     sync.Mutex
	chatAgent *agent.ChatAgent
	llmProv   llm.Provider
	llmDirect llm.Provider
	llmCfg    agent.Config
	llmOn     bool
	llmProf   string

	chatMu     sync.Mutex
	chatBusy   map[string]bool
	chatCancel map[string]context.CancelCauseFunc

	profMu         sync.Mutex
	profChatAgents map[int64]*agent.ChatAgent

	provCacheMu   sync.Mutex
	provByProfile map[int64]*provEntry
	provCacheGen  uint64

	llmHealth *llmpool.Registry

	side *sideQuestionState

	protocolRunner *protocol.Runner
	protocolHub    *protocolHub

	protocolJobsMu sync.Mutex
	protocolJobs   map[int64]map[string]*protocolPhaseJob

	captureMu sync.Mutex
	captures  map[int64]*protocolCapture
}

func New(ctx context.Context, m *Manager, skillDir string, dataDir string, keyDir string) *Server {
	key, err := loadOrCreateJWTKey(keyDir, dataDir)
	if err != nil {
		log.Fatalf("[auth] JWT key: %v", err)
	}
	s := &Server{
		m: m, ctx: ctx, skillDir: skillDir, jwtKey: key,
		chatBusy:       map[string]bool{},
		chatCancel:     map[string]context.CancelCauseFunc{},
		protocolJobs:   map[int64]map[string]*protocolPhaseJob{},
		captures:       map[int64]*protocolCapture{},
		profChatAgents: map[int64]*agent.ChatAgent{},
		provByProfile:  map[int64]*provEntry{}, llmHealth: newLLMHealthRegistry(m.pg),
	}
	if err := config.EnsureSecretKey(); err != nil {
		log.Printf("[security] secret key unavailable: %v", err)
	}
	if m.pg != nil {
		if n, err := m.pg.EncryptPlaintextProfileKeys(); err != nil {
			log.Printf("[security] encrypt plaintext API keys: %v", err)
		} else if n > 0 {
			log.Printf("[security] encrypted %d plaintext LLM API key(s)", n)
		}
	}
	s.initSideQuestions()

	pc := config.ProtocolConfig()
	s.protocolRunner = protocol.New(m.pg, pc.ToolsDir, pc.RunsDir, pc.Python, pc.Tshark, pc.Spec)
	s.protocolHub = newProtocolHub()
	if m.pg != nil {
		if err := m.pg.RecoverInterruptedProtocolRuns(); err != nil {
			log.Printf("[protocol] recover interrupted runs: %v", err)
		}
	}
	log.Printf("[protocol] tools=%s runs=%s python=%s tshark=%s spec=%s",
		pc.ToolsDir, pc.RunsDir, pc.Python, pc.Tshark, pc.Spec)
	s.applyRetryPolicy()

	if m.pg != nil {
		agent.PromptOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil {
				return "", false
			}
			t, err := m.pg.CurrentPrompt(a.ID)
			if err != nil || t == "" {
				return "", false
			}
			return t, true
		}
		agent.WrapupOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.WrapupPrompt == "" {
				return "", false
			}
			return a.WrapupPrompt, true
		}
		agent.WrapupMaxTurnsOverride = func(key string) (int, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.WrapupMaxTurns <= 0 {
				return 0, false
			}
			return a.WrapupMaxTurns, true
		}
		agent.WrapupTaskTimeoutOverride = func(key string) (string, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.TaskTimeoutWrapupPrompt == "" {
				return "", false
			}
			return a.TaskTimeoutWrapupPrompt, true
		}
		agent.WrapupTaskTimeoutTurnsOverride = func(key string) (int, bool) {
			a, err := m.pg.GetAgentByKey(key)
			if err != nil || a == nil || a.TaskTimeoutWrapupMaxTurns <= 0 {
				return 0, false
			}
			return a.TaskTimeoutWrapupMaxTurns, true
		}
		wireAgentAugment(m.pg, s.skillDir, s.hostTools) // skills/MCP + protocol/platform host tools
		wireToolCatalog(m.pg)                           // tools-table binding/overrides + usage ledger
		seedPrompts(m.pg)                               // protocol agent prompts
		s.seedProtocolAgent()                           // protocol host tools + agent bindings
		s.seedPythonInterpreter()                       // custom script tools
		go s.discoverEmptyMCPsOnStartup()
		logSink.SetDB(ctx, m.pg)
		s.startRetentionLoop(ctx)
	}

	// precedence: persisted DB config > env.
	if cfg, ok := s.loadLLMConfig(); ok {
		if err := s.applyLLM(cfg); err != nil {
			log.Printf("[llm] saved config init failed: %v", err)
		} else {
			log.Printf("[llm] configured from DB: %s / %s", cfg.Provider(), cfg.Model)
		}
	} else if cfg, ok := agent.FromEnv(); ok {
		if err := s.applyLLM(cfg); err != nil {
			log.Printf("[llm] env provider init failed: %v", err)
		} else {
			log.Printf("[llm] configured from env: %s / %s", cfg.Provider(), cfg.Model)
		}
	}
	return s
}
