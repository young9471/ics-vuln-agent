package agent

// WebSearchOpts is the per-run web-search configuration passed to ChatAgent and
// the other conversational agents.
type WebSearchOpts struct {
	Enabled         bool
	Backend         string
	BraveKey        string
	TavilyKey       string
	DeepSeekBaseURL string
	DeepSeekAPIKey  string
	DeepSeekModel   string
	Proxy           string
}
