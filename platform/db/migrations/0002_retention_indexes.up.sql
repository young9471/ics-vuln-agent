CREATE INDEX IF NOT EXISTS idx_llm_usage_ts ON llm_usage(ts);
CREATE INDEX IF NOT EXISTS idx_tool_usage_ts ON tool_usage(ts);
CREATE INDEX IF NOT EXISTS idx_protocol_events_created ON protocol_events(created_at);
