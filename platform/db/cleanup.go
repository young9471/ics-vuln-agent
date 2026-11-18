package db

// CleanupLegacyBrowserTools removes the old built-in browser MCP and the
// playwright-cli skill visibility once. Generic MCP/Skill management remains.
func (d *DB) CleanupLegacyBrowserTools() error {
	const flag = "cleanup_legacy_browser_v1"
	if v, _, _ := d.GetSetting(flag); v == "true" {
		return nil
	}
	if _, err := d.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp'
AND resource_id IN (SELECT id FROM mcp_servers WHERE name='browser' AND command='npx' AND args::text LIKE '%@playwright/mcp%')`); err != nil {
		return err
	}
	if _, err := d.Exec(`DELETE FROM mcp_servers WHERE name='browser' AND command='npx' AND args::text LIKE '%@playwright/mcp%'`); err != nil {
		return err
	}
	if _, err := d.Exec(`DELETE FROM agent_skill_visibility WHERE skill_name='playwright-cli'`); err != nil {
		return err
	}
	if _, err := d.Exec(`DELETE FROM skill_usage WHERE skill='playwright-cli'`); err != nil {
		return err
	}
	return d.SetSetting(flag, "true")
}
