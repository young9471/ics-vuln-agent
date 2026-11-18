//go:build integration

package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestIntegrationVulnDashboard guards the JSON-null / non-array sections that
// real P7 output can leave in findings ("vuln_hypotheses": null): one bad row
// used to abort the whole aggregation and silently zero every count.
func TestIntegrationVulnDashboard(t *testing.T) {
	pg := integrationDB(t)
	name := fmt.Sprintf("integration-dash-%d", time.Now().UnixNano())
	c, err := pg.CreateProtocolCase(ProtocolCaseInput{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteProtocolCase(c.ID) })

	// JSON null sections (the exact shape that broke COALESCE) plus real arrays.
	findings := map[string]any{
		"vuln_hypotheses": nil,
		"exploit_assets":  nil,
		"campaigns": []any{
			map[string]any{"campaign_id": "C-1", "mode": "fuzz"},
		},
	}
	raw, _ := json.Marshal(findings)
	if err := pg.SetProtocolCaseFindings(c.ID, raw); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	// Second case: real arrays only.
	c2, err := pg.CreateProtocolCase(ProtocolCaseInput{Name: name + "-2"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteProtocolCase(c2.ID) })
	raw2, _ := json.Marshal(map[string]any{
		"vuln_hypotheses": []any{
			map[string]any{"id": "H-1", "state": "confirmed", "vclass": 1, "risk": "read"},
			map[string]any{"id": "H-2", "state": "pending", "vclass": 3, "risk": "destructive"},
		},
		"exploit_assets": []any{
			map[string]any{"id": "EXP-H-1", "tier": "replay"},
		},
	})
	if err := pg.SetProtocolCaseFindings(c2.ID, raw2); err != nil {
		t.Fatalf("seed findings2: %v", err)
	}

	d, err := pg.VulnDashboard()
	if err != nil {
		t.Fatal(err)
	}
	if d.Hypotheses.Total < 2 || d.Hypotheses.ByState["confirmed"] < 1 {
		t.Fatalf("hypotheses not aggregated: %+v", d.Hypotheses)
	}
	if d.Exploits.Total < 1 || d.Exploits.ByTier["replay"] < 1 {
		t.Fatalf("exploits not aggregated: %+v", d.Exploits)
	}
	if d.Campaigns.ByMode["fuzz"] < 1 {
		t.Fatalf("campaigns not aggregated: %+v", d.Campaigns)
	}
	found := false
	for _, row := range d.CaseRows {
		if row.CaseID == c.ID && (row.Hypotheses != 0 || row.Exploits != 0) {
			t.Fatalf("json-null case should count as 0: %+v", row)
		}
		if row.CaseID == c2.ID && row.Hypotheses == 2 && row.Exploits == 1 && row.Confirmed == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("case posture row for c2 missing/wrong: %+v", d.CaseRows)
	}
}
