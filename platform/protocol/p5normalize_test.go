package protocol

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/protocol-agent/db"
)

func TestNormalizeP5FindingsContract(t *testing.T) {
	raw := map[string]json.RawMessage{
		"function_codes": json.RawMessage(`[
			{"code":"0x2101","verdict":"confirmed"},
			{"code":"0x110b","verdict":"unverified"},
			{"code":"0x1003(hyp)","verdict":"refuted"}
		]`),
		"notes": json.RawMessage(`[{"kind":"code-reconciliation","items":[
			{"code":"0x2101","verdict":"matched"},
			{"code":"0x110b","verdict":"consistent"},
			{"code":"0x1003(hyp)","verdict":"consistent"}
		]}]`),
		"frame_formats": json.RawMessage(`[{"stream":"tcp:5562 client->plc","magic":"0x57 0x01"}]`),
		"field_maps":    json.RawMessage(`[{"map_key":"static-request"}]`),
		"probes":        json.RawMessage(`[{"kind":"live-probe","action":"identify","code":"0x2101","request":"aa"}]`),
	}
	NormalizeP5Findings(raw)

	var codes []map[string]any
	if err := json.Unmarshal(raw["function_codes"], &codes); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"0x2101": "matched", "0x110b": "single-source", "0x1003(hyp)": "single-source"}
	for _, c := range codes {
		if got := c["verdict"]; got != want[c["code"].(string)] {
			t.Errorf("code %v verdict=%v want %v", c["code"], got, want[c["code"].(string)])
		}
	}

	var frames []map[string]any
	_ = json.Unmarshal(raw["frame_formats"], &frames)
	if frames[0]["key"] == "" || frames[0]["key"] == nil {
		t.Fatal("traffic frame key was not generated")
	}
	if got := frames[0]["key"]; got != db.FrameKeyFor(frames[0]) {
		t.Fatalf("frame key=%v want %v", got, db.FrameKeyFor(frames[0]))
	}

	var fields []map[string]any
	_ = json.Unmarshal(raw["field_maps"], &fields)
	if fields[0]["key"] != "static-request" {
		t.Fatalf("field key=%v", fields[0]["key"])
	}

	var probes []map[string]any
	_ = json.Unmarshal(raw["probes"], &probes)
	if probes[0]["probe_key"] == "" || probes[0]["probe_key"] == nil {
		t.Fatal("probe_key was not generated")
	}
	if got := probes[0]["probe_key"]; got != db.ProbeKeyFor(probes[0]) {
		t.Fatalf("probe_key=%v want %v", got, db.ProbeKeyFor(probes[0]))
	}
}
