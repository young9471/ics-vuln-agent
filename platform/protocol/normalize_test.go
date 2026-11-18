package protocol

import (
	"encoding/json"
	"testing"
)

func TestNormalizeFindingsMap(t *testing.T) {
	raw := `{
	  "notes":[
	    {"kind":"","payload":{"x":1}},
	    {"kind":"session-model-final","payload":{"payload":{"states":["ready"],"transitions":[]},"grade":"traffic"}},
	    {"kind":"session-model","payload":{"states":["a"]}}
	  ],
	  "field_maps":[
	    {"map_key":"m1","fields":[
	      {"name":"token","offset":31,"width":5,"kind":"ascii_token","values":"_INSE | +INSE"},
	      {"off":0,"size":2,"class":"constant"}
	    ]}
	  ]
	}`
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	stats := NormalizeFindingsMap(m)
	if stats.DroppedNotes != 1 {
		t.Fatalf("DroppedNotes=%d want 1", stats.DroppedNotes)
	}
	if stats.NormalizedNotes != 1 {
		t.Fatalf("NormalizedNotes=%d want 1", stats.NormalizedNotes)
	}
	if stats.NormalizedFields != 2 {
		t.Fatalf("NormalizedFields=%d want 2", stats.NormalizedFields)
	}

	var notes []map[string]any
	if err := json.Unmarshal(m["notes"], &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 {
		t.Fatalf("notes=%d want 2", len(notes))
	}
	final := notes[0]
	payload, _ := final["payload"].(map[string]any)
	if _, nested := payload["payload"]; nested {
		t.Fatal("nested payload should be unwrapped")
	}
	if payload["grade"] != "traffic" {
		t.Fatalf("outer metadata should be merged into payload: %#v", payload)
	}
	if _, ok := payload["states"]; !ok {
		t.Fatal("states missing after unwrap")
	}

	var maps []map[string]any
	if err := json.Unmarshal(m["field_maps"], &maps); err != nil {
		t.Fatal(err)
	}
	fields := maps[0]["fields"].([]any)
	first := fields[0].(map[string]any)
	if first["off"] != float64(31) || first["size"] != float64(5) || first["class"] != "ascii_token" {
		t.Fatalf("field keys not normalized: %#v", first)
	}
	if _, ok := first["values"].(string); !ok {
		t.Fatalf("string values must be preserved: %#v", first["values"])
	}

	// Idempotent: a second pass reports no repairs.
	again := NormalizeFindingsMap(m)
	if again != (NormalizeStats{}) {
		t.Fatalf("second pass should be a no-op, got %+v", again)
	}
}

func TestPruneNotesDeduplicatesAndCaps(t *testing.T) {
	m := map[string]json.RawMessage{
		"notes": json.RawMessage(`[
			{"kind":"session-model","payload":{"stream":"a","created_at":"t1"}},
			{"kind":"session-model","payload":{"stream":"a","created_at":"t2"}}
		]`),
	}
	stats := NormalizeFindingsMap(m)
	if stats.DedupedNotes != 1 {
		t.Fatalf("DedupedNotes=%d want 1", stats.DedupedNotes)
	}
	var notes []map[string]any
	if err := json.Unmarshal(m["notes"], &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("notes=%d want 1", len(notes))
	}

	items := make([]map[string]any, noteKindLimit+5)
	for i := range items {
		items[i] = map[string]any{"kind": "code-reconciliation", "payload": map[string]any{"i": i}}
	}
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	capped := map[string]json.RawMessage{"notes": raw}
	stats = PruneNotes(capped)
	if stats.CappedNotes != 5 {
		t.Fatalf("CappedNotes=%d want 5", stats.CappedNotes)
	}
	if err := json.Unmarshal(capped["notes"], &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != noteKindLimit {
		t.Fatalf("notes=%d want %d", len(notes), noteKindLimit)
	}
}
