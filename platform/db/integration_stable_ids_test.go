//go:build integration

package db

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Report evidence references use row IDs ([asset:<id>] etc.), so repeated
// findings syncs must not renumber the rows. This test mirrors a P3/P4 → P5 →
// P6 sync sequence and asserts primary keys stay stable.
func TestIntegrationFindingsIDsStableAcrossSyncs(t *testing.T) {
	pg := integrationDB(t)
	c, err := pg.CreateProtocolCase(ProtocolCaseInput{Name: fmt.Sprintf("integration-stable-ids-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pg.DeleteProtocolCase(c.ID) })

	first := json.RawMessage(`{
	  "comm_assets":[{"path":"C:/app/comm.dll","score":9}],
	  "streams":[{"pcap":"a.pcapng","stream":1,"protocol":"tcp"}],
	  "frame_formats":[{"key":"f1","stream":1,"magic":"aa","header_size":8,"frames":3,"source":"traffic"}],
	  "field_maps":[{"key":"m1","direction":"req","fields":[]}],
	  "function_codes":[{"layer":"traffic","code":"0x01","label":"read","source":"traffic"}],
	  "probes":[{"kind":"p5-live","host":"192.168.1.20","port":2455,"action":"code 0x0106","code":"0x0106","status":"pending","grade":"live"}],
	  "notes":[{"kind":"session-model","payload":{}}]
	}`)
	if err := pg.ReplaceProtocolFindings(c.ID, first); err != nil {
		t.Fatal(err)
	}
	before, err := pg.GetProtocolFindings(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Assets) != 1 || len(before.Frames) != 1 || len(before.Fields) != 1 || len(before.Codes) != 1 || len(before.Probes) != 1 {
		t.Fatalf("unexpected initial rows: assets=%d frames=%d fields=%d codes=%d probes=%d",
			len(before.Assets), len(before.Frames), len(before.Fields), len(before.Codes), len(before.Probes))
	}

	// Same identities with changed labels/outcome: IDs must not move.
	second := json.RawMessage(`{
	  "comm_assets":[{"path":"C:/app/comm.dll","score":9,"name":"renamed"}],
	  "streams":[{"pcap":"a.pcapng","stream":1,"protocol":"tcp"}],
	  "frame_formats":[{"key":"f1","stream":1,"magic":"aa","header_size":8,"frames":4,"source":"traffic"}],
	  "field_maps":[{"key":"m1","direction":"req","fields":[]}],
	  "function_codes":[{"layer":"traffic","code":"0x01","label":"read updated","source":"traffic"}],
	  "probes":[{"kind":"p5-live","host":"192.168.1.20","port":2455,"action":"code 0x0106","code":"0x0106","status":"ok","grade":"live"}],
	  "notes":[{"kind":"session-model","payload":{}}]
	}`)
	if err := pg.ReplaceProtocolFindings(c.ID, second); err != nil {
		t.Fatal(err)
	}
	after, err := pg.GetProtocolFindings(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		kind string
		a, b int64
	}{
		{"asset", before.Assets[0].ID, after.Assets[0].ID},
		{"frame", before.Frames[0].ID, after.Frames[0].ID},
		{"field", before.Fields[0].ID, after.Fields[0].ID},
		{"code", before.Codes[0].ID, after.Codes[0].ID},
		{"probe", before.Probes[0].ID, after.Probes[0].ID},
	} {
		if row.a != row.b {
			t.Fatalf("%s id drifted across sync: %d -> %d", row.kind, row.a, row.b)
		}
	}

	// Removing entries deletes stale rows; surviving rows keep their IDs.
	third := json.RawMessage(`{
	  "comm_assets":[],
	  "streams":[{"pcap":"a.pcapng","stream":1,"protocol":"tcp"}],
	  "frame_formats":[{"key":"f1","stream":1,"magic":"aa","header_size":8,"frames":4,"source":"traffic"}],
	  "field_maps":[],
	  "function_codes":[],
	  "probes":[],
	  "notes":[]
	}`)
	if err := pg.ReplaceProtocolFindings(c.ID, third); err != nil {
		t.Fatal(err)
	}
	final, err := pg.GetProtocolFindings(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Assets) != 0 || len(final.Fields) != 0 || len(final.Codes) != 0 || len(final.Probes) != 0 {
		t.Fatalf("stale rows survived: assets=%d fields=%d codes=%d probes=%d",
			len(final.Assets), len(final.Fields), len(final.Codes), len(final.Probes))
	}
	if len(final.Frames) != 1 || final.Frames[0].ID != before.Frames[0].ID {
		t.Fatalf("frame rows/id changed: %+v", final.Frames)
	}
}
