package db

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONBCleanPassthrough(t *testing.T) {
	in := []byte(`{"run_id":1762345678901234567,"msg":"plain text","nested":{"a":[1,2,3]}}`)
	out := jsonbClean(in)
	if !bytes.Equal(in, out) {
		t.Fatalf("clean JSON without NUL should pass through unchanged, got %s", out)
	}
}

func TestJSONBCleanStripsNUL(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"run_id":      int64(1762345678901234567),
		"tool_output": "before" + "\x00" + "after",
		"list":        []any{"a\x00b", map[string]any{"deep\x00key": "v\x00"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := jsonbClean(raw)
	if !json.Valid(out) {
		t.Fatalf("output is not valid JSON: %s", out)
	}
	if strings.Contains(string(out), `\u0000`) {
		t.Fatalf("NUL escape survived cleaning: %s", out)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got["tool_output"] != "beforeafter" {
		t.Fatalf("tool_output=%q", got["tool_output"])
	}
	if got["run_id"].(float64) != 1762345678901234567 {
		t.Fatalf("int64 precision lost: %v", got["run_id"])
	}
	list := got["list"].([]any)
	if list[0] != "ab" {
		t.Fatalf("list[0]=%q", list[0])
	}
	deep := list[1].(map[string]any)
	if deep["deepkey"] != "v" {
		t.Fatalf("nested key/value not cleaned: %#v", deep)
	}
}

func TestJSONBCleanKeepsLiteralEscapeText(t *testing.T) {
	// A string that literally contains the six characters \u0000 must not be
	// mangled by the cleaning pass.
	raw, err := json.Marshal(map[string]any{"note": `text mentioning \u0000 literally`, "drop": "x\x00"})
	if err != nil {
		t.Fatal(err)
	}
	out := jsonbClean(raw)
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("invalid JSON after cleaning: %v (%s)", err, out)
	}
	if got["note"] != `text mentioning \u0000 literally` {
		t.Fatalf("literal escape text corrupted: %q", got["note"])
	}
	if got["drop"] != "x" {
		t.Fatalf("drop=%q", got["drop"])
	}
}

func TestJSONBCleanInvalid(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte(`{"broken":`)} {
		if out := jsonbClean(in); string(out) != "{}" {
			t.Fatalf("jsonbClean(%q)=%s want {}", in, out)
		}
	}
}
