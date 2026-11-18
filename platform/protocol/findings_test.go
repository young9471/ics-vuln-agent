package protocol

import (
	"encoding/json"
	"testing"
)

func TestValidateFindingsAllowsStaticInferredFrames(t *testing.T) {
	staticFrame := map[string]json.RawMessage{
		"frame_formats": json.RawMessage(`[{"magic":"aa","frames":0,"source":"static","grade":"static"}]`),
	}
	if err := ValidateFindingsMap(staticFrame); err != nil {
		t.Fatalf("static inferred frame should validate: %v", err)
	}
	trafficFrame := map[string]json.RawMessage{
		"frame_formats": json.RawMessage(`[{"magic":"aa","frames":0}]`),
	}
	if err := ValidateFindingsMap(trafficFrame); err == nil {
		t.Fatal("traffic frame with zero observations must fail validation")
	}
	negative := map[string]json.RawMessage{
		"frame_formats": json.RawMessage(`[{"magic":"aa","frames":-1,"source":"static"}]`),
	}
	if err := ValidateFindingsMap(negative); err == nil {
		t.Fatal("negative frames must fail validation")
	}
}
