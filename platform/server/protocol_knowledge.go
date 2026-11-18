package server

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/protocol-agent/db"
)

// protocolKnowledgeFromCase builds a compact, non-secret fingerprint from the
// normalized findings. It is stored after a P6 pass and used by P1/P4 as a
// hypothesis source; it never replaces current-case evidence.
func protocolKnowledgeFromCase(c *db.ProtocolCase, f *db.ProtocolFindings) *db.ProtocolKnowledge {
	if c == nil || f == nil {
		return nil
	}
	ports := map[string]bool{}
	for _, s := range f.Streams {
		if s.Sport > 0 {
			ports[fmt.Sprintf("%d", s.Sport)] = true
		}
		if s.Dport > 0 {
			ports[fmt.Sprintf("%d", s.Dport)] = true
		}
	}
	// Canonical findings may use client/server/server_port schema instead of the
	// normalized src/dst/sport/dport columns. Read raw streams as a fallback.
	var raw struct {
		Streams []map[string]any `json:"streams"`
		Frames  []map[string]any `json:"frame_formats"`
	}
	_ = json.Unmarshal(f.Raw, &raw)
	for _, stream := range raw.Streams {
		addKnowledgePort(ports, stream["server_port"])
		addKnowledgePort(ports, stream["client_port"])
		for _, v := range objectList(stream["umbrella_ports_observed"]) {
			addKnowledgePort(ports, v)
		}
		for _, fd := range objectList(stream["flow_detail"]) {
			addPortFromTuple(ports, knowledgeStr(fd["tuple"]))
		}
		addPortFromTuple(ports, knowledgeStr(stream["src"]))
		addPortFromTuple(ports, knowledgeStr(stream["dst"]))
	}
	portList := make([]string, 0, len(ports))
	for p := range ports {
		portList = append(portList, p)
	}
	sort.Strings(portList)

	magics := map[string]bool{}
	for _, fr := range f.Frames {
		if strings.TrimSpace(fr.Magic) != "" {
			magics[fr.Magic] = true
		}
		if strings.TrimSpace(fr.AltMagic) != "" {
			magics[fr.AltMagic] = true
		}
	}
	for _, frame := range raw.Frames {
		for _, key := range []string{"magic", "alt_magic"} {
			if v := knowledgeStr(frame[key]); v != "" {
				magics[v] = true
			}
		}
	}
	magicList := make([]string, 0, len(magics))
	for m := range magics {
		magicList = append(magicList, m)
	}
	sort.Strings(magicList)

	layers := map[string]bool{}
	grades := map[string]int{}
	for _, code := range f.Codes {
		if code.Layer != "" {
			layers[code.Layer] = true
		}
		grades[code.Grade]++
	}
	layerList := make([]string, 0, len(layers))
	for l := range layers {
		layerList = append(layerList, l)
	}
	sort.Strings(layerList)
	gradeParts := make([]string, 0, len(grades))
	for g, n := range grades {
		gradeParts = append(gradeParts, fmt.Sprintf("%s=%d", g, n))
	}
	sort.Strings(gradeParts)

	stateSummary := ""
	for _, n := range f.Notes {
		var obj map[string]any
		if json.Unmarshal(n.Payload, &obj) != nil {
			continue
		}
		if knowledgeStr(obj["kind"]) == "session-model" {
			stateSummary = fmt.Sprintf("messages=%v transitions=%d; %s",
				obj["messages"], len(objectList(obj["transitions"])), knowledgeStr(obj["summary"]))
			break
		}
	}

	fingerprint, _ := json.Marshal(map[string]any{
		"ports": portList, "magic": magicList,
		"streams": len(f.Streams), "frames": len(f.Frames), "fields": len(f.Fields),
		"codes": len(f.Codes), "probes": len(f.Probes), "layers": layerList,
		"grades": grades,
	})
	return &db.ProtocolKnowledge{
		Name:         c.Name,
		Protocol:     strings.Join(layerList, ","),
		Ports:        strings.Join(portList, ","),
		Magic:        strings.Join(magicList, ","),
		FrameSummary: fmt.Sprintf("%d frame formats, %d field maps", len(f.Frames), len(f.Fields)),
		CodeSummary:  fmt.Sprintf("%d codes (%s)", len(f.Codes), strings.Join(gradeParts, ", ")),
		StateSummary: stateSummary,
		Fingerprint:  fingerprint,
		SourceCaseID: c.ID,
	}
}

func (s *Server) storeProtocolKnowledge(c *db.ProtocolCase) {
	if s.m == nil || s.m.pg == nil || c == nil {
		return
	}
	f, err := s.m.pg.GetProtocolFindings(c.ID)
	if err != nil {
		log.Printf("[knowledge] load case %d: %v", c.ID, err)
		return
	}
	k := protocolKnowledgeFromCase(c, f)
	if k == nil {
		return
	}
	if err := s.m.pg.UpsertProtocolKnowledge(k); err != nil {
		log.Printf("[knowledge] save case %d: %v", c.ID, err)
	}
}

func knowledgeStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// objectList is a small local decoder for JSON arrays of objects.
func objectList(raw any) []map[string]any {
	if raw == nil {
		return nil
	}
	b, _ := json.Marshal(raw)
	var out []map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func addKnowledgePort(ports map[string]bool, v any) {
	switch x := v.(type) {
	case float64:
		if x > 0 {
			ports[strconv.Itoa(int(x))] = true
		}
	case int:
		if x > 0 {
			ports[strconv.Itoa(x)] = true
		}
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil && n > 0 {
			ports[strconv.Itoa(n)] = true
		}
	}
}

func addPortFromTuple(ports map[string]bool, tuple string) {
	parts := strings.Split(tuple, ":")
	if len(parts) < 2 {
		return
	}
	addKnowledgePort(ports, parts[len(parts)-1])
}
