package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

type tsVectors struct {
	RPID      string `json:"rpId"`
	Origin    string `json:"origin"`
	Now       int64  `json:"now"`
	AgentSeed string `json:"agentSeed"`
	AgentID   string `json:"agentId"`
	Signer    Signer `json:"signer"`
	Requests  []struct {
		Name    string          `json:"name"`
		Request json.RawMessage `json:"request"`
	} `json:"requests"`
}

// TestTypeScriptVectors checks that requests produced by the browser
// implementation (packages/protocol) verify in the agent.
func TestTypeScriptVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/ts-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v tsVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Config{RPID: v.RPID, Origins: []string{v.Origin}, Signers: []Signer{v.Signer}}
	cb, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(dir, "agent.json"), cb, 0o600)
	os.WriteFile(filepath.Join(dir, "identity.key"), []byte(v.AgentSeed+"\n"), 0o600)

	now := time.Unix(v.Now, 0)
	a, err := New(Options{Paths: Paths{Config: filepath.Join(dir, "agent.json"), Identity: filepath.Join(dir, "identity.key"), State: dir}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != v.AgentID {
		t.Fatalf("agent id derivation differs: go=%s ts=%s", a.ID(), v.AgentID)
	}

	type vectorOut struct {
		Name     string                  `json:"name"`
		Payload  string                  `json:"requestPayload"`
		Response protocol.SignedResponse `json:"response"`
	}
	var outs []vectorOut
	for _, r := range v.Requests {
		raw := a.Handle(context.Background(), r.Request)
		var sr protocol.SignedResponse
		json.Unmarshal(raw, &sr)
		p, _ := protocol.UnB64(sr.Payload)
		var resp protocol.Response
		json.Unmarshal(p, &resp)
		if !resp.Ok {
			t.Errorf("%s: %+v", r.Name, resp.Error)
		}
		var req protocol.SignedRequest
		json.Unmarshal(r.Request, &req)
		outs = append(outs, vectorOut{Name: r.Name, Payload: req.Payload, Response: sr})
	}

	// Responses signed here are verified by packages/protocol/test.
	if os.Getenv("UPDATE_VECTORS") != "" {
		ob, _ := json.MarshalIndent(map[string]any{"agentId": a.ID(), "vectors": outs}, "", "  ")
		if err := os.WriteFile("../../../packages/protocol/test/go-vectors.json", append(ob, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
