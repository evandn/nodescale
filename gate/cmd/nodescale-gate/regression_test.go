package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/evandn/nodescale/gate/internal/gate"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

// F5: an oversized request is rejected before authentication, but the
// rejection is signed with the server identity (docs: pre-auth rejections are
// never signed).
func TestReviewOversizedRequestRejectionIsSigned(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	cfg := map[string]any{"rpId": "example.com", "origins": []string{"https://example.com"},
		"signers": []map[string]any{{"id": "AAAA", "alg": protocol.AlgEdDSA, "publicKey": protocol.B64(der), "role": "admin"}}}
	b, _ := json.Marshal(cfg)
	os.WriteFile(filepath.Join(dir, "gate.json"), b, 0o600)
	t.Setenv("NODESCALE_CONFIG", filepath.Join(dir, "gate.json"))
	t.Setenv("NODESCALE_STATE", dir)

	in, _ := os.CreateTemp(dir, "in")
	in.Write(make([]byte, gate.MaxRequestBytes+10))
	in.Seek(0, 0)
	out, _ := os.CreateTemp(dir, "out")
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = in, out
	shell()
	os.Stdin, os.Stdout = oldIn, oldOut

	raw, _ := os.ReadFile(out.Name())
	var sr protocol.SignedResponse
	if err := json.Unmarshal(raw, &sr); err != nil {
		t.Fatalf("output: %v %q", err, raw)
	}
	if sr.Signature != "" || sr.PublicKey != "" {
		p, _ := protocol.UnB64(sr.Payload)
		t.Fatalf("pre-auth rejection is signed by the server identity: %s", p)
	}
}
