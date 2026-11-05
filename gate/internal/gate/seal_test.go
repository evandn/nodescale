package gate

import (
	"crypto/ecdh"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

// sealFor mirrors the browser: encrypt to the server's published seal key.
func sealFor(t *testing.T, g *Gate, plaintext, label string) string {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(g.SealPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	eph, _ := ecdh.X25519().GenerateKey(rand.Reader)
	shared, _ := eph.ECDH(pub)
	aead, err := sealAEAD(shared, eph.PublicKey().Bytes(), pub.Bytes(), g.id)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 12)
	rand.Read(iv)
	return sealPrefix + protocol.B64(eph.PublicKey().Bytes()) + "." + protocol.B64(iv) + "." + protocol.B64(aead.Seal(nil, iv, []byte(plaintext), []byte(label)))
}

// openFrom mirrors the browser opening a reply sealed to its ephemeral key.
func openFrom(t *testing.T, g *Gate, priv *ecdh.PrivateKey, sealed, label string) string {
	t.Helper()
	parts := strings.Split(strings.TrimPrefix(sealed, sealPrefix), ".")
	ephPub, _ := protocol.UnB64(parts[0])
	iv, _ := protocol.UnB64(parts[1])
	ct, _ := protocol.UnB64(parts[2])
	peer, _ := ecdh.X25519().NewPublicKey(ephPub)
	shared, _ := priv.ECDH(peer)
	aead, _ := sealAEAD(shared, ephPub, priv.PublicKey().Bytes(), g.id)
	pt, err := aead.Open(nil, iv, ct, []byte(label))
	if err != nil {
		t.Fatal(err)
	}
	return string(pt)
}

func TestSealRoundTrip(t *testing.T) {
	h := newHarness(t)
	g := h.a
	env := []string{"PLAIN=x", "DB_PASSWORD=" + sealFor(t, g, "s3cr=et", "DB_PASSWORD")}
	if err := g.unsealEnv(env); err != nil {
		t.Fatal(err)
	}
	if env[1] != "DB_PASSWORD=s3cr=et" || env[0] != "PLAIN=x" {
		t.Fatalf("unexpected env %v", env)
	}
	// A value sealed for one variable cannot be moved to another.
	moved := []string{"OTHER=" + sealFor(t, g, "v", "DB_PASSWORD")}
	if err := g.unsealEnv(moved); err == nil {
		t.Fatal("moved sealed value must not decrypt")
	}
	// Nor can a value sealed for another server be used here.
	other := newHarness(t)
	foreign := []string{"K=" + sealFor(t, other.a, "v", "K")}
	if err := g.unsealEnv(foreign); err == nil {
		t.Fatal("value sealed for another server must not decrypt")
	}
	// Reply sealing to a browser key.
	browser, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sealed, err := g.sealTo(browser.PublicKey().Bytes(), []byte(`["A=1"]`), "containers.env")
	if err != nil {
		t.Fatal(err)
	}
	if got := openFrom(t, g, browser, sealed, "containers.env"); got != `["A=1"]` {
		t.Fatalf("reply = %q", got)
	}
	// The seal key is stable across processes (derived from the identity).
	h.reload()
	if string(h.a.SealPublicKey()) != string(g.SealPublicKey()) {
		t.Fatal("seal key must be derived deterministically")
	}
}
