package gate

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

// Sealed values give end-to-end secrecy between the browser and a server:
// the console and relay carry them but cannot read them.
//
//	nsseal1.<b64 ephemeral X25519 public>.<b64 12-byte IV>.<b64 AES-256-GCM ciphertext>
//
// key = HKDF-SHA256(X25519(eph, recipient), salt = eph_pub || recipient_pub,
//
//	info = "nodescale/v1/seal" || 0x00 || agentID)
//
// AAD = label (for environment variables, the variable name), so the console
// cannot move a sealed value to another variable.
const sealPrefix = "nsseal1."

func deriveSeed(priv ed25519.PrivateKey, info string) []byte {
	k, _ := hkdf.Key(sha256.New, priv.Seed(), nil, info, 32)
	return k
}

func (g *Gate) sealKey() *ecdh.PrivateKey {
	k, _ := ecdh.X25519().NewPrivateKey(deriveSeed(g.priv, "nodescale/v1/x25519"))
	return k
}

// SealPublicKey is published in agent.hello and pinned with the identity.
func (g *Gate) SealPublicKey() []byte { return g.sealKey().PublicKey().Bytes() }

func sealAEAD(shared, ephPub, recipientPub []byte, agentID string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recipientPub...), "nodescale/v1/seal\x00"+agentID, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// unseal decrypts a value sealed to this server.
func (g *Gate) unseal(value, label string) (string, error) {
	parts := strings.Split(strings.TrimPrefix(value, sealPrefix), ".")
	if len(parts) != 3 {
		return "", errors.New("malformed sealed value")
	}
	ephPub, err1 := protocol.UnB64(parts[0])
	iv, err2 := protocol.UnB64(parts[1])
	ct, err3 := protocol.UnB64(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 {
		return "", errors.New("malformed sealed value")
	}
	peer, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return "", err
	}
	priv := g.sealKey()
	shared, err := priv.ECDH(peer)
	if err != nil {
		return "", err
	}
	aead, err := sealAEAD(shared, ephPub, priv.PublicKey().Bytes(), g.id)
	if err != nil {
		return "", err
	}
	pt, err := aead.Open(nil, iv, ct, []byte(label))
	if err != nil {
		return "", errors.New("cannot decrypt (sealed for another server or variable?)")
	}
	return string(pt), nil
}

// sealTo encrypts plaintext to a browser's ephemeral X25519 key.
func (g *Gate) sealTo(recipient []byte, plaintext []byte, label string) (string, error) {
	peer, err := ecdh.X25519().NewPublicKey(recipient)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return "", err
	}
	aead, err := sealAEAD(shared, eph.PublicKey().Bytes(), recipient, g.id)
	if err != nil {
		return "", err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, iv, plaintext, []byte(label))
	return sealPrefix + protocol.B64(eph.PublicKey().Bytes()) + "." + protocol.B64(iv) + "." + protocol.B64(ct), nil
}

// unsealEnv decrypts sealed values in KEY=value entries in place.
func (g *Gate) unsealEnv(env []string) error {
	for i, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if ok && strings.HasPrefix(v, sealPrefix) {
			pt, err := g.unseal(v, k)
			if err != nil {
				return bad("environment variable %s: %v", k, err)
			}
			env[i] = k + "=" + pt
		}
	}
	return nil
}

// specMAC keys stack spec hashes so the hash label on a container (visible to
// anyone who can inspect it) cannot be used to guess secret values.
func (g *Gate) specMAC(data []byte) string {
	m := hmac.New(sha256.New, deriveSeed(g.priv, "nodescale/v1/spec-hash"))
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil)[:12])
}
