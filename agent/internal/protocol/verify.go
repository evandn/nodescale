package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// COSE algorithm identifiers supported for passkeys.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// WebAuthn authenticator data flags.
const (
	FlagUserPresent  = 0x01
	FlagUserVerified = 0x04
)

// PublicKey is a parsed passkey public key.
type PublicKey struct {
	Alg int
	Key crypto.PublicKey
}

// ParsePublicKey parses a base64url SPKI public key for the given COSE alg.
func ParsePublicKey(alg int, spkiB64 string) (*PublicKey, error) {
	der, err := UnB64(spkiB64)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	switch alg {
	case AlgES256:
		ek, ok := k.(*ecdsa.PublicKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, errors.New("public key: ES256 requires a P-256 key")
		}
	case AlgEdDSA:
		if _, ok := k.(ed25519.PublicKey); !ok {
			return nil, errors.New("public key: EdDSA requires an Ed25519 key")
		}
	case AlgRS256:
		rk, ok := k.(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < 2048 {
			return nil, errors.New("public key: RS256 requires an RSA key of at least 2048 bits")
		}
	default:
		return nil, fmt.Errorf("public key: unsupported COSE algorithm %d", alg)
	}
	return &PublicKey{Alg: alg, Key: k}, nil
}

// Verify checks sig over data using the passkey algorithm.
func (p *PublicKey) Verify(data, sig []byte) bool {
	switch p.Alg {
	case AlgES256:
		h := sha256.Sum256(data)
		return ecdsa.VerifyASN1(p.Key.(*ecdsa.PublicKey), h[:], sig)
	case AlgEdDSA:
		return ed25519.Verify(p.Key.(ed25519.PublicKey), data, sig)
	case AlgRS256:
		h := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(p.Key.(*rsa.PublicKey), crypto.SHA256, h[:], sig) == nil
	}
	return false
}

// RelyingParty describes what a valid assertion must be bound to.
type RelyingParty struct {
	ID                      string
	Origins                 []string
	RequireUserVerification bool
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// VerifyAssertion verifies a WebAuthn assertion over challenge. requireUV
// forces the user-verified flag regardless of the relying-party default.
func VerifyAssertion(rp RelyingParty, key *PublicKey, a *Assertion, challenge []byte, requireUV bool) error {
	if a == nil {
		return Errorf(CodeUnauthorized, "missing assertion")
	}
	cdj, err := UnB64(a.ClientDataJSON)
	if err != nil {
		return Errorf(CodeBadRequest, "clientDataJSON: %v", err)
	}
	authData, err := UnB64(a.AuthenticatorData)
	if err != nil {
		return Errorf(CodeBadRequest, "authenticatorData: %v", err)
	}
	sig, err := UnB64(a.Signature)
	if err != nil {
		return Errorf(CodeBadRequest, "signature: %v", err)
	}

	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return Errorf(CodeBadRequest, "clientDataJSON: %v", err)
	}
	if cd.Type != "webauthn.get" {
		return Errorf(CodeUnauthorized, "unexpected clientData type %q", cd.Type)
	}
	got, err := UnB64(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return Errorf(CodeUnauthorized, "challenge does not match the signed payload")
	}
	if !slices.Contains(rp.Origins, cd.Origin) {
		return Errorf(CodeUnauthorized, "origin %q is not trusted by this agent", cd.Origin)
	}
	if cd.CrossOrigin {
		return Errorf(CodeUnauthorized, "cross-origin assertions are not accepted")
	}

	if len(authData) < 37 {
		return Errorf(CodeBadRequest, "authenticatorData too short")
	}
	rpHash := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(authData[:32], rpHash[:]) {
		return Errorf(CodeUnauthorized, "assertion is for a different relying party")
	}
	flags := authData[32]
	if flags&FlagUserPresent == 0 {
		return Errorf(CodeUnauthorized, "user presence flag not set")
	}
	if (requireUV || rp.RequireUserVerification) && flags&FlagUserVerified == 0 {
		return Errorf(CodeUnauthorized, "user verification (PIN/biometric) is required")
	}

	cdHash := sha256.Sum256(cdj)
	signed := make([]byte, 0, len(authData)+32)
	signed = append(signed, authData...)
	signed = append(signed, cdHash[:]...)
	if !key.Verify(signed, sig) {
		return Errorf(CodeUnauthorized, "invalid passkey signature")
	}
	return nil
}

// ParseSessionKey parses the P-256 delegated session key from a certificate.
func ParseSessionKey(spkiB64 string) (*ecdsa.PublicKey, error) {
	der, err := UnB64(spkiB64)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("session key must be ECDSA P-256")
	}
	return ek, nil
}

// VerifyRawP256 verifies a WebCrypto-style (IEEE P1363, r||s) ECDSA P-256
// SHA-256 signature.
func VerifyRawP256(pub *ecdsa.PublicKey, data, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256(data)
	return ecdsa.Verify(pub, h[:], r, s)
}
