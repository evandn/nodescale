// Package protocol implements the nodescale signed-request protocol.
//
// Every request that reaches an agent is a JSON payload signed either directly
// by an enrolled WebAuthn passkey, or by a short-lived browser session key that
// was itself delegated by a passkey. The agent never trusts the transport (the
// Cloudflare-hosted control plane, the relay, or SSH): it verifies every
// signature against keys stored locally on the server.
//
// See docs/protocol.md for the full specification.
package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const Version = 1

// Payload types.
const (
	TypRequest  = "nodescale.request"
	TypSession  = "nodescale.session"
	TypResponse = "nodescale.response"
)

// Domain separation strings. A signature is always computed over
// domain || 0x00 || payload so that a signature for one purpose can never be
// replayed as another.
const (
	DomainRequest        = "nodescale/v1/request"
	DomainSession        = "nodescale/v1/session"
	DomainSessionRequest = "nodescale/v1/session-request"
	DomainResponse       = "nodescale/v1/response"
)

// Auth kinds.
const (
	AuthWebAuthn = "webauthn"
	AuthSession  = "session"
)

// Session scopes.
const (
	ScopeRead    = "read"
	ScopeOperate = "operate"
)

// SignedRequest is what travels over the wire to the agent.
type SignedRequest struct {
	// Payload is the base64url encoding of the exact JSON bytes that were signed.
	Payload string `json:"payload"`
	Auth    *Auth  `json:"auth,omitempty"`
}

// Auth carries the proof that an enrolled signer authorised Payload.
type Auth struct {
	Kind string `json:"kind"`
	// For Kind == "webauthn": an assertion over Challenge(DomainRequest, payload).
	Assertion *Assertion `json:"assertion,omitempty"`
	// For Kind == "session": a passkey-signed delegation certificate and an
	// ECDSA P-256 signature (raw r||s, base64url) by the delegated key over
	// Message(DomainSessionRequest, payload).
	Certificate *Certificate `json:"certificate,omitempty"`
	Signature   string       `json:"signature,omitempty"`
}

// Assertion is a serialized WebAuthn AuthenticatorAssertionResponse.
type Assertion struct {
	CredentialID      string `json:"credentialId"`
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
}

// Certificate delegates a subset of a passkey's authority to an ephemeral,
// non-extractable browser key.
type Certificate struct {
	Payload   string     `json:"payload"`
	Assertion *Assertion `json:"assertion"`
}

// Request is the decoded request payload.
type Request struct {
	V     int             `json:"v"`
	Typ   string          `json:"typ"`
	Aud   string          `json:"aud"`
	Op    string          `json:"op"`
	Args  json.RawMessage `json:"args,omitempty"`
	Iat   int64           `json:"iat"`
	Exp   int64           `json:"exp"`
	Nonce string          `json:"nonce"`
}

// SessionCert is the decoded certificate payload.
type SessionCert struct {
	V     int      `json:"v"`
	Typ   string   `json:"typ"`
	Key   string   `json:"key"` // base64url SPKI of a P-256 public key
	Aud   []string `json:"aud"` // agent IDs, or ["*"]
	Scope string   `json:"scope"`
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	Nonce string   `json:"nonce"`
}

// Response is the decoded response payload, signed by the agent identity key.
type Response struct {
	V      int             `json:"v"`
	Typ    string          `json:"typ"`
	Agent  string          `json:"agent"`
	Req    string          `json:"req"`
	Ok     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
	Ts     int64           `json:"ts"`
}

// SignedResponse is what the agent writes back.
type SignedResponse struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// Error is a machine-readable failure.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds a protocol error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Error codes.
const (
	CodeBadRequest   = "bad_request"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeReplay       = "replay"
	CodeExpired      = "expired"
	CodeNotFound     = "not_found"
	CodeConflict     = "conflict"
	CodeInternal     = "internal"
	CodeUnsupported  = "unsupported"
)

// Message returns domain || 0x00 || payload.
func Message(domain string, payload []byte) []byte {
	m := make([]byte, 0, len(domain)+1+len(payload))
	m = append(m, domain...)
	m = append(m, 0)
	m = append(m, payload...)
	return m
}

// Challenge returns SHA-256(Message(domain, payload)); it is used as the
// WebAuthn challenge when a passkey signs a payload directly.
func Challenge(domain string, payload []byte) []byte {
	h := sha256.Sum256(Message(domain, payload))
	return h[:]
}

// RequestHash identifies a request in responses and audit logs.
func RequestHash(payload []byte) string {
	h := sha256.Sum256(payload)
	return B64(h[:])
}

// AgentID derives the self-certifying agent identifier from its Ed25519 key.
func AgentID(pub []byte) string {
	h := sha256.Sum256(pub)
	return "ag_" + hex.EncodeToString(h[:16])
}

// B64 encodes base64url without padding.
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UnB64 decodes base64url, tolerating padding.
func UnB64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base64url value")
	}
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return base64.RawURLEncoding.DecodeString(s)
}
