package agent

import (
	"bytes"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/evandn/nodescale/agent/internal/protocol"
)

// Level is the privilege an operation requires.
type Level int

const (
	LevelPublic Level = iota
	LevelRead
	LevelOperate
	LevelAdmin
)

func (l Level) String() string {
	return [...]string{"public", "read", "operate", "admin"}[l]
}

// Ops is the complete catalogue of operations the agent understands, and the
// level each one needs. Anything not listed here is rejected. This table is
// mirrored in packages/protocol/src/ops.ts.
var Ops = map[string]Level{
	"agent.hello": LevelPublic,

	"agent.info":         LevelRead,
	"system.info":        LevelRead,
	"containers.list":    LevelRead,
	"containers.inspect": LevelRead,
	"containers.logs":    LevelRead,
	"containers.stats":   LevelRead,
	"images.list":        LevelRead,
	"networks.list":      LevelRead,
	"signers.list":       LevelRead,

	"containers.start":   LevelOperate,
	"containers.stop":    LevelOperate,
	"containers.restart": LevelOperate,

	"containers.create": LevelAdmin,
	"containers.remove": LevelAdmin,
	"images.pull":       LevelAdmin,
	"images.remove":     LevelAdmin,
	"signers.add":       LevelAdmin,
	"signers.remove":    LevelAdmin,
}

func roleLevel(role string) Level {
	switch role {
	case RoleAdmin:
		return LevelAdmin
	case RoleOperator:
		return LevelOperate
	case RoleViewer:
		return LevelRead
	}
	return LevelPublic
}

func scopeLevel(scope string) Level {
	switch scope {
	case protocol.ScopeOperate:
		return LevelOperate
	case protocol.ScopeRead:
		return LevelRead
	}
	return LevelPublic
}

// Verified is a request that passed every check.
type Verified struct {
	Req      *protocol.Request
	Payload  []byte
	Level    Level
	Signer   *Signer // nil for public operations
	AuthKind string
}

// nonceCache remembers request nonces until they expire so that a captured
// request cannot be replayed.
type nonceCache struct {
	mu      sync.Mutex
	entries map[string]int64
}

const maxNonces = 200_000

func (n *nonceCache) use(nonce string, until, now int64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.entries == nil {
		n.entries = map[string]int64{}
	}
	if len(n.entries) > maxNonces/2 {
		for k, exp := range n.entries {
			if exp < now {
				delete(n.entries, k)
			}
		}
	}
	if _, seen := n.entries[nonce]; seen {
		return false
	}
	if len(n.entries) >= maxNonces {
		return false
	}
	n.entries[nonce] = until
	return true
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// verify authenticates and authorises a signed request.
func (a *Agent) verify(sr *protocol.SignedRequest, now time.Time) (*Verified, *protocol.Error) {
	payload, err := protocol.UnB64(sr.Payload)
	if err != nil || len(payload) > 256<<10 {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "payload must be base64url JSON under 256 KiB")
	}
	var req protocol.Request
	if err := decodeStrict(payload, &req); err != nil {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "payload: %v", err)
	}
	if req.V != protocol.Version || req.Typ != protocol.TypRequest {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "unsupported payload version or type")
	}
	level, ok := Ops[req.Op]
	if !ok {
		return nil, protocol.Errorf(protocol.CodeUnsupported, "unknown operation %q", req.Op)
	}
	v := &Verified{Req: &req, Payload: payload, Level: level}

	if level == LevelPublic {
		if req.Aud != a.id && req.Aud != "*" {
			return nil, protocol.Errorf(protocol.CodeForbidden, "request is addressed to a different agent")
		}
		return v, nil
	}

	cfg := a.config()
	pol := cfg.Policy.withDefaults()
	ts := now.Unix()
	skew := pol.ClockSkewSeconds

	if req.Aud != a.id {
		return nil, protocol.Errorf(protocol.CodeForbidden, "request is addressed to a different agent")
	}
	if len(req.Nonce) < 16 || len(req.Nonce) > 64 {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "nonce must be 16-64 characters")
	}
	if req.Exp <= req.Iat || req.Exp-req.Iat > pol.MaxRequestSeconds {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "request lifetime must be between 1 and %d seconds", pol.MaxRequestSeconds)
	}
	if req.Iat > ts+skew {
		return nil, protocol.Errorf(protocol.CodeExpired, "request issued in the future; check clocks")
	}
	if req.Exp < ts-skew {
		return nil, protocol.Errorf(protocol.CodeExpired, "request expired")
	}
	// A request issued before this process started could have been executed
	// by the previous process, whose nonce cache is gone.
	if req.Iat < a.bootTime.Unix() {
		return nil, protocol.Errorf(protocol.CodeExpired, "request predates agent start; retry")
	}

	rp := protocol.RelyingParty{ID: cfg.RPID, Origins: cfg.Origins}
	if sr.Auth == nil {
		return nil, protocol.Errorf(protocol.CodeUnauthorized, "operation %q requires a signature", req.Op)
	}

	switch sr.Auth.Kind {
	case protocol.AuthWebAuthn:
		s := cfg.signer(sr.Auth.Assertion)
		if s == nil {
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "passkey is not enrolled on this server")
		}
		// State-changing operations always need user verification.
		requireUV := level >= LevelOperate
		if err := protocol.VerifyAssertion(rp, s.key, sr.Auth.Assertion, protocol.Challenge(protocol.DomainRequest, payload), requireUV); err != nil {
			return nil, asProtoErr(err)
		}
		v.Signer, v.AuthKind = s, protocol.AuthWebAuthn

	case protocol.AuthSession:
		if level >= LevelAdmin {
			return nil, protocol.Errorf(protocol.CodeForbidden, "operation %q requires a fresh passkey signature", req.Op)
		}
		c := sr.Auth.Certificate
		if c == nil || c.Assertion == nil {
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "missing session certificate")
		}
		certPayload, err := protocol.UnB64(c.Payload)
		if err != nil || len(certPayload) > 16<<10 {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "invalid session certificate encoding")
		}
		var cert protocol.SessionCert
		if err := decodeStrict(certPayload, &cert); err != nil {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "session certificate: %v", err)
		}
		if cert.V != protocol.Version || cert.Typ != protocol.TypSession {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "unsupported session certificate")
		}
		if !slices.Contains(cert.Aud, "*") && !slices.Contains(cert.Aud, a.id) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session certificate is not valid for this agent")
		}
		if !slices.Contains(pol.AllowSessionScopes, cert.Scope) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session scope %q is not allowed by this agent's policy", cert.Scope)
		}
		if cert.Exp <= cert.Iat || cert.Exp-cert.Iat > pol.MaxSessionSeconds {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session lifetime exceeds this agent's policy (%ds)", pol.MaxSessionSeconds)
		}
		if cert.Iat > ts+skew || cert.Exp < ts-skew {
			return nil, protocol.Errorf(protocol.CodeExpired, "session certificate expired; unlock again")
		}
		if req.Exp > cert.Exp+skew {
			return nil, protocol.Errorf(protocol.CodeExpired, "request outlives its session certificate")
		}
		if scopeLevel(cert.Scope) < level {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session scope %q does not allow %q", cert.Scope, req.Op)
		}
		s := cfg.signer(c.Assertion)
		if s == nil {
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "passkey is not enrolled on this server")
		}
		// Starting a session always requires user verification.
		if err := protocol.VerifyAssertion(rp, s.key, c.Assertion, protocol.Challenge(protocol.DomainSession, certPayload), true); err != nil {
			return nil, asProtoErr(err)
		}
		sessionKey, err := protocol.ParseSessionKey(cert.Key)
		if err != nil {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "session key: %v", err)
		}
		sig, err := protocol.UnB64(sr.Auth.Signature)
		if err != nil || !protocol.VerifyRawP256(sessionKey, protocol.Message(protocol.DomainSessionRequest, payload), sig) {
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "invalid session signature")
		}
		v.Signer, v.AuthKind = s, protocol.AuthSession

	default:
		return nil, protocol.Errorf(protocol.CodeUnauthorized, "unknown auth kind %q", sr.Auth.Kind)
	}

	if roleLevel(v.Signer.Role) < level {
		return nil, protocol.Errorf(protocol.CodeForbidden, "role %q may not perform %q", v.Signer.Role, req.Op)
	}
	// Record the nonce only after authentication so unauthenticated traffic
	// cannot fill the cache.
	if !a.nonces.use(req.Nonce, req.Exp+skew, ts) {
		return nil, protocol.Errorf(protocol.CodeReplay, "request has already been used")
	}
	return v, nil
}

func (c *Config) signer(a *protocol.Assertion) *Signer {
	if a == nil {
		return nil
	}
	id, err := protocol.UnB64(a.CredentialID)
	if err != nil {
		return nil
	}
	want := protocol.B64(id)
	for i := range c.Signers {
		if c.Signers[i].ID == want {
			return &c.Signers[i]
		}
	}
	return nil
}

func asProtoErr(err error) *protocol.Error {
	if pe, ok := err.(*protocol.Error); ok {
		return pe
	}
	return protocol.Errorf(protocol.CodeUnauthorized, "%v", err)
}
