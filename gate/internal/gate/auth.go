package gate

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"

	"github.com/evandn/nodescale/gate/internal/protocol"
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

// Ops is the complete catalogue of operations the gate understands, and the
// level each one needs. Anything not listed here is rejected. This table is
// mirrored in packages/protocol/src/ops.ts (a test keeps them in sync).
var Ops = map[string]Level{
	"agent.hello": LevelPublic,

	"agent.info":         LevelRead,
	"audit.read":         LevelRead,
	"host.info":          LevelRead,
	"system.info":        LevelRead,
	"system.df":          LevelRead,
	"containers.list":    LevelRead,
	"containers.inspect": LevelRead,
	"containers.logs":    LevelRead,
	"containers.stats":   LevelRead,
	"containers.top":     LevelRead,
	"images.list":        LevelRead,
	"networks.list":      LevelRead,
	"volumes.list":       LevelRead,
	"signers.list":       LevelRead,

	"containers.start":   LevelOperate,
	"containers.stop":    LevelOperate,
	"containers.restart": LevelOperate,
	"containers.kill":    LevelOperate,
	"containers.pause":   LevelOperate,
	"containers.unpause": LevelOperate,

	"containers.create": LevelAdmin,
	"containers.remove": LevelAdmin,
	"containers.rename": LevelAdmin,
	"containers.update": LevelAdmin,
	"containers.exec":   LevelAdmin,
	"containers.env":    LevelAdmin,
	"images.pull":       LevelAdmin,
	"images.remove":     LevelAdmin,
	"images.prune":      LevelAdmin,
	"networks.create":   LevelAdmin,
	"networks.remove":   LevelAdmin,
	"volumes.create":    LevelAdmin,
	"volumes.remove":    LevelAdmin,
	"stacks.deploy":     LevelAdmin,
	"stacks.remove":     LevelAdmin,
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

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// verify authenticates and authorises a signed request.
func (g *Gate) verify(sr *protocol.SignedRequest, now time.Time) (*Verified, *protocol.Error) {
	payload, err := protocol.UnB64(sr.Payload)
	if err != nil || len(payload) > 512<<10 {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "payload must be base64url JSON under 512 KiB")
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
		if req.Aud != g.id && req.Aud != "*" {
			return nil, protocol.Errorf(protocol.CodeForbidden, "request is addressed to a different server")
		}
		return v, nil
	}

	cfg := g.cfg
	pol := cfg.Policy.withDefaults()
	ts := now.Unix()
	skew := pol.ClockSkewSeconds

	if req.Aud != g.id {
		return nil, protocol.Errorf(protocol.CodeForbidden, "request is addressed to a different server")
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

	rp := protocol.RelyingParty{ID: cfg.RPID, Origins: cfg.Origins}
	if sr.Auth == nil {
		return nil, protocol.Errorf(protocol.CodeUnauthorized, "operation %q requires a signature", req.Op)
	}

	switch sr.Auth.Kind {
	case protocol.AuthWebAuthn:
		s := cfg.signer(sr.Auth.Assertion)
		if s == nil {
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "passkey is not trusted by this server")
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
		if !slices.Contains(cert.Aud, "*") && !slices.Contains(cert.Aud, g.id) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session certificate is not valid for this server")
		}
		if !slices.Contains(pol.AllowSessionScopes, cert.Scope) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session scope %q is not allowed by this server's policy", cert.Scope)
		}
		if cert.Exp <= cert.Iat || cert.Exp-cert.Iat > pol.MaxSessionSeconds {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session lifetime exceeds this server's policy (%ds)", pol.MaxSessionSeconds)
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
			return nil, protocol.Errorf(protocol.CodeUnauthorized, "passkey is not trusted by this server")
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
	// cannot create files.
	fresh, err := g.nonces.use(v.Signer.ID, req.Nonce, now)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInternal, "replay store: %v", err)
	}
	if !fresh {
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
