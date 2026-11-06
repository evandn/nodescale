package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
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
	// encoding/json matches keys case-insensitively and lets duplicates
	// overwrite each other; check the exact, case-sensitive key set first so
	// this parser and JavaScript's JSON.parse always agree on the meaning.
	if err := checkKeys(b, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("unexpected data after JSON value")
	}
	return nil
}

// exactKeys rejects objects with keys outside the allowed set, compared
// case-sensitively. encoding/json matches field names case-insensitively, so
// without this {"op":"containers.list","Op":"signers.add"} would be read as
// signers.add here but as containers.list by JavaScript (e.g. the console's
// audit log). It also rejects duplicate keys.
func exactKeys(b []byte, allowed ...string) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("payload must be a JSON object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := tok.(string)
		if !slices.Contains(allowed, k) {
			return fmt.Errorf("unexpected field %q", k)
		}
		if seen[k] {
			return fmt.Errorf("duplicate field %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// jsonFields maps exact JSON names to field types, including embedded structs.
func jsonFields(t reflect.Type, out map[string]reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if tag == "-" || (!f.IsExported() && !f.Anonymous) {
			continue
		}
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			jsonFields(f.Type, out)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
}

// checkKeys walks raw JSON alongside the Go type it will be decoded into and
// rejects keys that are unknown, differ in case from the field's name, or
// repeat.
func checkKeys(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == rawMessageType {
		return nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		fields := map[string]reflect.Type{}
		jsonFields(t, fields)
		return walkObject(raw, func(k string, v []byte) error {
			ft, ok := fields[k]
			if !ok {
				return fmt.Errorf("unexpected field %q", k)
			}
			return checkKeys(v, ft)
		})
	case reflect.Map:
		return walkObject(raw, func(_ string, v []byte) error { return checkKeys(v, t.Elem()) })
	case reflect.Slice, reflect.Array:
		if raw[0] != '[' {
			return nil // type errors are reported by the decoder
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		for _, it := range items {
			if err := checkKeys(it, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkObject(raw []byte, fn func(k string, v []byte) error) error {
	if raw[0] != '{' {
		return nil // type errors are reported by the decoder
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if _, err := dec.Token(); err != nil {
		return err
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := tok.(string)
		if seen[k] {
			return fmt.Errorf("duplicate field %q", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		if err := fn(k, v); err != nil {
			return err
		}
	}
	return nil
}

var (
	requestKeys = []string{"v", "typ", "aud", "op", "args", "iat", "exp", "nonce"}
	certKeys    = []string{"v", "typ", "key", "aud", "scope", "iat", "exp", "nonce"}
)

// verify authenticates and authorises a signed request.
func (g *Gate) verify(sr *protocol.SignedRequest, now time.Time) (*Verified, *protocol.Error) {
	payload, err := protocol.UnB64(sr.Payload)
	if err != nil || len(payload) > 512<<10 {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "payload must be base64url JSON under 512 KiB")
	}
	if err := exactKeys(payload, requestKeys...); err != nil {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "payload: %v", err)
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
	// Bound each timestamp against now before subtracting, so extreme values
	// cannot overflow into an "always valid" window.
	if req.Iat > ts+skew {
		return nil, protocol.Errorf(protocol.CodeExpired, "request issued in the future; check clocks")
	}
	if req.Iat < ts-pol.MaxRequestSeconds-skew || req.Exp < ts-skew {
		return nil, protocol.Errorf(protocol.CodeExpired, "request expired")
	}
	if req.Exp <= req.Iat || req.Exp-req.Iat > pol.MaxRequestSeconds {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "request lifetime must be between 1 and %d seconds", pol.MaxRequestSeconds)
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
		if err := exactKeys(certPayload, certKeys...); err != nil {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "session certificate: %v", err)
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
		if cert.Iat > ts+skew || cert.Iat < ts-pol.MaxSessionSeconds-skew || cert.Exp < ts-skew {
			return nil, protocol.Errorf(protocol.CodeExpired, "session certificate expired; unlock again")
		}
		if cert.Exp <= cert.Iat || cert.Exp-cert.Iat > pol.MaxSessionSeconds {
			return nil, protocol.Errorf(protocol.CodeForbidden, "session lifetime exceeds this server's policy (%ds)", pol.MaxSessionSeconds)
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
