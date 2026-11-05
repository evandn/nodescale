package gate

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

const (
	testRPID   = "nodescale.example.com"
	testOrigin = "https://nodescale.example.com"
)

// passkey simulates an authenticator.
type passkey struct {
	id   []byte
	alg  int
	priv crypto.Signer
}

func newPasskey(t *testing.T, alg int) *passkey {
	t.Helper()
	id := make([]byte, 16)
	rand.Read(id)
	var priv crypto.Signer
	var err error
	switch alg {
	case protocol.AlgES256:
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case protocol.AlgEdDSA:
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &passkey{id: id, alg: alg, priv: priv}
}

func (p *passkey) signer(role string) Signer {
	der, _ := x509.MarshalPKIXPublicKey(p.priv.Public())
	return Signer{ID: protocol.B64(p.id), Alg: p.alg, PublicKey: protocol.B64(der), Role: role, Label: role}
}

type assertOpts struct {
	origin string
	rpID   string
	flags  byte
	typ    string
}

func (p *passkey) assert(t *testing.T, challenge []byte, o assertOpts) *protocol.Assertion {
	t.Helper()
	if o.origin == "" {
		o.origin = testOrigin
	}
	if o.rpID == "" {
		o.rpID = testRPID
	}
	if o.flags == 0 {
		o.flags = protocol.FlagUserPresent | protocol.FlagUserVerified
	}
	if o.typ == "" {
		o.typ = "webauthn.get"
	}
	cdj, _ := json.Marshal(map[string]any{"type": o.typ, "challenge": protocol.B64(challenge), "origin": o.origin, "crossOrigin": false})
	rpHash := sha256.Sum256([]byte(o.rpID))
	authData := append(rpHash[:], o.flags, 0, 0, 0, 1)
	cdHash := sha256.Sum256(cdj)
	msg := append(append([]byte{}, authData...), cdHash[:]...)
	var sig []byte
	var err error
	switch p.alg {
	case protocol.AlgES256:
		h := sha256.Sum256(msg)
		sig, err = ecdsa.SignASN1(rand.Reader, p.priv.(*ecdsa.PrivateKey), h[:])
	case protocol.AlgEdDSA:
		sig = ed25519.Sign(p.priv.(ed25519.PrivateKey), msg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Assertion{
		CredentialID:      protocol.B64(p.id),
		AuthenticatorData: protocol.B64(authData),
		ClientDataJSON:    protocol.B64(cdj),
		Signature:         protocol.B64(sig),
	}
}

type harness struct {
	t     *testing.T
	a     *Gate
	now   time.Time
	dir   string
	admin *passkey
}

func newHarness(t *testing.T, extra ...Signer) *harness {
	t.Helper()
	dir := t.TempDir()
	admin := newPasskey(t, protocol.AlgES256)
	cfg := Config{RPID: testRPID, Origins: []string{testOrigin}, Signers: append([]Signer{admin.signer(RoleAdmin)}, extra...)}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, admin: admin, now: time.Unix(1_800_000_000, 0)}
	h.reload()
	return h
}

// reload starts a fresh gate process, as every production request does.
func (h *harness) reload() {
	h.t.Helper()
	a, err := New(Options{
		Paths:          Paths{Config: filepath.Join(h.dir, "agent.json"), Identity: filepath.Join(h.dir, "identity.key"), State: h.dir, Docker: filepath.Join(h.dir, "no-docker.sock")},
		Now:            func() time.Time { return h.now },
		CreateIdentity: true,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.a = a
}

func (h *harness) payload(op string, args any, mut ...func(*protocol.Request)) []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	r := protocol.Request{V: 1, Typ: protocol.TypRequest, Aud: h.a.ID(), Op: op, Iat: h.now.Unix(), Exp: h.now.Unix() + 60, Nonce: protocol.B64(nonce)}
	if args != nil {
		r.Args, _ = json.Marshal(args)
	}
	for _, m := range mut {
		m(&r)
	}
	b, _ := json.Marshal(r)
	return b
}

func (h *harness) webauthn(p *passkey, payload []byte, o assertOpts) []byte {
	sr := protocol.SignedRequest{
		Payload: protocol.B64(payload),
		Auth:    &protocol.Auth{Kind: protocol.AuthWebAuthn, Assertion: p.assert(h.t, protocol.Challenge(protocol.DomainRequest, payload), o)},
	}
	b, _ := json.Marshal(sr)
	return b
}

type session struct {
	key  *ecdsa.PrivateKey
	cert *protocol.Certificate
}

func (h *harness) session(p *passkey, scope string, mut ...func(*protocol.SessionCert)) *session {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	c := protocol.SessionCert{V: 1, Typ: protocol.TypSession, Key: protocol.B64(der), Aud: []string{"*"}, Scope: scope, Iat: h.now.Unix(), Exp: h.now.Unix() + 3600, Nonce: "server-issued-nonce-123"}
	for _, m := range mut {
		m(&c)
	}
	cp, _ := json.Marshal(c)
	return &session{key: key, cert: &protocol.Certificate{
		Payload:   protocol.B64(cp),
		Assertion: p.assert(h.t, protocol.Challenge(protocol.DomainSession, cp), assertOpts{}),
	}}
}

func (s *session) sign(payload []byte) []byte {
	h := sha256.Sum256(protocol.Message(protocol.DomainSessionRequest, payload))
	r, ss, _ := ecdsa.Sign(rand.Reader, s.key, h[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	sr := protocol.SignedRequest{Payload: protocol.B64(payload), Auth: &protocol.Auth{Kind: protocol.AuthSession, Certificate: s.cert, Signature: protocol.B64(sig)}}
	b, _ := json.Marshal(sr)
	return b
}

func (h *harness) call(raw []byte) protocol.Response {
	h.t.Helper()
	out := h.a.Handle(context.Background(), raw)
	var sr protocol.SignedResponse
	if err := json.Unmarshal(out, &sr); err != nil {
		h.t.Fatalf("response is not JSON: %v", err)
	}
	payload, _ := protocol.UnB64(sr.Payload)
	var r protocol.Response
	if err := json.Unmarshal(payload, &r); err != nil {
		h.t.Fatal(err)
	}
	if sr.Signature == "" {
		// Rejections before authentication are deliberately unsigned.
		if r.Ok || r.Error == nil {
			h.t.Fatal("only rejections may be unsigned")
		}
		return r
	}
	pub, _ := protocol.UnB64(sr.PublicKey)
	sig, _ := protocol.UnB64(sr.Signature)
	if !ed25519.Verify(pub, protocol.Message(protocol.DomainResponse, payload), sig) {
		h.t.Fatal("response signature does not verify")
	}
	if protocol.AgentID(pub) != h.a.ID() {
		h.t.Fatal("response key does not match agent id")
	}
	return r
}

func expectOK(t *testing.T, r protocol.Response) {
	t.Helper()
	if !r.Ok {
		t.Fatalf("expected success, got %+v", r.Error)
	}
}

func expectErr(t *testing.T, r protocol.Response, code string, contains ...string) {
	t.Helper()
	if r.Ok {
		t.Fatalf("expected %s error, got success", code)
	}
	if r.Error.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, r.Error.Code, r.Error.Message)
	}
	for _, c := range contains {
		if !strings.Contains(r.Error.Message, c) {
			t.Fatalf("error %q does not mention %q", r.Error.Message, c)
		}
	}
}

func TestHelloIsPublicAndSigned(t *testing.T) {
	h := newHarness(t)
	p := h.payload("agent.hello", nil, func(r *protocol.Request) { r.Aud = "*" })
	b, _ := json.Marshal(protocol.SignedRequest{Payload: protocol.B64(p)})
	r := h.call(b)
	expectOK(t, r)
	if r.Req != protocol.RequestHash(p) {
		t.Fatal("response not bound to request")
	}
}

func TestPasskeyRequest(t *testing.T) {
	for _, alg := range []int{protocol.AlgES256, protocol.AlgEdDSA} {
		pk := newPasskey(t, alg)
		h := newHarness(t, pk.signer(RoleViewer))
		r := h.call(h.webauthn(pk, h.payload("signers.list", nil), assertOpts{flags: protocol.FlagUserPresent}))
		expectOK(t, r)
		var signers []Signer
		json.Unmarshal(r.Result, &signers)
		if len(signers) != 2 {
			t.Fatalf("expected 2 signers, got %d", len(signers))
		}
	}
}

func TestRejectsUnauthenticated(t *testing.T) {
	h := newHarness(t)
	b, _ := json.Marshal(protocol.SignedRequest{Payload: protocol.B64(h.payload("signers.list", nil))})
	expectErr(t, h.call(b), protocol.CodeUnauthorized)
}

func TestRejectsUnknownPasskey(t *testing.T) {
	h := newHarness(t)
	stranger := newPasskey(t, protocol.AlgES256)
	expectErr(t, h.call(h.webauthn(stranger, h.payload("signers.list", nil), assertOpts{})), protocol.CodeUnauthorized, "not trusted")
}

func TestRejectsReplay(t *testing.T) {
	h := newHarness(t)
	req := h.webauthn(h.admin, h.payload("signers.list", nil), assertOpts{})
	expectOK(t, h.call(req))
	// Replay protection must survive process restarts: each request runs in
	// a new gate process.
	h.reload()
	expectErr(t, h.call(req), protocol.CodeReplay)
}

func TestRejectsTamperedPayload(t *testing.T) {
	h := newHarness(t)
	signed := h.payload("signers.list", nil)
	var sr protocol.SignedRequest
	json.Unmarshal(h.webauthn(h.admin, signed, assertOpts{}), &sr)
	sr.Payload = protocol.B64(h.payload("signers.remove", map[string]string{"id": "AAAA"}))
	b, _ := json.Marshal(sr)
	expectErr(t, h.call(b), protocol.CodeUnauthorized, "challenge")
}

func TestRejectsWrongBinding(t *testing.T) {
	h := newHarness(t)
	cases := map[string]assertOpts{
		"origin":   {origin: "https://evil.example.com"},
		"rpId":     {rpID: "evil.example.com"},
		"type":     {typ: "webauthn.create"},
		"presence": {flags: protocol.FlagUserVerified},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil), o)), protocol.CodeUnauthorized)
		})
	}
}

func TestRejectsWrongAudienceAndTime(t *testing.T) {
	h := newHarness(t)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil, func(r *protocol.Request) { r.Aud = "ag_other" }), assertOpts{})), protocol.CodeForbidden)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil, func(r *protocol.Request) { r.Iat -= 600; r.Exp -= 600 }), assertOpts{})), protocol.CodeExpired)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil, func(r *protocol.Request) { r.Exp = r.Iat + 3600 }), assertOpts{})), protocol.CodeBadRequest)
}

func TestStateChangeRequiresUserVerification(t *testing.T) {
	h := newHarness(t)
	newKey := newPasskey(t, protocol.AlgEdDSA)
	p := h.payload("signers.add", newKey.signer(RoleOperator))
	expectErr(t, h.call(h.webauthn(h.admin, p, assertOpts{flags: protocol.FlagUserPresent})), protocol.CodeUnauthorized, "verification")
	expectOK(t, h.call(h.webauthn(h.admin, h.payload("signers.add", newKey.signer(RoleOperator)), assertOpts{})))

	// The change is persisted and visible to the next gate process.
	h.reload()
	r := h.call(h.webauthn(newKey, h.payload("signers.list", nil), assertOpts{}))
	expectOK(t, r)
	var signers []Signer
	json.Unmarshal(r.Result, &signers)
	if len(signers) != 2 || signers[1].AddedBy != "admin" {
		t.Fatalf("signer not persisted: %+v", signers)
	}
}

func TestRoles(t *testing.T) {
	viewer := newPasskey(t, protocol.AlgES256)
	h := newHarness(t, viewer.signer(RoleViewer))
	expectErr(t, h.call(h.webauthn(viewer, h.payload("containers.start", map[string]string{"id": "web"}), assertOpts{})), protocol.CodeForbidden, "role")
	expectErr(t, h.call(h.webauthn(viewer, h.payload("signers.add", newPasskey(t, protocol.AlgES256).signer(RoleAdmin)), assertOpts{})), protocol.CodeForbidden, "role")
}

func TestSessionDelegation(t *testing.T) {
	h := newHarness(t)
	s := h.session(h.admin, protocol.ScopeOperate)
	expectOK(t, h.call(s.sign(h.payload("signers.list", nil))))
	expectOK(t, h.call(s.sign(h.payload("agent.info", nil))))

	// Admin operations can never be performed with a session key.
	expectErr(t, h.call(s.sign(h.payload("signers.remove", map[string]string{"id": protocol.B64(h.admin.id)}))), protocol.CodeForbidden, "fresh passkey")

	// Read scope cannot change state.
	ro := h.session(h.admin, protocol.ScopeRead)
	expectErr(t, h.call(ro.sign(h.payload("containers.restart", map[string]string{"id": "web"}))), protocol.CodeForbidden, "scope")

	// A different key cannot reuse the certificate.
	thief := h.session(h.admin, protocol.ScopeOperate)
	thief.cert = s.cert
	expectErr(t, h.call(thief.sign(h.payload("signers.list", nil))), protocol.CodeUnauthorized, "session signature")
}

func TestSessionLimits(t *testing.T) {
	h := newHarness(t)
	long := h.session(h.admin, protocol.ScopeOperate, func(c *protocol.SessionCert) { c.Exp = c.Iat + 9*3600 })
	expectErr(t, h.call(long.sign(h.payload("signers.list", nil))), protocol.CodeForbidden, "lifetime")

	other := h.session(h.admin, protocol.ScopeOperate, func(c *protocol.SessionCert) { c.Aud = []string{"ag_someone_else"} })
	expectErr(t, h.call(other.sign(h.payload("signers.list", nil))), protocol.CodeForbidden, "not valid for this server")

	s := h.session(h.admin, protocol.ScopeOperate)
	h.now = h.now.Add(2 * time.Hour)
	expectErr(t, h.call(s.sign(h.payload("signers.list", nil))), protocol.CodeExpired)
}

func TestCannotRemoveLastAdmin(t *testing.T) {
	h := newHarness(t)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.remove", map[string]string{"id": protocol.B64(h.admin.id)}), assertOpts{})), protocol.CodeConflict, "last admin")
}

func TestUnknownOpAndArgs(t *testing.T) {
	h := newHarness(t)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("shell.exec", map[string]string{"cmd": "id"}), assertOpts{})), protocol.CodeUnsupported)
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.remove", map[string]any{"id": "x", "extra": 1}), assertOpts{})), protocol.CodeBadRequest)
}

func TestAuditLogWritten(t *testing.T) {
	h := newHarness(t)
	k := newPasskey(t, protocol.AlgEdDSA)
	expectOK(t, h.call(h.webauthn(h.admin, h.payload("signers.add", k.signer(RoleViewer)), assertOpts{})))
	// Failed state-changing requests are logged too; reads are not.
	h.call(h.webauthn(h.admin, h.payload("containers.create", map[string]any{"image": "alpine", "env": []string{"SECRET=hunter2"}, "privileged": true}), assertOpts{}))
	h.call(h.webauthn(h.admin, h.payload("signers.list", nil), assertOpts{}))
	b, err := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(b), `"op":"signers.add"`) || !strings.Contains(string(b), `"op":"containers.create"`) {
		t.Fatalf("audit log missing entry: %v %s", err, b)
	}
	if strings.Contains(string(b), "hunter2") || !strings.Contains(string(b), "SECRET=[redacted]") {
		t.Fatalf("env values must be redacted in the audit log: %s", b)
	}
	if strings.Contains(string(b), `"op":"signers.list"`) {
		t.Fatal("successful reads should not be logged")
	}
	r := h.call(h.webauthn(h.admin, h.payload("audit.read", map[string]int{"lines": 10}), assertOpts{}))
	expectOK(t, r)
	var entries []map[string]any
	json.Unmarshal(r.Result, &entries)
	if len(entries) != 2 || entries[0]["op"] != "containers.create" {
		t.Fatalf("audit.read returned %v", entries)
	}
}

func TestPolicyDeniesHostEscapes(t *testing.T) {
	h := newHarness(t)
	for name, spec := range map[string]map[string]any{
		"privileged":  {"image": "alpine", "privileged": true},
		"host pid":    {"image": "alpine", "pidMode": "host"},
		"cap":         {"image": "alpine", "capAdd": []string{"SYS_ADMIN"}},
		"docker.sock": {"image": "alpine", "mounts": []map[string]any{{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}}},
		"root bind":   {"image": "alpine", "mounts": []map[string]any{{"type": "bind", "source": "/", "target": "/host"}}},
		"ports":       {"image": "alpine", "ports": []map[string]any{{"containerPort": 80, "hostPort": 80}}},
		"devices":     {"image": "alpine", "devices": []string{"/dev/sda"}},
	} {
		t.Run(name, func(t *testing.T) {
			expectErr(t, h.call(h.webauthn(h.admin, h.payload("containers.create", spec), assertOpts{})), protocol.CodeForbidden)
		})
	}
}

func TestTimeOverflowRejected(t *testing.T) {
	h := newHarness(t)
	// exp - iat overflows int64 and would wrap to a negative "lifetime".
	huge := func(r *protocol.Request) { r.Iat = -6e18; r.Exp = 4e18 }
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil, huge), assertOpts{})), protocol.CodeExpired)
	s := h.session(h.admin, protocol.ScopeOperate, func(c *protocol.SessionCert) { c.Iat = -6e18; c.Exp = 4e18 })
	expectErr(t, h.call(s.sign(h.payload("signers.list", nil))), protocol.CodeExpired)
	// A request issued long ago is rejected even with a short lifetime.
	old := func(r *protocol.Request) { r.Iat -= 1000; r.Exp = r.Iat + 60 }
	expectErr(t, h.call(h.webauthn(h.admin, h.payload("signers.list", nil, old), assertOpts{})), protocol.CodeExpired)
}

func TestRejectionsAreUnsigned(t *testing.T) {
	h := newHarness(t)
	stranger := newPasskey(t, protocol.AlgES256)
	out := h.a.Handle(context.Background(), h.webauthn(stranger, h.payload("signers.list", nil), assertOpts{}))
	var sr protocol.SignedResponse
	json.Unmarshal(out, &sr)
	if sr.Signature != "" || sr.PublicKey != "" {
		t.Fatal("a rejection before authentication must not be signed")
	}
}

func TestSecretNotEchoedForBadName(t *testing.T) {
	h := newHarness(t)
	sealed := sealFor(t, h.a, "TOPSECRET", "BAD KEY")
	r := h.call(h.webauthn(h.admin, h.payload("containers.create", map[string]any{"image": "alpine", "env": []string{"BAD KEY=" + sealed}}), assertOpts{}))
	expectErr(t, r, protocol.CodeBadRequest)
	b, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	if strings.Contains(r.Error.Message, "TOPSECRET") || strings.Contains(string(b), "TOPSECRET") {
		t.Fatal("decrypted value leaked")
	}
}
