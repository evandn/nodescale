// Package gate implements nodescale's on-server component. It is not a
// daemon: the SSH login shell of the restricted "nodescale" user runs it once
// per request. It verifies the passkey signature, applies the server's
// policy, calls the Docker Engine API on the local socket, signs the response
// and exits.
package gate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/evandn/nodescale/gate/internal/docker"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

// Version is set at build time.
var Version = "dev"

// MaxRequestBytes bounds a single request.
const MaxRequestBytes = 1 << 20

// Options configures a Gate.
type Options struct {
	Paths Paths
	Now   func() time.Time
	// CreateIdentity allows generating the identity key on first use. The
	// production gate never does this; `nodescale-gate init` does, as root.
	CreateIdentity bool
}

// Gate verifies and executes one request.
type Gate struct {
	opts   Options
	cfg    *Config
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	id     string
	docker *docker.Client
	nonces nonceStore
}

// New loads the configuration and identity key.
func New(opts Options) (*Gate, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	cfg, err := LoadConfig(opts.Paths.Config)
	if err != nil {
		return nil, err
	}
	priv, err := LoadIdentity(opts.Paths.Identity, opts.CreateIdentity)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	pol := cfg.Policy.withDefaults()
	return &Gate{
		opts:   opts,
		cfg:    cfg,
		priv:   priv,
		pub:    pub,
		id:     protocol.AgentID(pub),
		docker: docker.New(opts.Paths.Docker),
		nonces: nonceStore{dir: opts.Paths.nonceDir(), maxAge: time.Duration(pol.MaxRequestSeconds+3*pol.ClockSkewSeconds) * time.Second},
	}, nil
}

// ID returns the server identity (self-certifying hash of the public key).
func (g *Gate) ID() string { return g.id }

// PublicKey returns the identity public key.
func (g *Gate) PublicKey() ed25519.PublicKey { return g.pub }

// LoadIdentity loads the Ed25519 identity seed, optionally generating it.
func LoadIdentity(path string, create bool) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		seed, err := protocol.UnB64(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: invalid identity key", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, fmt.Errorf("identity key: %w", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(protocol.B64(seed) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Handle processes one raw request and returns the signed response bytes.
func (g *Gate) Handle(ctx context.Context, raw []byte) []byte {
	now := g.opts.Now()
	var sr protocol.SignedRequest
	if err := json.Unmarshal(raw, &sr); err != nil {
		return g.Respond("", nil, protocol.Errorf(protocol.CodeBadRequest, "request must be JSON"))
	}
	reqHash := ""
	if p, err := protocol.UnB64(sr.Payload); err == nil {
		reqHash = protocol.RequestHash(p)
	}

	v, perr := g.verify(&sr, now)
	if perr != nil {
		// Unauthenticated failures are not logged to disk: anyone who can
		// reach the gate could otherwise fill the log.
		return g.Respond(reqHash, nil, perr)
	}

	result, err := g.dispatch(ctx, v)
	var pe *protocol.Error
	if err != nil && !errors.As(err, &pe) {
		code := protocol.CodeInternal
		switch {
		case docker.IsNotFound(err):
			code = protocol.CodeNotFound
		case docker.IsConflict(err):
			code = protocol.CodeConflict
		case errors.Is(err, syscall.EACCES):
			err = fmt.Errorf("%w (is nodescale-gate installed setgid docker? run `nodescale-gate check` as root)", err)
		}
		pe = protocol.Errorf(code, "%v", err)
	}
	if v.Level > LevelRead || pe != nil && v.Level > LevelPublic {
		e := auditEntry{Ts: now.Unix(), Op: v.Req.Op, Req: reqHash, Ok: pe == nil, Auth: v.AuthKind, Args: redact(v.Req.Args)}
		if v.Signer != nil {
			e.Signer, e.Label = v.Signer.ID, v.Signer.Label
		}
		if pe != nil {
			e.Error = pe.Code + ": " + pe.Message
		}
		g.audit(e)
	}
	return g.Respond(reqHash, result, pe)
}

// Respond builds a signed response.
func (g *Gate) Respond(reqHash string, result any, perr *protocol.Error) []byte {
	resp := protocol.Response{
		V: protocol.Version, Typ: protocol.TypResponse, Agent: g.id, Req: reqHash,
		Ok: perr == nil, Error: perr, Ts: g.opts.Now().Unix(),
	}
	if perr == nil && result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			resp.Ok = false
			resp.Error = protocol.Errorf(protocol.CodeInternal, "encode result: %v", err)
		} else {
			resp.Result = b
		}
	}
	payload, _ := json.Marshal(resp)
	sig := ed25519.Sign(g.priv, protocol.Message(protocol.DomainResponse, payload))
	out, _ := json.Marshal(protocol.SignedResponse{
		Payload:   protocol.B64(payload),
		Signature: protocol.B64(sig),
		PublicKey: protocol.B64(g.pub),
	})
	return out
}

// ---------------------------------------------------------------------------
// Audit log

type auditEntry struct {
	Ts     int64           `json:"ts"`
	Op     string          `json:"op,omitempty"`
	Req    string          `json:"req,omitempty"`
	Signer string          `json:"signer,omitempty"`
	Label  string          `json:"label,omitempty"`
	Auth   string          `json:"auth,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Ok     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
}

const maxAuditBytes = 20 << 20

// audit appends an entry to the server-side audit log. It lives in a
// directory only root and the setgid gate can reach, so neither the console
// nor the "nodescale" SSH user can alter it.
func (g *Gate) audit(e auditEntry) {
	path := g.opts.Paths.auditPath()
	b, _ := json.Marshal(e)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o660)
	if err != nil {
		return
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err == nil {
		defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
	if st, err := f.Stat(); err == nil && st.Size() > maxAuditBytes {
		_ = os.Rename(path, path+".1")
	}
	_, _ = f.Write(append(b, '\n'))
}

// redact replaces environment variable values ("KEY=value" strings inside any
// "env" array) so secrets passed to containers never reach the audit log.
func redact(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(redactValue(v, ""))
	return bytes.TrimSpace(buf.Bytes())
}

func redactValue(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = redactValue(x, k)
		}
		return t
	case []any:
		for i, x := range t {
			if s, ok := x.(string); ok && strings.EqualFold(key, "env") {
				if k, _, found := strings.Cut(s, "="); found {
					t[i] = k + "=[redacted]"
				}
				continue
			}
			t[i] = redactValue(x, key)
		}
		return t
	}
	return v
}

func redactEnvList(env []any) []any {
	for i, x := range env {
		if s, ok := x.(string); ok {
			if k, _, found := strings.Cut(s, "="); found {
				env[i] = k + "=[redacted]"
			}
		}
	}
	return env
}

// withConfigLock serialises read-modify-write of the configuration across
// concurrent gate processes.
func (g *Gate) withConfigLock(fn func(cfg *Config) error) error {
	lf, err := os.OpenFile(g.opts.Paths.Config+".lock", os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	cfg, err := LoadConfig(g.opts.Paths.Config)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return protocol.Errorf(protocol.CodeConflict, "%v", err)
	}
	if err := cfg.Save(g.opts.Paths.Config); err != nil {
		return err
	}
	g.cfg = cfg
	return nil
}
