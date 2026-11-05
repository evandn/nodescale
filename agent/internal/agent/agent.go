// Package agent implements the on-server nodescale agent: it verifies signed
// requests and executes allow-listed Docker operations.
package agent

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/evandn/nodescale/agent/internal/docker"
	"github.com/evandn/nodescale/agent/internal/protocol"
)

// Version is set at build time.
var Version = "dev"

// MaxRequestBytes bounds a single request line.
const MaxRequestBytes = 1 << 20

// Options configures an Agent.
type Options struct {
	ConfigPath   string
	IdentityPath string
	AuditPath    string
	DockerSocket string
	Logger       *slog.Logger
	Now          func() time.Time
}

// Agent verifies and executes requests.
type Agent struct {
	opts     Options
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	id       string
	bootTime time.Time
	docker   *docker.Client
	log      *slog.Logger
	nonces   nonceCache

	mu  sync.RWMutex
	cfg *Config

	auditMu sync.Mutex
}

// New loads the configuration and identity key, creating the key if needed.
func New(opts Options) (*Agent, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	cfg, err := LoadConfig(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	priv, err := LoadOrCreateIdentity(opts.IdentityPath)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	a := &Agent{
		opts:     opts,
		priv:     priv,
		pub:      pub,
		id:       protocol.AgentID(pub),
		bootTime: opts.Now().Truncate(time.Second),
		log:      opts.Logger,
		cfg:      cfg,
	}
	if opts.DockerSocket != "" {
		a.docker = docker.New(opts.DockerSocket)
	}
	return a, nil
}

// ID returns the agent identifier.
func (a *Agent) ID() string { return a.id }

// PublicKey returns the agent identity public key.
func (a *Agent) PublicKey() ed25519.PublicKey { return a.pub }

func (a *Agent) config() *Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// LoadOrCreateIdentity loads the Ed25519 identity seed, generating it on first run.
func LoadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		seed, err := protocol.UnB64(string(trimSpace(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: invalid identity key", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// Handle processes one raw request and returns the signed response bytes.
func (a *Agent) Handle(ctx context.Context, raw []byte) []byte {
	now := a.opts.Now()
	var sr protocol.SignedRequest
	if err := json.Unmarshal(raw, &sr); err != nil {
		return a.respond("", nil, protocol.Errorf(protocol.CodeBadRequest, "request must be JSON"), now)
	}
	reqHash := ""
	if p, err := protocol.UnB64(sr.Payload); err == nil {
		reqHash = protocol.RequestHash(p)
	}

	v, perr := a.verify(&sr, now)
	if perr != nil {
		a.audit(auditEntry{Ts: now.Unix(), Req: reqHash, Ok: false, Error: perr.Code + ": " + perr.Message, Op: peekOp(sr.Payload)})
		return a.respond(reqHash, nil, perr, now)
	}

	result, err := a.dispatch(ctx, v)
	var pe *protocol.Error
	if err != nil {
		if !errors.As(err, &pe) {
			code := protocol.CodeInternal
			if docker.IsNotFound(err) {
				code = protocol.CodeNotFound
			}
			pe = protocol.Errorf(code, "%v", err)
		}
	}
	if v.Level > LevelPublic || pe != nil {
		e := auditEntry{Ts: now.Unix(), Op: v.Req.Op, Req: reqHash, Ok: pe == nil, Auth: v.AuthKind, Args: v.Req.Args}
		if v.Signer != nil {
			e.Signer, e.Label = v.Signer.ID, v.Signer.Label
		}
		if pe != nil {
			e.Error = pe.Code + ": " + pe.Message
		}
		a.audit(e)
	}
	return a.respond(reqHash, result, pe, a.opts.Now())
}

func peekOp(payload string) string {
	p, err := protocol.UnB64(payload)
	if err != nil {
		return ""
	}
	var r struct {
		Op string `json:"op"`
	}
	_ = json.Unmarshal(p, &r)
	if len(r.Op) > 64 {
		return r.Op[:64]
	}
	return r.Op
}

func (a *Agent) respond(reqHash string, result any, perr *protocol.Error, now time.Time) []byte {
	resp := protocol.Response{
		V: protocol.Version, Typ: protocol.TypResponse, Agent: a.id, Req: reqHash,
		Ok: perr == nil, Error: perr, Ts: now.Unix(),
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
	sig := ed25519.Sign(a.priv, protocol.Message(protocol.DomainResponse, payload))
	out, _ := json.Marshal(protocol.SignedResponse{
		Payload:   protocol.B64(payload),
		Signature: protocol.B64(sig),
		PublicKey: protocol.B64(a.pub),
	})
	return out
}

// Serve accepts connections on a unix socket. Each connection carries one
// newline-terminated request and receives one newline-terminated response.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go a.serveConn(ctx, conn)
	}
}

func (a *Agent) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	r := bufio.NewReaderSize(io.LimitReader(conn, MaxRequestBytes+1), 64<<10)
	line, err := r.ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		if len(line) > MaxRequestBytes {
			_, _ = conn.Write(append(a.respond("", nil, protocol.Errorf(protocol.CodeBadRequest, "request too large"), a.opts.Now()), '\n'))
		}
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, 14*time.Minute)
	defer cancel()
	out := a.Handle(reqCtx, line)
	_, _ = conn.Write(append(out, '\n'))
}

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

// audit appends an entry to the local, server-side audit log. This log lives
// on the server and is written only by the agent, so it remains trustworthy
// even if the control plane is compromised.
func (a *Agent) audit(e auditEntry) {
	lvl := slog.LevelInfo
	if !e.Ok {
		lvl = slog.LevelWarn
	}
	a.log.Log(context.Background(), lvl, "request", "op", e.Op, "ok", e.Ok, "signer", e.Label, "auth", e.Auth, "error", e.Error)
	if a.opts.AuditPath == "" {
		return
	}
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if st, err := os.Stat(a.opts.AuditPath); err == nil && st.Size() > maxAuditBytes {
		_ = os.Rename(a.opts.AuditPath, a.opts.AuditPath+".1")
	}
	f, err := os.OpenFile(a.opts.AuditPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		a.log.Error("audit log", "err", err)
		return
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	_, _ = f.Write(append(b, '\n'))
}
