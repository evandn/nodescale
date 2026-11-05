// Command nodescale-relay runs inside a Cloudflare Container. It joins the
// user's tailnet as an ephemeral, tagged node and forwards signed requests to
// servers over Tailscale SSH, where nodescale-gate verifies them.
//
// The relay is intentionally a dumb pipe: it holds no credentials that grant
// anything on a server. The tailnet policy only lets it SSH as the restricted
// "nodescale" user, whose login shell is nodescale-gate: it verifies the
// passkey signature on the server itself before touching Docker.
package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
)

const (
	maxRequest  = 1 << 20
	maxResponse = 32 << 20
	sshUser     = "nodescale"
)

var (
	tailnetV4  = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	hostnameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

type relay struct {
	secret  string
	log     *slog.Logger
	devGate string

	mu       sync.Mutex
	ts       *tsnet.Server
	state    string
	lastErr  string
	hostname string
	ips      []string
	clients  map[string]*ssh.Client
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	secret := os.Getenv("RELAY_SECRET")
	if len(secret) < 32 {
		log.Error("RELAY_SECRET must be set to at least 32 characters")
		os.Exit(1)
	}
	r := &relay{secret: secret, log: log, state: "down", clients: map[string]*ssh.Client{}}
	// Development only: bypass the tailnet and SSH and run a local gate
	// binary for each request, exactly as the gate login shell would be run.
	if bin := os.Getenv("RELAY_DEV_GATE"); bin != "" {
		r.devGate, r.state, r.hostname = bin, "up", "dev"
		log.Warn("development mode: running local gate binary instead of SSH", "gate", bin)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /v1/status", r.auth(r.status))
	mux.HandleFunc("POST /v1/tailnet/up", r.auth(r.up))
	mux.HandleFunc("POST /v1/tailnet/down", r.auth(r.down))
	mux.HandleFunc("POST /v1/rpc", r.auth(r.rpc))

	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		r.shutdown()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Info("relay listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}

func (r *relay) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		got := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(r.secret)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, req)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (r *relay) statusLocked() map[string]any {
	return map[string]any{"state": r.state, "error": r.lastErr, "hostname": r.hostname, "ips": r.ips}
}

func (r *relay) status(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	writeJSON(w, http.StatusOK, r.statusLocked())
}

type upRequest struct {
	AuthKey    string `json:"authKey"`
	Hostname   string `json:"hostname"`
	ControlURL string `json:"controlUrl,omitempty"`
}

// up joins the tailnet using a single-use, ephemeral, pre-authorised auth key
// minted in the user's browser moments earlier.
func (r *relay) up(w http.ResponseWriter, req *http.Request) {
	var in upRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, 8<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if !strings.HasPrefix(in.AuthKey, "tskey-auth-") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authKey must be a Tailscale auth key"})
		return
	}
	if !hostnameRe.MatchString(in.Hostname) {
		in.Hostname = "nodescale-relay"
	}

	r.mu.Lock()
	if r.state == "up" || r.state == "starting" {
		defer r.mu.Unlock()
		writeJSON(w, http.StatusOK, r.statusLocked())
		return
	}
	dir, err := os.MkdirTemp("", "tsnet-")
	if err != nil {
		r.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	ts := &tsnet.Server{
		Hostname:   in.Hostname,
		AuthKey:    in.AuthKey,
		Ephemeral:  true,
		Store:      new(mem.Store),
		Dir:        dir,
		ControlURL: in.ControlURL,
		Logf:       func(string, ...any) {},
		UserLogf:   func(f string, a ...any) { r.log.Info(fmt.Sprintf(f, a...)) },
	}
	r.ts, r.state, r.lastErr, r.hostname = ts, "starting", "", in.Hostname
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(req.Context(), 60*time.Second)
	defer cancel()
	st, err := ts.Up(ctx)

	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		ts.Close()
		r.ts, r.state, r.lastErr = nil, "error", err.Error()
		writeJSON(w, http.StatusBadGateway, r.statusLocked())
		return
	}
	r.state = "up"
	r.ips = nil
	for _, ip := range st.TailscaleIPs {
		r.ips = append(r.ips, ip.String())
	}
	r.log.Info("joined tailnet", "hostname", in.Hostname, "ips", r.ips)
	writeJSON(w, http.StatusOK, r.statusLocked())
}

func (r *relay) down(w http.ResponseWriter, _ *http.Request) {
	r.shutdown()
	r.mu.Lock()
	defer r.mu.Unlock()
	writeJSON(w, http.StatusOK, r.statusLocked())
}

func (r *relay) shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for h, c := range r.clients {
		c.Close()
		delete(r.clients, h)
	}
	if r.ts != nil {
		r.ts.Close()
	}
	r.ts, r.state, r.ips = nil, "down", nil
}

type rpcRequest struct {
	Host    string          `json:"host"`
	Request json.RawMessage `json:"request"`
}

func (r *relay) rpc(w http.ResponseWriter, req *http.Request) {
	var in rpcRequest
	if err := json.NewDecoder(io.LimitReader(req.Body, maxRequest+1024)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	addr, err := netip.ParseAddr(in.Host)
	if err != nil || !(tailnetV4.Contains(addr) || tailnetV6.Contains(addr)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host must be a Tailscale IP address"})
		return
	}
	if len(in.Request) == 0 || bytes.ContainsRune(in.Request, '\n') {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request must be single-line JSON"})
		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), 14*time.Minute)
	defer cancel()
	out, err := r.exec(ctx, addr.String(), in.Request)
	if err != nil {
		// Retry once on a fresh connection; cached connections go stale when
		// a server restarts.
		r.drop(addr.String())
		out, err = r.exec(ctx, addr.String(), in.Request)
	}
	if err != nil {
		r.drop(addr.String())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(bytes.TrimSpace(out))
}

func (r *relay) client(ctx context.Context, host string) (*ssh.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[host]; ok {
		return c, nil
	}
	if r.ts == nil || r.state != "up" {
		return nil, errors.New("relay is not connected to the tailnet")
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	addr := net.JoinHostPort(host, "22")
	conn, err := r.ts.Dial(dctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	// Tailscale SSH authenticates the connection by tailnet identity ("none"
	// auth) and the transport is already end-to-end encrypted by WireGuard.
	// Host keys are not pinned because nothing sent over this channel is
	// trusted: requests are signed by passkeys and responses by the server gate.
	cfg := &ssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         20 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	c := ssh.NewClient(sc, chans, reqs)
	r.clients[host] = c
	go func() {
		c.Wait()
		r.mu.Lock()
		if r.clients[host] == c {
			delete(r.clients, host)
		}
		r.mu.Unlock()
	}()
	return c, nil
}

func (r *relay) drop(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.clients[host]; ok {
		c.Close()
		delete(r.clients, host)
	}
}

type limitWriter struct {
	buf bytes.Buffer
	max int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		return 0, errors.New("response too large")
	}
	return l.buf.Write(p)
}

func (r *relay) execDev(ctx context.Context, request []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.devGate, "-c", "nodescale-rpc")
	cmd.Stdin = bytes.NewReader(append(append([]byte{}, request...), '\n'))
	stdout := &limitWriter{max: maxResponse}
	stderr := &limitWriter{max: 64 << 10}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gate: %v: %s", err, strings.TrimSpace(stderr.buf.String()))
	}
	return stdout.buf.Bytes(), nil
}

func (r *relay) exec(ctx context.Context, host string, request []byte) ([]byte, error) {
	if r.devGate != "" {
		return r.execDev(ctx, request)
	}
	c, err := r.client(ctx, host)
	if err != nil {
		return nil, err
	}
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	stdout := &limitWriter{max: maxResponse}
	stderr := &limitWriter{max: 64 << 10}
	sess.Stdin = bytes.NewReader(append(append([]byte{}, request...), '\n'))
	sess.Stdout, sess.Stderr = stdout, stderr

	done := make(chan error, 1)
	// The command is ignored by the gate shell; it only documents intent in
	// the server's SSH logs.
	go func() { done <- sess.Run("nodescale-rpc") }()
	select {
	case <-ctx.Done():
		sess.Signal(ssh.SIGKILL)
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.buf.String())
			if msg == "" {
				msg = err.Error()
			}
			return nil, fmt.Errorf("gate: %s", msg)
		}
	}
	if stdout.buf.Len() == 0 {
		return nil, errors.New("gate returned an empty response")
	}
	return stdout.buf.Bytes(), nil
}
