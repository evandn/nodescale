package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func newTestRelay(t *testing.T, devGate string) http.Handler {
	t.Helper()
	r := &relay{secret: testSecret, log: slog.New(slog.NewTextHandler(os.Stderr, nil)), state: "down", clients: map[string]*ssh.Client{}}
	if devGate != "" {
		r.devGate, r.state = devGate, "up"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", r.auth(r.status))
	mux.HandleFunc("POST /v1/rpc", r.auth(r.rpc))
	mux.HandleFunc("POST /v1/tailnet/up", r.auth(r.up))
	return mux
}

func do(h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+testSecret)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestRequiresSecret(t *testing.T) {
	h := newTestRelay(t, "")
	if w := do(h, "GET", "/v1/status", "", false); w.Code != http.StatusUnauthorized {
		t.Fatalf("status without secret: %d", w.Code)
	}
	if w := do(h, "GET", "/v1/status", "", true); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"down"`) {
		t.Fatalf("status: %d %s", w.Code, w.Body)
	}
}

func TestRPCOnlyToTailnetAddresses(t *testing.T) {
	h := newTestRelay(t, "")
	for _, host := range []string{"8.8.8.8", "127.0.0.1", "169.254.169.254", "example.com", "100.128.0.1", "fd00::1"} {
		w := do(h, "POST", "/v1/rpc", `{"host":"`+host+`","request":{"payload":"x"}}`, true)
		if w.Code != http.StatusBadRequest {
			t.Errorf("host %s: expected 400, got %d", host, w.Code)
		}
	}
	w := do(h, "POST", "/v1/rpc", `{"host":"100.64.0.1","request":{"payload":"x"}}`, true)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "not connected") {
		t.Fatalf("tailnet host while down: %d %s", w.Code, w.Body)
	}
}

func TestUpValidatesKey(t *testing.T) {
	h := newTestRelay(t, "")
	if w := do(h, "POST", "/v1/tailnet/up", `{"authKey":"not-a-key"}`, true); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestDevGatePipe(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	// A stand-in gate: echoes stdin back, like the real one answers one line.
	os.WriteFile(gate, []byte("#!/bin/sh\ncat\n"), 0o755)
	h := newTestRelay(t, gate)
	w := do(h, "POST", "/v1/rpc", `{"host":"100.64.0.1","request":{"payload":"abc"}}`, true)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"payload":"abc"}` {
		t.Fatalf("dev pipe: %d %q", w.Code, w.Body)
	}
	if w := do(h, "POST", "/v1/rpc", "{\"host\":\"100.64.0.1\",\"request\":{\"payload\":\n\"abc\"}}", true); w.Code != http.StatusBadRequest {
		t.Fatalf("multi-line request must be rejected, got %d", w.Code)
	}
}

func TestSilentPeerDoesNotWedgeRelay(t *testing.T) {
	// A peer that accepts TCP but never speaks SSH.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	r := &relay{secret: testSecret, log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: "up", clients: map[string]*ssh.Client{}}
	r.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := r.client(ctx, "100.64.0.1"); done <- err }()

	// While the handshake hangs, the relay lock must be free.
	time.Sleep(50 * time.Millisecond)
	locked := make(chan struct{})
	go func() { r.mu.Lock(); r.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("relay mutex held during SSH handshake")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a handshake error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake did not honour the deadline")
	}
}
