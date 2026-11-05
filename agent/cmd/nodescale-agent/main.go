// Command nodescale-agent runs on every managed server.
//
//	nodescale-agent serve          verify signed requests on a unix socket (default)
//	nodescale-agent gate           SSH login shell: pipe one request to the socket
//	nodescale-agent install-gate   copy this binary to the host as the gate shell
//	nodescale-agent id             print the agent ID and public key
//	nodescale-agent version
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/evandn/nodescale/agent/internal/agent"
	"github.com/evandn/nodescale/agent/internal/protocol"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var (
	configPath   = env("NODESCALE_CONFIG", "/etc/nodescale/agent.json")
	identityPath = env("NODESCALE_IDENTITY", "/var/lib/nodescale/identity.key")
	auditPath    = env("NODESCALE_AUDIT", "/var/lib/nodescale/audit.jsonl")
	socketPath   = env("NODESCALE_SOCKET", "/run/nodescale/agent.sock")
	dockerSocket = env("DOCKER_SOCKET", "/var/run/docker.sock")
)

func main() {
	// When installed as a login shell the binary is invoked as
	// "nodescale-gate" (or "-nodescale-gate" for login shells).
	if strings.TrimPrefix(filepath.Base(os.Args[0]), "-") == "nodescale-gate" {
		os.Exit(gate())
	}
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "gate":
		os.Exit(gate())
	case "install-gate":
		dest := "/host/usr/local/bin/nodescale-gate"
		if len(os.Args) > 2 {
			dest = os.Args[2]
		}
		if err := installGate(dest); err != nil {
			fmt.Fprintln(os.Stderr, "install-gate:", err)
			os.Exit(1)
		}
	case "id":
		priv, err := agent.LoadOrCreateIdentity(identityPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "id:", err)
			os.Exit(1)
		}
		pub := priv.Public().(ed25519.PublicKey)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"agent": protocol.AgentID(pub), "publicKey": protocol.B64(pub)})
	case "version":
		fmt.Println(agent.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}

func serve() int {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	a, err := agent.New(agent.Options{
		ConfigPath:   configPath,
		IdentityPath: identityPath,
		AuditPath:    auditPath,
		DockerSocket: dockerSocket,
		Logger:       log,
	})
	if err != nil {
		log.Error("startup failed", "err", err)
		return 1
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o750); err != nil {
		log.Error("socket dir", "err", err)
		return 1
	}
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Error("listen", "err", err)
		return 1
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		log.Error("chmod socket", "err", err)
		return 1
	}
	if gid := os.Getenv("NODESCALE_SOCKET_GID"); gid != "" {
		n, err := strconv.Atoi(gid)
		if err == nil {
			err = os.Chown(socketPath, 0, n)
			if err == nil {
				err = os.Chown(filepath.Dir(socketPath), 0, n)
			}
		}
		if err != nil {
			log.Error("chown socket", "err", err)
			return 1
		}
	}

	log.Info("nodescale agent ready", "agent", a.ID(), "publicKey", protocol.B64(a.PublicKey()), "version", agent.Version, "socket", socketPath)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Serve(ctx, ln); err != nil {
		log.Error("serve", "err", err)
		return 1
	}
	return 0
}

// gate is the login shell for the restricted "nodescale" SSH user. It forwards
// exactly one request from stdin to the agent socket and prints the response.
// It never interprets its arguments, so the SSH command line cannot be used to
// run anything else; and even arbitrary code running as the "nodescale" user
// can only submit requests that the agent will verify.
func gate() int {
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "This account only accepts signed nodescale requests. Interactive login is disabled.")
		return 1
	}
	req, err := io.ReadAll(io.LimitReader(os.Stdin, agent.MaxRequestBytes+1))
	if err != nil || len(req) == 0 || len(req) > agent.MaxRequestBytes {
		fmt.Fprintln(os.Stderr, "gate: expected a single request on stdin")
		return 2
	}
	if req[len(req)-1] != '\n' {
		req = append(req, '\n')
	}
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gate: agent unavailable:", err)
		return 3
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	if _, err := conn.Write(req); err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		return 3
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := bufio.NewReaderSize(conn, 64<<10).ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, "gate:", err)
		return 3
	}
	_, _ = os.Stdout.Write(line)
	return 0
}

func installGate(dest string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	src, err := os.Open(self)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".nodescale-gate-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return err
	}
	fmt.Println("installed", dest)
	return nil
}
