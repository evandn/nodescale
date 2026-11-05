package gate

import (
	"os"
	"path/filepath"
	"syscall"
)

// Paths are the files the gate reads and writes.
type Paths struct {
	Config   string // trusted passkeys and policy
	Identity string // Ed25519 seed that signs responses
	State    string // nonces/ and audit.jsonl live here
	Docker   string // Docker Engine API socket
}

// Default production locations.
var DefaultPaths = Paths{
	Config:   "/etc/nodescale/gate.json",
	Identity: "/var/lib/nodescale/identity.key",
	State:    "/var/lib/nodescale",
	Docker:   "/var/run/docker.sock",
}

// Privileged reports whether this process runs with set-user-ID or
// set-group-ID privileges (the production setup, where the gate is setgid
// docker). In that mode the environment comes from a less privileged caller
// and must never influence which files are used.
func Privileged() bool {
	return syscall.Getuid() != syscall.Geteuid() || syscall.Getgid() != syscall.Getegid()
}

// ResolvePaths returns the production paths, or environment overrides when
// the process is not privileged (development and tests).
func ResolvePaths() Paths {
	p := DefaultPaths
	if Privileged() {
		return p
	}
	if v := os.Getenv("NODESCALE_CONFIG"); v != "" {
		p.Config = v
	}
	if v := os.Getenv("NODESCALE_STATE"); v != "" {
		p.State = v
		p.Identity = filepath.Join(v, "identity.key")
	}
	if v := os.Getenv("NODESCALE_IDENTITY"); v != "" {
		p.Identity = v
	}
	if v := os.Getenv("DOCKER_SOCKET"); v != "" {
		p.Docker = v
	}
	return p
}

func (p Paths) nonceDir() string  { return filepath.Join(p.State, "nonces") }
func (p Paths) auditPath() string { return filepath.Join(p.State, "audit.jsonl") }
