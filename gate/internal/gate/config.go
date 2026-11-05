package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

// Roles a signer can hold.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Signer is a passkey trusted by this server.
type Signer struct {
	ID        string `json:"id"` // base64url WebAuthn credential ID
	Alg       int    `json:"alg"`
	PublicKey string `json:"publicKey"` // base64url SPKI
	Role      string `json:"role"`
	Label     string `json:"label,omitempty"`
	User      string `json:"user,omitempty"`
	AddedAt   int64  `json:"addedAt,omitempty"`
	AddedBy   string `json:"addedBy,omitempty"`

	key *protocol.PublicKey
}

// Policy tunes verification limits and what containers may do on this host.
// It can only be changed by root on the server, never over the wire.
type Policy struct {
	// MaxSessionSeconds caps the lifetime of a delegated session certificate.
	MaxSessionSeconds int64 `json:"maxSessionSeconds,omitempty"`
	// MaxRequestSeconds caps exp-iat of an individual request.
	MaxRequestSeconds int64 `json:"maxRequestSeconds,omitempty"`
	// ClockSkewSeconds is the tolerated clock difference with the browser.
	ClockSkewSeconds int64 `json:"clockSkewSeconds,omitempty"`
	// AllowSessionScopes limits which scopes a session certificate may carry.
	// Defaults to ["read", "operate"]. Set to ["read"] to require a fresh
	// passkey touch for every state-changing action.
	AllowSessionScopes []string `json:"allowSessionScopes,omitempty"`

	Containers ContainerPolicy `json:"containers"`
}

// ContainerPolicy limits what a (passkey-signed) container spec may request.
// The defaults keep a signed deploy from turning into root on the host.
type ContainerPolicy struct {
	AllowPrivileged     bool     `json:"allowPrivileged,omitempty"`
	AllowHostNamespaces bool     `json:"allowHostNamespaces,omitempty"` // network/pid/ipc/uts/userns=host
	AllowDevices        bool     `json:"allowDevices,omitempty"`
	AllowPublishedPorts bool     `json:"allowPublishedPorts,omitempty"`
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
	BindMountPrefixes   []string `json:"bindMountPrefixes,omitempty"`
}

// DefaultCapabilities are capabilities that do not by themselves enable
// escaping the container.
var DefaultCapabilities = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID", "SETPCAP", "AUDIT_WRITE", "SYS_CHROOT", "MKNOD", "NET_RAW", "SETFCAP"}

// DefaultBindMountPrefixes are host directories bind mounts may come from.
var DefaultBindMountPrefixes = []string{"/srv", "/opt/apps", "/data", "/mnt"}

// Config is the on-disk configuration (/etc/nodescale/gate.json).
type Config struct {
	RPID    string   `json:"rpId"`
	Origins []string `json:"origins"`
	Signers []Signer `json:"signers"`
	Policy  Policy   `json:"policy"`
}

func (p Policy) withDefaults() Policy {
	if p.MaxSessionSeconds <= 0 {
		p.MaxSessionSeconds = 8 * 3600
	}
	if p.MaxRequestSeconds <= 0 {
		p.MaxRequestSeconds = 300
	}
	if p.ClockSkewSeconds <= 0 {
		p.ClockSkewSeconds = 60
	}
	if p.AllowSessionScopes == nil {
		p.AllowSessionScopes = []string{protocol.ScopeRead, protocol.ScopeOperate}
	}
	if p.Containers.AllowedCapabilities == nil {
		p.Containers.AllowedCapabilities = DefaultCapabilities
	}
	if p.Containers.BindMountPrefixes == nil {
		p.Containers.BindMountPrefixes = DefaultBindMountPrefixes
	}
	return p
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.RPID == "" {
		return errors.New("rpId is required")
	}
	if len(c.Origins) == 0 {
		return errors.New("at least one origin is required")
	}
	for _, o := range c.Origins {
		u, err := url.Parse(o)
		ok := err == nil && u.Host != "" && u.Path == "" && (u.Scheme == "https" || (u.Scheme == "http" && u.Hostname() == "localhost"))
		if !ok {
			return fmt.Errorf("origin %q must be an https origin such as https://nodescale.example.com", o)
		}
	}
	for _, p := range c.Policy.Containers.BindMountPrefixes {
		if !filepath.IsAbs(p) || filepath.Clean(p) == "/" {
			return fmt.Errorf("bind mount prefix %q must be an absolute path other than /", p)
		}
	}
	seen := map[string]bool{}
	admins := 0
	for i := range c.Signers {
		s := &c.Signers[i]
		if err := s.init(); err != nil {
			return fmt.Errorf("signer %q: %w", s.Label, err)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate signer %q", s.ID)
		}
		seen[s.ID] = true
		if s.Role == RoleAdmin {
			admins++
		}
	}
	if admins == 0 {
		return errors.New("at least one admin signer is required")
	}
	return nil
}

func (s *Signer) init() error {
	id, err := protocol.UnB64(s.ID)
	if err != nil || len(id) == 0 || len(id) > 1023 {
		return errors.New("id must be a base64url credential ID")
	}
	s.ID = protocol.B64(id) // canonical form
	switch s.Role {
	case RoleViewer, RoleOperator, RoleAdmin:
	default:
		return fmt.Errorf("unknown role %q", s.Role)
	}
	if len(s.Label) > 200 || len(s.User) > 200 || strings.ContainsAny(s.Label+s.User, "\x00\n") {
		return errors.New("label and user must be short single-line strings")
	}
	k, err := protocol.ParsePublicKey(s.Alg, s.PublicKey)
	if err != nil {
		return err
	}
	s.key = k
	return nil
}

// Save writes the configuration atomically. The containing directory is
// root:docker 2770, so the file is unreachable to anything but root and
// the setgid gate regardless of its owner.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o660)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
