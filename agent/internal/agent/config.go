package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/evandn/nodescale/agent/internal/protocol"
)

// Roles a signer can hold.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Signer is a passkey trusted by this agent.
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

// Policy tunes verification limits.
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
}

// Config is the on-disk agent configuration (/etc/nodescale/agent.json).
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
	return p
}

// LoadConfig reads and validates the configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
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
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
			if !(err == nil && u.Scheme == "http" && strings.HasPrefix(u.Host, "localhost")) {
				return fmt.Errorf("origin %q must be an https origin such as https://nodescale.example.com", o)
			}
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
	k, err := protocol.ParsePublicKey(s.Alg, s.PublicKey)
	if err != nil {
		return err
	}
	s.key = k
	return nil
}

// Save writes the configuration atomically with 0600 permissions.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
