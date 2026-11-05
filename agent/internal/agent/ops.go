package agent

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"

	"github.com/evandn/nodescale/agent/internal/docker"
	"github.com/evandn/nodescale/agent/internal/protocol"
)

// Labels with special meaning to nodescale.
const (
	LabelRole    = "io.nodescale.role"
	LabelManaged = "io.nodescale.managed"
	RoleAgent    = "agent"
)

type idArgs struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout,omitempty"`
}

type logsArgs struct {
	ID    string `json:"id"`
	Tail  int    `json:"tail,omitempty"`
	Since int64  `json:"since,omitempty"`
}

type removeArgs struct {
	ID      string `json:"id"`
	Force   bool   `json:"force,omitempty"`
	Volumes bool   `json:"volumes,omitempty"`
}

type listArgs struct {
	All bool `json:"all,omitempty"`
}

type mountArgs struct {
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

type createArgs struct {
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	Env     []string          `json:"env,omitempty"`
	Cmd     []string          `json:"cmd,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
	Restart string            `json:"restart,omitempty"`
	Network string            `json:"network,omitempty"`
	Mounts  []mountArgs       `json:"mounts,omitempty"`
	Pull    bool              `json:"pull,omitempty"`
	Start   bool              `json:"start,omitempty"`
}

type imageArgs struct {
	Image string `json:"image"`
}

type imageRemoveArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force,omitempty"`
}

type signerRemoveArgs struct {
	ID string `json:"id"`
}

func parseArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	if err := decodeStrict(raw, v); err != nil {
		return protocol.Errorf(protocol.CodeBadRequest, "args: %v", err)
	}
	return nil
}

func badRef(field string) error {
	return protocol.Errorf(protocol.CodeBadRequest, "%s is not a valid identifier", field)
}

func (a *Agent) hostname() string {
	if h := os.Getenv("NODESCALE_HOSTNAME"); h != "" {
		return h
	}
	h, _ := os.Hostname()
	return h
}

func (a *Agent) needDocker() error {
	if a.docker == nil {
		return protocol.Errorf(protocol.CodeUnsupported, "docker is not configured on this agent")
	}
	return nil
}

// guard refuses to stop or remove the agent's own container, which would lock
// every user out of the server.
func (a *Agent) guard(ctx context.Context, id string) error {
	labels, _, err := a.docker.ContainerLabels(ctx, id)
	if err != nil {
		return err
	}
	if labels[LabelRole] == RoleAgent {
		return protocol.Errorf(protocol.CodeForbidden, "the nodescale agent container is protected; manage it over SSH from a trusted device")
	}
	return nil
}

func (a *Agent) dispatch(ctx context.Context, v *Verified) (any, error) {
	args := v.Req.Args
	op := v.Req.Op

	switch op {
	case "agent.hello":
		cfg := a.config()
		return map[string]any{
			"agent": a.id, "publicKey": protocol.B64(a.pub), "version": Version,
			"hostname": a.hostname(), "rpId": cfg.RPID, "origins": cfg.Origins,
		}, nil

	case "agent.info":
		cfg := a.config()
		return map[string]any{
			"agent": a.id, "publicKey": protocol.B64(a.pub), "version": Version,
			"hostname": a.hostname(), "rpId": cfg.RPID, "origins": cfg.Origins,
			"startedAt": a.bootTime.Unix(), "signers": len(cfg.Signers),
			"policy": cfg.Policy.withDefaults(),
		}, nil

	case "signers.list":
		cfg := a.config()
		return cfg.Signers, nil

	case "signers.add":
		var s Signer
		if err := parseArgs(args, &s); err != nil {
			return nil, err
		}
		return a.addSigner(s, v)

	case "signers.remove":
		var r signerRemoveArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		return a.removeSigner(r.ID)
	}

	if err := a.needDocker(); err != nil {
		return nil, err
	}
	d := a.docker

	switch op {
	case "system.info":
		return d.Info(ctx)

	case "containers.list":
		var l listArgs
		if err := parseArgs(args, &l); err != nil {
			return nil, err
		}
		return d.ListContainers(ctx, l.All)

	case "containers.inspect", "containers.stats":
		var r idArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.ID) {
			return nil, badRef("id")
		}
		if op == "containers.stats" {
			return d.Stats(ctx, r.ID)
		}
		return d.InspectContainer(ctx, r.ID)

	case "containers.logs":
		var r logsArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.ID) {
			return nil, badRef("id")
		}
		if r.Tail <= 0 || r.Tail > 5000 {
			r.Tail = 500
		}
		_, tty, err := d.ContainerLabels(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		return d.Logs(ctx, r.ID, r.Tail, r.Since, tty)

	case "containers.start", "containers.stop", "containers.restart":
		var r idArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.ID) {
			return nil, badRef("id")
		}
		if r.Timeout < 0 || r.Timeout > 600 {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "timeout must be 0-600 seconds")
		}
		var err error
		switch op {
		case "containers.start":
			err = d.Start(ctx, r.ID)
		case "containers.stop":
			if err = a.guard(ctx, r.ID); err == nil {
				err = d.Stop(ctx, r.ID, r.Timeout)
			}
		default:
			err = d.Restart(ctx, r.ID, r.Timeout)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "containers.remove":
		var r removeArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.ID) {
			return nil, badRef("id")
		}
		if err := a.guard(ctx, r.ID); err != nil {
			return nil, err
		}
		if err := d.Remove(ctx, r.ID, r.Force, r.Volumes); err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "containers.create":
		var c createArgs
		if err := parseArgs(args, &c); err != nil {
			return nil, err
		}
		return a.createContainer(ctx, c)

	case "images.list":
		return d.ListImages(ctx)

	case "images.pull":
		var r imageArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidImage(r.Image) {
			return nil, badRef("image")
		}
		if err := d.Pull(ctx, r.Image); err != nil {
			return nil, err
		}
		return map[string]any{"image": r.Image}, nil

	case "images.remove":
		var r imageRemoveArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidImage(r.ID) {
			return nil, badRef("id")
		}
		if err := d.RemoveImage(ctx, r.ID, r.Force); err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "networks.list":
		return d.ListNetworks(ctx)
	}
	return nil, protocol.Errorf(protocol.CodeUnsupported, "operation %q is not implemented", op)
}

func (a *Agent) createContainer(ctx context.Context, c createArgs) (any, error) {
	if c.Name != "" && !docker.ValidRef(c.Name) {
		return nil, badRef("name")
	}
	if !docker.ValidImage(c.Image) {
		return nil, badRef("image")
	}
	if c.Network != "" && !docker.ValidRef(c.Network) {
		return nil, badRef("network")
	}
	switch c.Restart {
	case "", "no", "always", "unless-stopped", "on-failure":
	default:
		return nil, protocol.Errorf(protocol.CodeBadRequest, "restart must be no, always, unless-stopped or on-failure")
	}
	labels := map[string]string{}
	for k, val := range c.Labels {
		if strings.HasPrefix(k, "io.nodescale.") {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "labels under io.nodescale.* are reserved")
		}
		labels[k] = val
	}
	labels[LabelManaged] = "true"

	mounts := []map[string]any{}
	for _, m := range c.Mounts {
		if m.Type != "volume" && m.Type != "bind" {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "mount type must be volume or bind")
		}
		if !strings.HasPrefix(m.Target, "/") || m.Source == "" {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "mount needs a source and an absolute target")
		}
		if m.Type == "bind" && slices.Contains([]string{"/var/run/docker.sock", "/run/docker.sock", "/run/nodescale", "/etc/nodescale", "/var/lib/nodescale"}, strings.TrimRight(m.Source, "/")) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "mounting nodescale or docker control paths is not allowed")
		}
		mounts = append(mounts, map[string]any{"Type": m.Type, "Source": m.Source, "Target": m.Target, "ReadOnly": m.ReadOnly})
	}

	if c.Pull {
		if err := a.docker.Pull(ctx, c.Image); err != nil {
			return nil, err
		}
	}
	host := map[string]any{"Mounts": mounts}
	if c.Restart != "" {
		host["RestartPolicy"] = map[string]any{"Name": c.Restart}
	}
	if c.Network != "" {
		host["NetworkMode"] = c.Network
	}
	spec := map[string]any{"Image": c.Image, "Labels": labels, "HostConfig": host}
	if len(c.Env) > 0 {
		spec["Env"] = c.Env
	}
	if len(c.Cmd) > 0 {
		spec["Cmd"] = c.Cmd
	}
	id, err := a.docker.CreateContainer(ctx, c.Name, spec)
	if err != nil {
		return nil, err
	}
	if c.Start {
		if err := a.docker.Start(ctx, id); err != nil {
			return nil, err
		}
	}
	return map[string]any{"id": id}, nil
}

func (a *Agent) addSigner(s Signer, v *Verified) (any, error) {
	if err := s.init(); err != nil {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "signer: %v", err)
	}
	s.AddedAt = a.opts.Now().Unix()
	if v.Signer != nil {
		s.AddedBy = v.Signer.Label
		if s.AddedBy == "" {
			s.AddedBy = v.Signer.ID
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	next := *a.cfg
	next.Signers = slices.Clone(a.cfg.Signers)
	for _, e := range next.Signers {
		if e.ID == s.ID {
			return nil, protocol.Errorf(protocol.CodeConflict, "passkey is already enrolled")
		}
	}
	next.Signers = append(next.Signers, s)
	if err := next.Save(a.opts.ConfigPath); err != nil {
		return nil, err
	}
	a.cfg = &next
	return s, nil
}

func (a *Agent) removeSigner(id string) (any, error) {
	raw, err := protocol.UnB64(id)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeBadRequest, "id must be base64url")
	}
	id = protocol.B64(raw)
	a.mu.Lock()
	defer a.mu.Unlock()
	next := *a.cfg
	next.Signers = nil
	found, admins := false, 0
	for _, e := range a.cfg.Signers {
		if e.ID == id {
			found = true
			continue
		}
		if e.Role == RoleAdmin {
			admins++
		}
		next.Signers = append(next.Signers, e)
	}
	if !found {
		return nil, protocol.Errorf(protocol.CodeNotFound, "passkey is not enrolled")
	}
	if admins == 0 {
		return nil, protocol.Errorf(protocol.CodeConflict, "refusing to remove the last admin passkey")
	}
	if err := next.Save(a.opts.ConfigPath); err != nil {
		return nil, err
	}
	a.cfg = &next
	return map[string]any{"id": id}, nil
}
