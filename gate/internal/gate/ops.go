package gate

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/evandn/nodescale/gate/internal/docker"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

type idArgs struct {
	ID      string `json:"id"`
	Timeout int    `json:"timeout,omitempty"`
}

type killArgs struct {
	ID     string `json:"id"`
	Signal string `json:"signal,omitempty"`
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

type renameArgs struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type updateArgs struct {
	ID      string  `json:"id"`
	Restart string  `json:"restart,omitempty"`
	Memory  int64   `json:"memory,omitempty"`
	CPUs    float64 `json:"cpus,omitempty"`
}

type envArgs struct {
	ID       string `json:"id"`
	ReplyKey string `json:"replyKey"`
}

type execArgs struct {
	ID         string   `json:"id"`
	Cmd        []string `json:"cmd"`
	User       string   `json:"user,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
	Env        []string `json:"env,omitempty"`
	Timeout    int      `json:"timeout,omitempty"`
}

type imageArgs struct {
	Image string `json:"image"`
}

type imageRemoveArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force,omitempty"`
}

type pruneArgs struct {
	All bool `json:"all,omitempty"`
}

type nameArgs struct {
	Name  string `json:"name"`
	Force bool   `json:"force,omitempty"`
}

type networkCreateArgs struct {
	Name     string `json:"name"`
	Internal bool   `json:"internal,omitempty"`
}

type stackRemoveArgs struct {
	Name    string `json:"name"`
	Volumes bool   `json:"volumes,omitempty"`
}

type auditArgs struct {
	Lines int `json:"lines,omitempty"`
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

func ref(id string) error {
	if !docker.ValidRef(id) {
		return badRef("id")
	}
	return nil
}

func (g *Gate) dispatch(ctx context.Context, v *Verified) (any, error) {
	args := v.Req.Args
	d := g.docker
	pol := g.cfg.Policy.withDefaults()

	switch v.Req.Op {
	case "agent.hello":
		host, _ := os.Hostname()
		return map[string]any{
			"agent": g.id, "publicKey": protocol.B64(g.pub), "sealKey": protocol.B64(g.SealPublicKey()),
			"version": Version, "hostname": host, "rpId": g.cfg.RPID, "origins": g.cfg.Origins,
		}, nil

	case "agent.info":
		host, _ := os.Hostname()
		return map[string]any{
			"agent": g.id, "publicKey": protocol.B64(g.pub), "sealKey": protocol.B64(g.SealPublicKey()),
			"version": Version, "hostname": host, "rpId": g.cfg.RPID, "origins": g.cfg.Origins,
			"signers": len(g.cfg.Signers), "policy": pol,
		}, nil

	case "host.info":
		return hostInfo(), nil

	case "audit.read":
		var a auditArgs
		if err := parseArgs(args, &a); err != nil {
			return nil, err
		}
		return g.readAudit(a.Lines)

	case "signers.list":
		return g.cfg.Signers, nil

	case "signers.add":
		var s Signer
		if err := parseArgs(args, &s); err != nil {
			return nil, err
		}
		if err := s.init(); err != nil {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "signer: %v", err)
		}
		s.AddedAt = g.opts.Now().Unix()
		s.AddedBy = v.Signer.Label
		if s.AddedBy == "" {
			s.AddedBy = v.Signer.ID
		}
		err := g.withConfigLock(func(cfg *Config) error {
			for _, e := range cfg.Signers {
				if e.ID == s.ID {
					return protocol.Errorf(protocol.CodeConflict, "passkey is already trusted")
				}
			}
			cfg.Signers = append(cfg.Signers, s)
			return nil
		})
		if err != nil {
			return nil, err
		}
		return s, nil

	case "signers.remove":
		var r signerRemoveArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		raw, err := protocol.UnB64(r.ID)
		if err != nil {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "id must be base64url")
		}
		id := protocol.B64(raw)
		err = g.withConfigLock(func(cfg *Config) error {
			n := len(cfg.Signers)
			cfg.Signers = slices.DeleteFunc(cfg.Signers, func(s Signer) bool { return s.ID == id })
			if len(cfg.Signers) == n {
				return protocol.Errorf(protocol.CodeNotFound, "passkey is not trusted")
			}
			if !slices.ContainsFunc(cfg.Signers, func(s Signer) bool { return s.Role == RoleAdmin }) {
				return protocol.Errorf(protocol.CodeConflict, "refusing to remove the last admin passkey")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id}, nil

	case "system.info":
		return d.Info(ctx)

	case "system.df":
		return d.DiskUsage(ctx)

	case "containers.list":
		var l listArgs
		if err := parseArgs(args, &l); err != nil {
			return nil, err
		}
		return d.ListContainers(ctx, l.All)

	case "containers.env":
		var r envArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		reply, err := protocol.UnB64(r.ReplyKey)
		if err != nil || len(reply) != 32 {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "replyKey must be a base64url X25519 public key; environment values are only returned encrypted")
		}
		var doc struct {
			ID     string `json:"Id"`
			Config struct {
				Env []string `json:"Env"`
			} `json:"Config"`
		}
		raw, err := d.InspectContainer(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		if doc.Config.Env == nil {
			doc.Config.Env = []string{}
		}
		plain, _ := json.Marshal(doc.Config.Env)
		sealed, err := g.sealTo(reply, plain, "containers.env")
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": doc.ID, "sealed": sealed}, nil

	case "containers.inspect", "containers.stats", "containers.top":
		var r idArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		switch v.Req.Op {
		case "containers.stats":
			return d.Stats(ctx, r.ID)
		case "containers.top":
			return d.Top(ctx, r.ID)
		}
		raw, err := d.InspectContainer(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		cfg, _ := doc["Config"].(map[string]any)
		env, _ := cfg["Env"].([]any)
		// Environment values often hold secrets; reading them needs the admin
		// operation containers.env, which returns them encrypted to the browser.
		if cfg != nil && env != nil {
			cfg["Env"] = redactEnvList(env)
		}
		return doc, nil

	case "containers.logs":
		var r logsArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if r.Tail <= 0 || r.Tail > 5000 {
			r.Tail = 500
		}
		_, tty, err := d.ContainerLabels(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		return d.Logs(ctx, r.ID, r.Tail, r.Since, tty)

	case "containers.start", "containers.stop", "containers.restart", "containers.pause", "containers.unpause":
		var r idArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if r.Timeout < 0 || r.Timeout > 600 {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "timeout must be 0-600 seconds")
		}
		var err error
		if v.Req.Op != "containers.stop" && v.Req.Op != "containers.pause" {
			if err := g.existingPolicy(ctx, r.ID); err != nil {
				return nil, err
			}
		}
		switch v.Req.Op {
		case "containers.start":
			err = d.Start(ctx, r.ID)
		case "containers.stop":
			err = d.Stop(ctx, r.ID, r.Timeout)
		case "containers.restart":
			err = d.Restart(ctx, r.ID, r.Timeout)
		case "containers.pause":
			err = d.Pause(ctx, r.ID)
		default:
			err = d.Unpause(ctx, r.ID)
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "containers.kill":
		var r killArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if r.Signal != "" && !capRe.MatchString(strings.ToUpper(r.Signal)) {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "signal must be a name such as SIGTERM")
		}
		if err := d.Kill(ctx, r.ID, r.Signal); err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "containers.remove":
		var r removeArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if err := d.Remove(ctx, r.ID, r.Force, r.Volumes); err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID}, nil

	case "containers.rename":
		var r renameArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.Name) {
			return nil, badRef("name")
		}
		if err := d.Rename(ctx, r.ID, r.Name); err != nil {
			return nil, err
		}
		return map[string]any{"id": r.ID, "name": r.Name}, nil

	case "containers.update":
		var r updateArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if err := g.existingPolicy(ctx, r.ID); err != nil {
			return nil, err
		}
		body := map[string]any{}
		switch r.Restart {
		case "":
		case "no", "always", "unless-stopped", "on-failure":
			body["RestartPolicy"] = map[string]any{"Name": r.Restart}
		default:
			return nil, protocol.Errorf(protocol.CodeBadRequest, "invalid restart policy")
		}
		if r.Memory > 0 {
			if r.Memory < 6<<20 {
				return nil, protocol.Errorf(protocol.CodeBadRequest, "memory limit must be at least 6 MiB")
			}
			body["Memory"] = r.Memory
			body["MemorySwap"] = -1
		}
		if r.CPUs > 0 {
			body["NanoCpus"] = int64(r.CPUs * 1e9)
		}
		return d.Update(ctx, r.ID, body)

	case "containers.exec":
		var r execArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if err := ref(r.ID); err != nil {
			return nil, err
		}
		if len(r.Cmd) == 0 || len(r.Cmd) > 256 {
			return nil, protocol.Errorf(protocol.CodeBadRequest, "cmd must have 1-256 arguments")
		}
		if r.Timeout <= 0 || r.Timeout > 600 {
			r.Timeout = 60
		}
		if err := g.unsealEnv(r.Env); err != nil {
			return nil, err
		}
		// Exec into a privileged or socket-mounting container would be a
		// path to root on the host.
		if err := g.existingPolicy(ctx, r.ID); err != nil {
			return nil, err
		}
		ectx, cancel := context.WithTimeout(ctx, time.Duration(r.Timeout)*time.Second)
		defer cancel()
		return d.Exec(ectx, r.ID, r.Cmd, r.User, r.WorkingDir, r.Env, 1<<20)

	case "containers.create":
		var s ContainerSpec
		if err := parseArgs(args, &s); err != nil {
			return nil, err
		}
		if err := g.unsealEnv(s.Env); err != nil {
			return nil, err
		}
		if err := s.validate(pol.Containers); err != nil {
			return nil, err
		}
		var id string
		err := g.withDeployLock(func() error {
			others, err := g.otherBinds(ctx, nil)
			if err != nil {
				return err
			}
			if err := checkBindOverlap([]*ContainerSpec{&s}, others); err != nil {
				return err
			}
			id, err = g.createContainer(ctx, &s, nil)
			return err
		})
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id}, nil

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

	case "images.prune":
		var r pruneArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		return d.PruneImages(ctx, r.All)

	case "networks.list":
		return d.ListNetworks(ctx)

	case "networks.create":
		var r networkCreateArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.Name) {
			return nil, badRef("name")
		}
		id, err := d.CreateNetwork(ctx, r.Name, map[string]string{LabelManaged: "true"}, r.Internal)
		if err != nil {
			return nil, err
		}
		return map[string]any{"id": id}, nil

	case "networks.remove":
		var r nameArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.Name) {
			return nil, badRef("name")
		}
		if slices.Contains([]string{"bridge", "host", "none"}, r.Name) {
			return nil, protocol.Errorf(protocol.CodeForbidden, "built-in networks cannot be removed")
		}
		if err := d.RemoveNetwork(ctx, r.Name); err != nil {
			return nil, err
		}
		return map[string]any{"name": r.Name}, nil

	case "volumes.list":
		return d.ListVolumes(ctx)

	case "volumes.create":
		var r nameArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.Name) {
			return nil, badRef("name")
		}
		if err := d.CreateVolume(ctx, r.Name, map[string]string{LabelManaged: "true"}); err != nil {
			return nil, err
		}
		return map[string]any{"name": r.Name}, nil

	case "volumes.remove":
		var r nameArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		if !docker.ValidRef(r.Name) {
			return nil, badRef("name")
		}
		if err := d.RemoveVolume(ctx, r.Name, r.Force); err != nil {
			return nil, err
		}
		return map[string]any{"name": r.Name}, nil

	case "stacks.deploy":
		var s StackSpec
		if err := parseArgs(args, &s); err != nil {
			return nil, err
		}
		return g.deployStack(ctx, s)

	case "stacks.remove":
		var r stackRemoveArgs
		if err := parseArgs(args, &r); err != nil {
			return nil, err
		}
		return g.removeStack(ctx, r.Name, r.Volumes)
	}
	return nil, protocol.Errorf(protocol.CodeUnsupported, "operation %q is not implemented", v.Req.Op)
}

// readAudit returns the most recent entries of the server-side audit log.
func (g *Gate) readAudit(n int) ([]json.RawMessage, error) {
	if n <= 0 || n > 1000 {
		n = 200
	}
	f, err := os.Open(g.opts.Paths.auditPath())
	if os.IsNotExist(err) {
		return []json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const window = 512 << 10
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := st.Size() - window
	if off < 0 {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:] // first line may be partial
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]json.RawMessage, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		if json.Valid([]byte(lines[i])) {
			out = append(out, json.RawMessage(lines[i]))
		}
	}
	return out, nil
}
