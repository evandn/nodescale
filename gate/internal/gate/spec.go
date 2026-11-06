package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/evandn/nodescale/gate/internal/docker"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

// Labels with special meaning to nodescale.
const (
	LabelManaged = "io.nodescale.managed"
	LabelStack   = "io.nodescale.stack"
	LabelService = "io.nodescale.service"
	LabelHash    = "io.nodescale.hash"
)

// ContainerSpec is the declarative container description accepted by
// containers.create and (per service) stacks.deploy.
type ContainerSpec struct {
	Name        string            `json:"name,omitempty"`
	Image       string            `json:"image"`
	Cmd         []string          `json:"cmd,omitempty"`
	Entrypoint  []string          `json:"entrypoint,omitempty"`
	Env         []string          `json:"env,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	User        string            `json:"user,omitempty"`
	WorkingDir  string            `json:"workingDir,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	Restart     string            `json:"restart,omitempty"`
	Networks    []string          `json:"networks,omitempty"` // the first one is the primary network
	Aliases     []string          `json:"aliases,omitempty"`
	NetworkMode string            `json:"networkMode,omitempty"` // "", "none" or "host"
	PidMode     string            `json:"pidMode,omitempty"`
	IpcMode     string            `json:"ipcMode,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Ports       []PortSpec        `json:"ports,omitempty"`
	Memory      int64             `json:"memory,omitempty"` // bytes
	CPUs        float64           `json:"cpus,omitempty"`
	ReadOnly    bool              `json:"readOnly,omitempty"`
	CapAdd      []string          `json:"capAdd,omitempty"`
	CapDrop     []string          `json:"capDrop,omitempty"`
	Privileged  bool              `json:"privileged,omitempty"`
	Devices     []string          `json:"devices,omitempty"`
	ExtraHosts  []string          `json:"extraHosts,omitempty"`
	Init        bool              `json:"init,omitempty"`
	StopTimeout int               `json:"stopTimeout,omitempty"`
	Healthcheck *Healthcheck      `json:"healthcheck,omitempty"`
	Pull        string            `json:"pull,omitempty"` // "missing" (default), "always", "never"
	Start       bool              `json:"start,omitempty"`
}

// Mount is a volume, bind or tmpfs mount.
type Mount struct {
	Type     string `json:"type"`
	Source   string `json:"source,omitempty"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

// PortSpec publishes a container port on the host.
type PortSpec struct {
	HostIP        string `json:"hostIp,omitempty"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
}

// Healthcheck mirrors Docker's health check (durations in seconds).
type Healthcheck struct {
	Test        []string `json:"test"`
	Interval    int      `json:"interval,omitempty"`
	Timeout     int      `json:"timeout,omitempty"`
	StartPeriod int      `json:"startPeriod,omitempty"`
	Retries     int      `json:"retries,omitempty"`
}

var (
	envKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)
	capRe      = regexp.MustCompile(`^[A-Z_]+$`)
	hostnameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,62}$`)
	devRe      = regexp.MustCompile(`^/dev/[a-zA-Z0-9/_\-.]+(:/dev/[a-zA-Z0-9/_\-.]+)?(:[rwm]+)?$`)
	hostEntry  = regexp.MustCompile(`^[a-zA-Z0-9.\-]+:[0-9a-fA-F.:]+$|^[a-zA-Z0-9.\-]+:host-gateway$`)
)

func bad(format string, args ...any) error {
	return protocol.Errorf(protocol.CodeBadRequest, format, args...)
}

func denied(format string, args ...any) error {
	return protocol.Errorf(protocol.CodeForbidden, format+" (change the server policy in /etc/nodescale/gate.json to allow it)", args...)
}

// validate checks the spec's syntax and enforces the server's container
// policy. It resolves bind mount sources on the host so symlinks cannot be
// used to escape the allowed prefixes.
func (s *ContainerSpec) validate(pol ContainerPolicy) error {
	if s.Name != "" && !docker.ValidRef(s.Name) {
		return bad("name %q is not a valid container name", s.Name)
	}
	if !docker.ValidImage(s.Image) {
		return bad("image %q is not a valid image reference", s.Image)
	}
	switch s.Restart {
	case "", "no", "always", "unless-stopped", "on-failure":
	default:
		return bad("restart must be no, always, unless-stopped or on-failure")
	}
	switch s.Pull {
	case "", "missing", "always", "never":
	default:
		return bad("pull must be missing, always or never")
	}
	for i, e := range s.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || !envKeyRe.MatchString(k) {
			// Never echo the entry: its value may be a secret.
			return bad("environment entry %d must be KEY=value with a valid name", i+1)
		}
	}
	for k := range s.Labels {
		if strings.HasPrefix(k, "io.nodescale.") {
			return bad("labels under io.nodescale.* are reserved")
		}
	}
	if s.Hostname != "" && !hostnameRe.MatchString(s.Hostname) {
		return bad("hostname is invalid")
	}
	for _, n := range append(slices.Clone(s.Networks), s.Aliases...) {
		if !docker.ValidRef(n) {
			return bad("network or alias %q is invalid", n)
		}
	}
	// Docker's built-in network names select a network mode; listing them in
	// networks must not bypass the namespace policy below.
	for _, n := range s.Networks {
		switch n {
		case "host":
			if !pol.AllowHostNamespaces {
				return denied("sharing host namespaces is not allowed")
			}
			if len(s.Networks) > 1 {
				return bad("the host network cannot be combined with other networks")
			}
		case "none", "bridge":
			if len(s.Networks) > 1 {
				return bad("the %s network cannot be combined with other networks", n)
			}
		}
	}
	for _, h := range s.ExtraHosts {
		if !hostEntry.MatchString(h) {
			return bad("extra host %q must be name:ip", h)
		}
	}
	if s.Memory != 0 && s.Memory < 6<<20 {
		return bad("memory limit must be at least 6 MiB")
	}
	if s.CPUs < 0 || s.CPUs > 1024 {
		return bad("cpus is out of range")
	}
	if s.StopTimeout < 0 || s.StopTimeout > 600 {
		return bad("stopTimeout must be 0-600 seconds")
	}
	if h := s.Healthcheck; h != nil {
		if len(h.Test) == 0 || h.Interval < 0 || h.Timeout < 0 || h.StartPeriod < 0 || h.Retries < 0 {
			return bad("healthcheck is invalid")
		}
	}

	// Host-level privileges.
	if s.Privileged && !pol.AllowPrivileged {
		return denied("privileged containers are not allowed")
	}
	for _, m := range []string{s.NetworkMode, s.PidMode, s.IpcMode} {
		switch m {
		case "", "none", "bridge":
		case "host":
			if !pol.AllowHostNamespaces {
				return denied("sharing host namespaces is not allowed")
			}
		default:
			return bad("unsupported namespace mode %q", m)
		}
	}
	if s.NetworkMode != "" && s.NetworkMode != "bridge" && len(s.Networks) > 0 {
		return bad("networks cannot be combined with networkMode %q", s.NetworkMode)
	}
	if len(s.Devices) > 0 {
		if !pol.AllowDevices {
			return denied("device access is not allowed")
		}
		for _, d := range s.Devices {
			if !devRe.MatchString(d) {
				return bad("device %q is invalid", d)
			}
		}
	}
	for i, c := range s.CapAdd {
		c = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		s.CapAdd[i] = c
		if !capRe.MatchString(c) {
			return bad("capability %q is invalid", c)
		}
		if !s.Privileged && !slices.Contains(pol.AllowedCapabilities, c) && !pol.AllowPrivileged {
			return denied("capability %s is not allowed", c)
		}
	}
	for i, c := range s.CapDrop {
		s.CapDrop[i] = strings.TrimPrefix(strings.ToUpper(c), "CAP_")
		if !capRe.MatchString(s.CapDrop[i]) {
			return bad("capability %q is invalid", c)
		}
	}
	if len(s.Ports) > 0 && !pol.AllowPublishedPorts {
		return denied("publishing ports on the host is not allowed; expose services through a Cloudflare Tunnel on the nodescale network")
	}
	for _, p := range s.Ports {
		if p.ContainerPort < 1 || p.ContainerPort > 65535 || p.HostPort < 0 || p.HostPort > 65535 {
			return bad("port numbers must be 1-65535")
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			return bad("port protocol must be tcp or udp")
		}
	}
	for i := range s.Mounts {
		if err := validateMount(&s.Mounts[i], pol); err != nil {
			return err
		}
	}
	return nil
}

var protectedTargets = []string{"/var/run/docker.sock", "/run/docker.sock"}

func validateMount(m *Mount, pol ContainerPolicy) error {
	if !filepath.IsAbs(m.Target) || filepath.Clean(m.Target) == "/" {
		return bad("mount target %q must be an absolute path other than /", m.Target)
	}
	switch m.Type {
	case "tmpfs":
		if m.Source != "" {
			return bad("tmpfs mounts take no source")
		}
	case "volume":
		if !docker.ValidRef(m.Source) {
			return bad("volume name %q is invalid", m.Source)
		}
	case "bind":
		src, err := resolveBindSource(m.Source)
		if err != nil {
			return err
		}
		if slices.Contains(protectedTargets, src) || !underPrefixes(src, pol.BindMountPrefixes) {
			return denied("bind mounts from %s are not allowed (allowed under %s)", src, strings.Join(pol.BindMountPrefixes, ", "))
		}
		// Hand Docker the resolved path, never the symlinked one.
		m.Source = src
	default:
		return bad("mount type must be volume, bind or tmpfs")
	}
	return nil
}

func (s *ContainerSpec) bindSources() []string {
	var out []string
	for _, m := range s.Mounts {
		if m.Type == "bind" {
			out = append(out, m.Source)
		}
	}
	return out
}

// nested reports whether one path is a strict ancestor of the other.
func nested(a, b string) bool {
	return a != b && (strings.HasPrefix(b, a+"/") || strings.HasPrefix(a, b+"/"))
}

// checkBindOverlap refuses bind mounts that are a strict ancestor or
// descendant of another bind mount. Docker resolves bind sources each time a
// container starts, so a container with write access to /srv/x could plant
// a symlink at /srv/x/y and turn a sibling's bind of /srv/x/y into a mount of
// the host's /. Identical sources are fine: neither side can replace the
// directory itself. existing holds bind sources of containers that stay.
func checkBindOverlap(specs []*ContainerSpec, existing []string) error {
	var mine []string
	for _, s := range specs {
		mine = append(mine, s.bindSources()...)
	}
	for i, a := range mine {
		for _, b := range append(slices.Clone(mine[i+1:]), existing...) {
			if nested(a, b) {
				return denied("bind mount %s overlaps bind mount %s; use separate directories (one could redirect the other through a symlink)", a, b)
			}
		}
	}
	return nil
}

// otherBinds lists bind sources of all containers except those whose ID is
// in skip.
func (g *Gate) otherBinds(ctx context.Context, skip map[string]bool) ([]string, error) {
	all, err := g.docker.ListContainers(ctx, true)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range all {
		if !skip[c.ID] {
			out = append(out, c.Binds...)
		}
	}
	return out, nil
}

// withDeployLock serialises container creation so two concurrent deploys
// cannot each pass the overlap check against the other.
func (g *Gate) withDeployLock(fn func() error) error {
	f, err := os.OpenFile(filepath.Join(g.opts.Paths.State, "deploy.lock"), os.O_RDWR|os.O_CREATE, 0o660)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}

// existingPolicy applies the container policy to a container that already
// exists (possibly created outside nodescale) before starting it, running
// commands in it, or changing its restart policy.
func (g *Gate) existingPolicy(ctx context.Context, id string) error {
	return g.existingPolicyDepth(ctx, id, 0)
}

func (g *Gate) existingPolicyDepth(ctx context.Context, id string, depth int) error {
	var c struct {
		Name       string `json:"Name"`
		HostConfig struct {
			Privileged        bool           `json:"Privileged"`
			NetworkMode       string         `json:"NetworkMode"`
			PidMode           string         `json:"PidMode"`
			IpcMode           string         `json:"IpcMode"`
			UTSMode           string         `json:"UTSMode"`
			UsernsMode        string         `json:"UsernsMode"`
			CapAdd            []string       `json:"CapAdd"`
			SecurityOpt       []string       `json:"SecurityOpt"`
			Devices           []any          `json:"Devices"`
			DeviceCgroupRules []string       `json:"DeviceCgroupRules"`
			DeviceRequests    []any          `json:"DeviceRequests"`
			PortBindings      map[string]any `json:"PortBindings"`
			MaskedPaths       []string       `json:"MaskedPaths"`
			ReadonlyPaths     []string       `json:"ReadonlyPaths"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type   string `json:"Type"`
			Name   string `json:"Name"`
			Source string `json:"Source"`
		} `json:"Mounts"`
	}
	raw, err := g.docker.InspectContainer(ctx, id)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return err
	}
	pol := g.cfg.Policy.withDefaults().Containers
	h := c.HostConfig
	name := strings.TrimPrefix(c.Name, "/")
	deny := func(why string) error {
		return denied("container %s does not satisfy this server's policy (%s)", name, why)
	}
	if h.Privileged && !pol.AllowPrivileged {
		return deny("privileged")
	}
	for _, m := range []string{h.NetworkMode, h.PidMode, h.IpcMode, h.UTSMode, h.UsernsMode} {
		// CgroupnsMode is not checked: "host" is Docker's default on cgroup v1.
		if m == "host" && !pol.AllowHostNamespaces {
			return deny("host namespace")
		}
		// Sharing another container's namespace inherits that container's
		// privileges, so the target must satisfy the policy too.
		if target, ok := strings.CutPrefix(m, "container:"); ok {
			if depth >= 3 {
				return deny("nested container namespaces")
			}
			if err := g.existingPolicyDepth(ctx, target, depth+1); err != nil {
				return deny("shares namespaces with a container that does not satisfy the policy")
			}
		}
	}
	if (len(h.Devices) > 0 || len(h.DeviceCgroupRules) > 0 || len(h.DeviceRequests) > 0) && !pol.AllowDevices {
		return deny("devices")
	}
	if len(h.PortBindings) > 0 && !pol.AllowPublishedPorts {
		return deny("published ports")
	}
	for _, cp := range h.CapAdd {
		cp = strings.TrimPrefix(strings.ToUpper(cp), "CAP_")
		if !pol.AllowPrivileged && !slices.Contains(pol.AllowedCapabilities, cp) {
			return deny("capability " + cp)
		}
	}
	for _, o := range h.SecurityOpt {
		if strings.Contains(o, "unconfined") || o == "label=disable" || o == "label:disable" {
			if !pol.AllowPrivileged {
				return deny("security option " + o)
			}
		}
	}
	// Docker masks parts of /proc for unprivileged containers; empty lists
	// mean e.g. /proc/sys is writable.
	if !h.Privileged && !pol.AllowPrivileged && (len(h.MaskedPaths) == 0 || len(h.ReadonlyPaths) == 0) {
		return deny("unmasked /proc paths")
	}
	for _, m := range c.Mounts {
		switch m.Type {
		case "bind":
			if slices.Contains(protectedTargets, m.Source) || !underPrefixes(m.Source, pol.BindMountPrefixes) {
				return deny("bind mount from " + m.Source)
			}
		case "volume":
			if err := g.checkVolume(ctx, m.Name, pol); err != nil {
				return deny("volume " + m.Name)
			}
		}
	}
	return nil
}

// checkVolume refuses volumes that are really host binds or use another
// driver: a local volume with "o=bind,device=/" mounts the host's root.
func (g *Gate) checkVolume(ctx context.Context, name string, pol ContainerPolicy) error {
	v, err := g.docker.InspectVolume(ctx, name)
	if err != nil {
		return err
	}
	if v == nil {
		return nil // Docker will create a plain local volume
	}
	if v.Driver != "local" && !pol.AllowPrivileged {
		return denied("volume %s uses driver %s", name, v.Driver)
	}
	if dev := v.Options["device"]; dev != "" || strings.Contains(v.Options["o"], "bind") {
		src, err := resolveBindSource(dev)
		if err != nil || slices.Contains(protectedTargets, src) || !underPrefixes(src, pol.BindMountPrefixes) {
			return denied("volume %s is backed by host path %q", name, dev)
		}
	}
	return nil
}

// resolveBindSource resolves symlinks in the longest existing prefix of the
// path, so that a symlink planted by a container (e.g. /srv/app/x -> /)
// cannot redirect a later bind mount outside the allowed prefixes.
func resolveBindSource(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", bad("bind source %q must be an absolute host path", p)
	}
	p = filepath.Clean(p)
	rest := ""
	cur := p
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", protocol.Errorf(protocol.CodeForbidden, "cannot inspect bind source %s: %v", cur, err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", bad("bind source %q cannot be resolved", p)
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

func underPrefixes(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		pre = filepath.Clean(pre)
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// dockerBody converts a validated spec into a Docker Engine create request.
func (s *ContainerSpec) dockerBody(labels map[string]string) map[string]any {
	l := map[string]string{}
	for k, v := range s.Labels {
		l[k] = v
	}
	for k, v := range labels {
		l[k] = v
	}
	l[LabelManaged] = "true"

	mounts := []map[string]any{}
	for _, m := range s.Mounts {
		mm := map[string]any{"Type": m.Type, "Target": m.Target, "ReadOnly": m.ReadOnly}
		if m.Source != "" {
			mm["Source"] = m.Source
		}
		if m.Type == "bind" {
			mm["BindOptions"] = map[string]any{"CreateMountpoint": true}
		}
		mounts = append(mounts, mm)
	}

	host := map[string]any{
		"Mounts": mounts,
		"Init":   s.Init,
		// Bounded logs so a chatty container cannot fill the disk.
		"LogConfig": map[string]any{"Type": "json-file", "Config": map[string]string{"max-size": "10m", "max-file": "3"}},
	}
	if s.Restart != "" {
		host["RestartPolicy"] = map[string]any{"Name": s.Restart}
	}
	if s.NetworkMode != "" {
		host["NetworkMode"] = s.NetworkMode
	} else if len(s.Networks) > 0 {
		host["NetworkMode"] = s.Networks[0]
	}
	if s.PidMode != "" {
		host["PidMode"] = s.PidMode
	}
	if s.IpcMode != "" {
		host["IpcMode"] = s.IpcMode
	}
	if s.Memory > 0 {
		host["Memory"] = s.Memory
	}
	if s.CPUs > 0 {
		host["NanoCpus"] = int64(s.CPUs * 1e9)
	}
	if s.ReadOnly {
		host["ReadonlyRootfs"] = true
	}
	if len(s.CapAdd) > 0 {
		host["CapAdd"] = s.CapAdd
	}
	if len(s.CapDrop) > 0 {
		host["CapDrop"] = s.CapDrop
	}
	if s.Privileged {
		host["Privileged"] = true
	}
	if len(s.ExtraHosts) > 0 {
		host["ExtraHosts"] = s.ExtraHosts
	}
	if len(s.Devices) > 0 {
		devs := []map[string]string{}
		for _, d := range s.Devices {
			parts := strings.Split(d, ":")
			dev := map[string]string{"PathOnHost": parts[0], "PathInContainer": parts[0], "CgroupPermissions": "rwm"}
			if len(parts) > 1 && strings.HasPrefix(parts[1], "/") {
				dev["PathInContainer"] = parts[1]
			}
			if p := parts[len(parts)-1]; len(parts) > 1 && !strings.HasPrefix(p, "/") {
				dev["CgroupPermissions"] = p
			}
			devs = append(devs, dev)
		}
		host["Devices"] = devs
	}
	exposed := map[string]any{}
	if len(s.Ports) > 0 {
		bindings := map[string][]map[string]string{}
		for _, p := range s.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			key := strconv.Itoa(p.ContainerPort) + "/" + proto
			exposed[key] = map[string]any{}
			ip := p.HostIP
			if ip == "" {
				ip = "127.0.0.1"
			}
			hp := ""
			if p.HostPort > 0 {
				hp = strconv.Itoa(p.HostPort)
			}
			bindings[key] = append(bindings[key], map[string]string{"HostIp": ip, "HostPort": hp})
		}
		host["PortBindings"] = bindings
	}

	body := map[string]any{"Image": s.Image, "Labels": l, "HostConfig": host}
	if len(exposed) > 0 {
		body["ExposedPorts"] = exposed
	}
	if len(s.Cmd) > 0 {
		body["Cmd"] = s.Cmd
	}
	if len(s.Entrypoint) > 0 {
		body["Entrypoint"] = s.Entrypoint
	}
	if len(s.Env) > 0 {
		body["Env"] = s.Env
	}
	if s.User != "" {
		body["User"] = s.User
	}
	if s.WorkingDir != "" {
		body["WorkingDir"] = s.WorkingDir
	}
	if s.Hostname != "" {
		body["Hostname"] = s.Hostname
	}
	if s.StopTimeout > 0 {
		body["StopTimeout"] = s.StopTimeout
	}
	if h := s.Healthcheck; h != nil {
		sec := func(n int) int64 { return int64(n) * 1e9 }
		body["Healthcheck"] = map[string]any{"Test": h.Test, "Interval": sec(h.Interval), "Timeout": sec(h.Timeout), "StartPeriod": sec(h.StartPeriod), "Retries": h.Retries}
	}
	if len(s.Networks) > 0 && s.NetworkMode == "" && len(s.Aliases) > 0 {
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{s.Networks[0]: map[string]any{"Aliases": s.Aliases}}}
	}
	return body
}

// ensureImage pulls the image according to the pull policy.
func (g *Gate) ensureImage(ctx context.Context, image, policy string) (string, error) {
	if policy == "always" {
		if err := g.docker.Pull(ctx, image); err != nil {
			return "", err
		}
	}
	id, err := g.docker.ImageID(ctx, image)
	if err != nil {
		return "", err
	}
	if id == "" {
		if policy == "never" {
			return "", protocol.Errorf(protocol.CodeNotFound, "image %s is not present and pull is disabled", image)
		}
		if err := g.docker.Pull(ctx, image); err != nil {
			return "", err
		}
		if id, err = g.docker.ImageID(ctx, image); err != nil {
			return "", err
		}
	}
	return id, nil
}

// ensureNetworks creates missing user networks (labelled as managed).
func (g *Gate) ensureNetworks(ctx context.Context, names []string, labels map[string]string) error {
	for _, n := range names {
		if n == "bridge" || n == "host" || n == "none" {
			continue
		}
		ok, err := g.docker.NetworkExists(ctx, n)
		if err != nil {
			return err
		}
		if !ok {
			l := map[string]string{LabelManaged: "true"}
			for k, v := range labels {
				l[k] = v
			}
			if _, err := g.docker.CreateNetwork(ctx, n, l, false); err != nil && !docker.IsConflict(err) {
				return fmt.Errorf("create network %s: %w", n, err)
			}
		}
	}
	return nil
}

// createContainer creates (and optionally starts) a container from a
// validated spec.
func (g *Gate) createContainer(ctx context.Context, s *ContainerSpec, labels map[string]string) (string, error) {
	pol := g.cfg.Policy.withDefaults().Containers
	for _, m := range s.Mounts {
		if m.Type == "volume" {
			if err := g.checkVolume(ctx, m.Source, pol); err != nil {
				return "", err
			}
		}
	}
	if _, err := g.ensureImage(ctx, s.Image, s.Pull); err != nil {
		return "", err
	}
	if s.NetworkMode == "" {
		if err := g.ensureNetworks(ctx, s.Networks, nil); err != nil {
			return "", err
		}
	}
	id, err := g.docker.CreateContainer(ctx, s.Name, s.dockerBody(labels))
	if err != nil {
		return "", err
	}
	if s.NetworkMode == "" && len(s.Networks) > 1 {
		for _, n := range s.Networks[1:] {
			if err := g.docker.ConnectNetwork(ctx, n, id, s.Aliases); err != nil {
				_ = g.docker.Remove(ctx, id, true, false)
				return "", fmt.Errorf("connect %s: %w", n, err)
			}
		}
	}
	if s.Start {
		if err := g.docker.Start(ctx, id); err != nil {
			return id, err
		}
	}
	return id, nil
}
