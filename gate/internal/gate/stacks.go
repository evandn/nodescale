package gate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/evandn/nodescale/gate/internal/docker"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

// StackSpec is a set of services deployed and updated together, similar to a
// Compose project. The browser converts compose YAML into this form.
type StackSpec struct {
	Name     string        `json:"name"`
	Services []ServiceSpec `json:"services"`
	// Volumes are named volumes to create (labelled with the stack).
	Volumes []string `json:"volumes,omitempty"`
	// Networks are extra networks services may join; missing ones are created.
	Networks []string `json:"networks,omitempty"`
	// Pull overrides each service's pull policy when set.
	Pull string `json:"pull,omitempty"`
}

// ServiceSpec is one service of a stack.
type ServiceSpec struct {
	Service string `json:"service"`
	ContainerSpec
}

// StackResult reports what deploy did to each service.
type StackResult struct {
	Service string `json:"service"`
	Action  string `json:"action"` // created, recreated, unchanged, removed
	ID      string `json:"id,omitempty"`
}

var stackNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func stackNetwork(stack string) string { return stack + "_default" }

func (g *Gate) deployStack(ctx context.Context, st StackSpec) ([]StackResult, error) {
	if !stackNameRe.MatchString(st.Name) {
		return nil, bad("stack name must be lowercase letters, digits, - and _")
	}
	if len(st.Services) == 0 || len(st.Services) > 50 {
		return nil, bad("a stack needs 1-50 services")
	}
	pol := g.cfg.Policy.withDefaults().Containers
	seen := map[string]bool{}
	for i := range st.Services {
		s := &st.Services[i]
		if !stackNameRe.MatchString(s.Service) || seen[s.Service] {
			return nil, bad("service name %q is invalid or duplicated", s.Service)
		}
		seen[s.Service] = true
		s.Name = st.Name + "-" + s.Service
		if st.Pull != "" {
			s.Pull = st.Pull
		}
		if s.NetworkMode == "" {
			// Every service joins the stack's own network, reachable by its
			// service name, plus any networks it lists (e.g. "nodescale",
			// which cloudflared is attached to).
			nets := []string{stackNetwork(st.Name)}
			for _, n := range s.Networks {
				if n != nets[0] {
					nets = append(nets, n)
				}
			}
			s.Networks = nets
			s.Aliases = appendUnique(s.Aliases, s.Service)
		}
		if s.Restart == "" {
			s.Restart = "unless-stopped"
		}
		s.Start = true
		if err := g.unsealEnv(s.Env); err != nil {
			return nil, fmt.Errorf("service %s: %w", s.Service, err)
		}
		// Validate everything before changing anything on the host.
		if err := s.validate(pol); err != nil {
			return nil, fmt.Errorf("service %s: %w", s.Service, err)
		}
	}
	for _, v := range st.Volumes {
		if !docker.ValidRef(v) {
			return nil, bad("volume name %q is invalid", v)
		}
	}
	for _, n := range st.Networks {
		if !docker.ValidRef(n) {
			return nil, bad("network name %q is invalid", n)
		}
	}

	var results []StackResult
	err := g.withDeployLock(func() error {
		var err error
		results, err = g.applyStack(ctx, st, seen)
		return err
	})
	return results, err
}

func (g *Gate) applyStack(ctx context.Context, st StackSpec, seen map[string]bool) ([]StackResult, error) {
	stackLabels := map[string]string{LabelStack: st.Name}
	if err := g.ensureNetworks(ctx, append([]string{stackNetwork(st.Name)}, st.Networks...), stackLabels); err != nil {
		return nil, err
	}
	for _, v := range st.Volumes {
		if err := g.docker.CreateVolume(ctx, v, map[string]string{LabelManaged: "true", LabelStack: st.Name}); err != nil {
			return nil, fmt.Errorf("volume %s: %w", v, err)
		}
	}

	existing, err := g.docker.ListContainersFiltered(ctx, true, []string{LabelStack + "=" + st.Name})
	if err != nil {
		return nil, err
	}
	byService := map[string]docker.ContainerSummary{}
	mine := map[string]bool{}
	for _, c := range existing {
		byService[c.Labels[LabelService]] = c
		mine[c.ID] = true
	}
	// This stack's own containers are replaced by the new spec, which is
	// checked against itself; everything else on the host must not overlap.
	others, err := g.otherBinds(ctx, mine)
	if err != nil {
		return nil, err
	}
	specs := make([]*ContainerSpec, len(st.Services))
	for i := range st.Services {
		specs[i] = &st.Services[i].ContainerSpec
	}
	if err := checkBindOverlap(specs, others); err != nil {
		return nil, err
	}

	var results []StackResult
	for i := range st.Services {
		s := &st.Services[i]
		imageID, err := g.ensureImage(ctx, s.Image, s.Pull)
		if err != nil {
			return results, fmt.Errorf("service %s: %w", s.Service, err)
		}
		hash := g.specHash(s, imageID)
		cur, exists := byService[s.Service]
		if exists && cur.Labels[LabelHash] == hash && cur.State == "running" {
			results = append(results, StackResult{Service: s.Service, Action: "unchanged", ID: cur.ID})
			continue
		}
		if exists && cur.Labels[LabelHash] == hash {
			if err := g.docker.Start(ctx, cur.ID); err != nil {
				return results, fmt.Errorf("service %s: %w", s.Service, err)
			}
			results = append(results, StackResult{Service: s.Service, Action: "started", ID: cur.ID})
			continue
		}
		action := "created"
		if exists {
			action = "recreated"
			_ = g.docker.Stop(ctx, cur.ID, s.StopTimeout)
			if err := g.docker.Remove(ctx, cur.ID, true, false); err != nil {
				return results, fmt.Errorf("service %s: remove old container: %w", s.Service, err)
			}
		}
		s.Pull = "never" // already ensured above
		id, err := g.createContainer(ctx, &s.ContainerSpec, map[string]string{LabelStack: st.Name, LabelService: s.Service, LabelHash: hash})
		if err != nil {
			return results, fmt.Errorf("service %s: %w", s.Service, err)
		}
		results = append(results, StackResult{Service: s.Service, Action: action, ID: id})
	}

	// Remove services that are no longer part of the stack.
	for name, c := range byService {
		if !seen[name] {
			_ = g.docker.Stop(ctx, c.ID, 10)
			if err := g.docker.Remove(ctx, c.ID, true, false); err != nil {
				return results, fmt.Errorf("remove service %s: %w", name, err)
			}
			results = append(results, StackResult{Service: name, Action: "removed", ID: c.ID})
		}
	}
	return results, nil
}

func (g *Gate) removeStack(ctx context.Context, name string, volumes bool) ([]StackResult, error) {
	if !stackNameRe.MatchString(name) {
		return nil, bad("invalid stack name")
	}
	existing, err := g.docker.ListContainersFiltered(ctx, true, []string{LabelStack + "=" + name})
	if err != nil {
		return nil, err
	}
	if len(existing) == 0 {
		return nil, protocol.Errorf(protocol.CodeNotFound, "stack %s has no containers", name)
	}
	var results []StackResult
	for _, c := range existing {
		_ = g.docker.Stop(ctx, c.ID, 10)
		if err := g.docker.Remove(ctx, c.ID, true, false); err != nil {
			return results, err
		}
		results = append(results, StackResult{Service: c.Labels[LabelService], Action: "removed", ID: c.ID})
	}
	if err := g.docker.RemoveNetwork(ctx, stackNetwork(name)); err != nil && !docker.IsNotFound(err) {
		return results, fmt.Errorf("remove network: %w", err)
	}
	if volumes {
		vols, err := g.docker.ListVolumes(ctx)
		if err != nil {
			return results, err
		}
		for _, v := range vols {
			if v.Labels[LabelStack] == name {
				if err := g.docker.RemoveVolume(ctx, v.Name, false); err != nil {
					return results, fmt.Errorf("remove volume %s: %w", v.Name, err)
				}
				results = append(results, StackResult{Service: "volume:" + v.Name, Action: "removed"})
			}
		}
	}
	return results, nil
}

// specHash identifies a service definition together with the exact image,
// so redeploying an unchanged stack leaves running containers alone while a
// new image or config recreates them.
func (g *Gate) specHash(s *ServiceSpec, imageID string) string {
	b, _ := json.Marshal(struct {
		S  ContainerSpec
		ID string
	}{s.ContainerSpec, imageID})
	return g.specMAC(b)
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
