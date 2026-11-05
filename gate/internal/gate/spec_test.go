package gate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

func code(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	if err == nil {
		return ""
	}
	return "other"
}

func TestBindMountPolicy(t *testing.T) {
	root := t.TempDir()
	apps := filepath.Join(root, "srv")
	os.MkdirAll(filepath.Join(apps, "app"), 0o755)
	// A container that can write to /srv could plant a symlink to escape.
	os.Symlink("/", filepath.Join(apps, "evil"))
	pol := Policy{Containers: ContainerPolicy{BindMountPrefixes: []string{apps}}}.withDefaults().Containers

	cases := map[string]struct {
		src  string
		want string
	}{
		"inside prefix":           {filepath.Join(apps, "app"), ""},
		"not yet existing":        {filepath.Join(apps, "new", "dir"), ""},
		"symlink escape":          {filepath.Join(apps, "evil", "etc"), protocol.CodeForbidden},
		"dotdot escape":           {filepath.Join(apps, "..", "etc"), protocol.CodeForbidden},
		"prefix lookalike":        {apps + "-other", protocol.CodeForbidden},
		"docker socket":           {"/var/run/docker.sock", protocol.CodeForbidden},
		"relative":                {"srv/app", protocol.CodeBadRequest},
		"symlink inside new path": {filepath.Join(apps, "evil"), protocol.CodeForbidden},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := ContainerSpec{Image: "alpine", Mounts: []Mount{{Type: "bind", Source: c.src, Target: "/data"}}}
			if got := code(s.validate(pol)); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestSpecValidation(t *testing.T) {
	pol := Policy{}.withDefaults().Containers
	ok := []ContainerSpec{
		{Image: "nginx:1.27-alpine", Name: "web", Env: []string{"A=1", "B="}, Restart: "unless-stopped", Networks: []string{"nodescale"}, CapAdd: []string{"cap_net_bind_service"}},
		{Image: "ghcr.io/org/app@sha256:" + "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", Mounts: []Mount{{Type: "volume", Source: "data", Target: "/data"}, {Type: "tmpfs", Target: "/tmp"}}},
	}
	for i, s := range ok {
		if err := s.validate(pol); err != nil {
			t.Fatalf("spec %d: %v", i, err)
		}
	}
	badSpecs := map[string]ContainerSpec{
		"image":        {Image: "nginx;rm -rf /"},
		"env":          {Image: "a", Env: []string{"NOVALUE"}},
		"label":        {Image: "a", Labels: map[string]string{"io.nodescale.stack": "x"}},
		"restart":      {Image: "a", Restart: "sometimes"},
		"netmode+nets": {Image: "a", NetworkMode: "none", Networks: []string{"x"}},
		"target":       {Image: "a", Mounts: []Mount{{Type: "volume", Source: "v", Target: "/"}}},
		"memory":       {Image: "a", Memory: 1024},
		"pidmode":      {Image: "a", PidMode: "container:x"},
	}
	for name, s := range badSpecs {
		if code(s.validate(pol)) != protocol.CodeBadRequest {
			t.Errorf("%s: expected bad_request, got %v", name, s.validate(pol))
		}
	}
	allow := Policy{Containers: ContainerPolicy{AllowPrivileged: true, AllowHostNamespaces: true, AllowPublishedPorts: true, AllowDevices: true}}.withDefaults().Containers
	s := ContainerSpec{Image: "a", Privileged: true, NetworkMode: "host", Ports: []PortSpec{{ContainerPort: 80}}, Devices: []string{"/dev/fuse"}}
	if err := s.validate(allow); err != nil {
		t.Fatalf("permissive policy rejected spec: %v", err)
	}
	body := s.dockerBody(nil)
	host := body["HostConfig"].(map[string]any)
	if host["Privileged"] != true || host["NetworkMode"] != "host" {
		t.Fatalf("unexpected host config %v", host)
	}
	pb := host["PortBindings"].(map[string][]map[string]string)
	if pb["80/tcp"][0]["HostIp"] != "127.0.0.1" {
		t.Fatal("published ports must default to loopback")
	}
}
