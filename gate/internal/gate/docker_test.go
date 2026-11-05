package gate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evandn/nodescale/gate/internal/docker"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

// These tests run against a real Docker daemon when one is available
// (DOCKER_SOCKET or /var/run/docker.sock). Set NODESCALE_TEST_IMAGE to use a
// different small image that has /bin/sh.
func dockerGate(t *testing.T) (*Gate, context.Context) {
	t.Helper()
	sock := os.Getenv("DOCKER_SOCKET")
	if sock == "" {
		sock = "/var/run/docker.sock"
	}
	c := docker.New(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	if _, err := c.Info(ctx); err != nil {
		t.Skipf("docker not available: %v", err)
	}
	h := newHarness(t)
	h.a.docker = c
	return h.a, ctx
}

func testImage() string {
	if v := os.Getenv("NODESCALE_TEST_IMAGE"); v != "" {
		return v
	}
	return "alpine:3.20"
}

func TestStackLifecycle(t *testing.T) {
	g, ctx := dockerGate(t)
	name := "nstest" + strings.ToLower(time.Now().Format("150405"))
	t.Cleanup(func() { g.removeStack(context.Background(), name, true) })

	spec := func(env string, services ...string) StackSpec {
		st := StackSpec{Name: name, Volumes: []string{name + "_data"}}
		for _, s := range services {
			st.Services = append(st.Services, ServiceSpec{Service: s, ContainerSpec: ContainerSpec{
				Image: testImage(), Cmd: []string{"sleep", "300"}, Env: []string{"MODE=" + env},
				Mounts: []Mount{{Type: "volume", Source: name + "_data", Target: "/data"}},
			}})
		}
		return st
	}
	actions := func(rs []StackResult) map[string]string {
		m := map[string]string{}
		for _, r := range rs {
			m[r.Service] = r.Action
		}
		return m
	}

	r, err := g.deployStack(ctx, spec("a", "web", "worker"))
	if err != nil {
		t.Fatal(err)
	}
	if a := actions(r); a["web"] != "created" || a["worker"] != "created" {
		t.Fatalf("first deploy: %v", a)
	}
	r, err = g.deployStack(ctx, spec("a", "web", "worker"))
	if err != nil {
		t.Fatal(err)
	}
	if a := actions(r); a["web"] != "unchanged" || a["worker"] != "unchanged" {
		t.Fatalf("redeploy should be a no-op: %v", a)
	}
	r, err = g.deployStack(ctx, spec("b", "web"))
	if err != nil {
		t.Fatal(err)
	}
	if a := actions(r); a["web"] != "recreated" || a["worker"] != "removed" {
		t.Fatalf("update: %v", a)
	}

	// Services reach each other by name on the stack network, and exec works.
	res, err := g.docker.Exec(ctx, name+"-web", []string{"sh", "-c", "echo $MODE; echo oops >&2; exit 3"}, "", "", nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 3 || len(res.Output) != 2 || res.Output[0].Text != "b" {
		t.Fatalf("exec result: %+v", res)
	}

	// Inspect redacts env; containers.env reveals it.
	raw, err := g.dispatch(ctx, &Verified{Req: reqFor("containers.inspect", map[string]string{"id": name + "-web"})})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(raw)
	if !strings.Contains(string(b), "MODE=[redacted]") {
		t.Fatalf("inspect must redact env: %s", b)
	}
	envRes, err := g.dispatch(ctx, &Verified{Req: reqFor("containers.env", map[string]string{"id": name + "-web"})})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(envRes)
	if !strings.Contains(string(b), "MODE=b") {
		t.Fatalf("containers.env should reveal env: %s", b)
	}

	r, err = g.removeStack(ctx, name, true)
	if err != nil {
		t.Fatal(err)
	}
	if a := actions(r); a["web"] != "removed" || a["volume:"+name+"_data"] != "removed" {
		t.Fatalf("remove: %v", a)
	}
}

func TestCreateRespectsPolicy(t *testing.T) {
	g, ctx := dockerGate(t)
	dir := t.TempDir()
	g.cfg.Policy.Containers.BindMountPrefixes = []string{dir}
	os.Symlink("/etc", filepath.Join(dir, "etc"))
	_, err := g.dispatch(ctx, &Verified{Req: reqFor("containers.create", ContainerSpec{Image: testImage(), Mounts: []Mount{{Type: "bind", Source: filepath.Join(dir, "etc"), Target: "/x"}}})})
	if code(err) != "forbidden" {
		t.Fatalf("symlinked bind escaping the prefix must be refused, got %v", err)
	}
}

func reqFor(op string, args any) *protocol.Request {
	b, _ := json.Marshal(args)
	return &protocol.Request{Op: op, Args: b}
}
