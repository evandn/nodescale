package gate

// Regression tests for security review findings (stack bind overlap, policy
// on existing containers, policy preserved across config saves, audit log
// integrity, parser differentials). None of them talks to a real Docker
// daemon; see fakedocker_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evandn/nodescale/gate/internal/protocol"
)

// F1: stacks.deploy excludes ALL of the stack's existing containers from the
// bind-overlap check, but containers of removed services (and of services
// recreated later in the list) keep running while new containers start. A
// running container with a rw bind of X can then swap a symlink at X/Y just
// before Docker resolves a new sibling bind of X/Y.
func TestReviewStackOverlapWithContainersStillRunning(t *testing.T) {
	cases := map[string]struct {
		oldService string
		services   func(dir string) []ServiceSpec
		newStart   string
	}{
		"removed service": {
			oldService: "old",
			services: func(dir string) []ServiceSpec {
				return []ServiceSpec{{Service: "new", ContainerSpec: ContainerSpec{Image: "alpine",
					Mounts: []Mount{{Type: "bind", Source: filepath.Join(dir, "x", "y"), Target: "/y"}}}}}
			},
			newStart: "start new-shop-new",
		},
		"service recreated later in the list": {
			oldService: "a",
			services: func(dir string) []ServiceSpec {
				return []ServiceSpec{
					{Service: "b", ContainerSpec: ContainerSpec{Image: "alpine", Mounts: []Mount{{Type: "bind", Source: filepath.Join(dir, "x", "y"), Target: "/y"}}}},
					{Service: "a", ContainerSpec: ContainerSpec{Image: "alpine", Mounts: []Mount{{Type: "bind", Source: filepath.Join(dir, "z"), Target: "/z"}}}},
				}
			},
			newStart: "start new-shop-b",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			dir, _ := filepath.EvalSymlinks(t.TempDir())
			os.MkdirAll(filepath.Join(dir, "x"), 0o755)
			h.a.cfg.Policy.Containers.BindMountPrefixes = []string{dir}
			fd := newFakeDocker(t, h.a)
			old := map[string]any{
				"Id": "old1", "Names": []string{"/shop-" + c.oldService}, "State": "running",
				"Labels": map[string]string{LabelStack: "shop", LabelService: c.oldService, LabelHash: "stale"},
				"Mounts": []map[string]any{{"Type": "bind", "Source": filepath.Join(dir, "x")}},
			}
			fd.containers = []map[string]any{old}

			_, err := h.a.deployStack(context.Background(), StackSpec{Name: "shop", Services: c.services(dir)})
			if code(err) == protocol.CodeForbidden {
				return // refused: fine
			}
			if err != nil {
				t.Fatalf("deploy: %v", err)
			}
			started, removed := fd.index(c.newStart), fd.index("remove old1")
			if started >= 0 && (removed < 0 || removed > started) {
				t.Fatalf("container binding x/y was started while old1 (rw bind of x) was still running; events: %v", fd.events)
			}
		})
	}
}

// F2: existingPolicy misses several host-escape settings of containers created
// outside nodescale, so containers.exec/start/restart/update are allowed on them.
func TestReviewExistingPolicyIncomplete(t *testing.T) {
	cases := map[string]map[string]any{
		// mknod of the host disk with the default CAP_MKNOD.
		"device cgroup rules": {"DeviceCgroupRules": []string{"b *:* rwm"}},
		// /proc/sys and /proc/sysrq-trigger writable (core_pattern => host root).
		"unmasked /proc": {"MaskedPaths": []string{}, "ReadonlyPaths": []string{}},
		// Joins the PID namespace of a host-PID container.
		"pid of host-pid container": {"PidMode": "container:hostpid"},
	}
	for name, hc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			fd := newFakeDocker(t, h.a)
			fd.inspect["victim"] = map[string]any{"Name": "/victim", "HostConfig": hc}
			fd.inspect["hostpid"] = map[string]any{"Name": "/hostpid", "HostConfig": map[string]any{"PidMode": "host"}}
			_, err := h.a.dispatch(context.Background(), &Verified{Req: reqFor("containers.exec", map[string]any{"id": "victim", "cmd": []string{"id"}})})
			if code(err) != protocol.CodeForbidden {
				t.Fatalf("exec into container with %v must be forbidden, got %v", hc, err)
			}
		})
	}
}

// F3: signers.add/remove rewrite gate.json with omitempty, so a root-set empty
// policy list ("no session scopes", "no extra capabilities", "no bind mounts")
// is dropped and silently reverts to the permissive defaults.
func TestReviewConfigSaveWidensPolicy(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(h.dir, "agent.json")
	b, _ := os.ReadFile(path)
	var raw map[string]any
	json.Unmarshal(b, &raw)
	raw["policy"] = map[string]any{
		"allowSessionScopes": []string{},
		"containers":         map[string]any{"allowedCapabilities": []string{}, "bindMountPrefixes": []string{}},
	}
	b, _ = json.Marshal(raw)
	os.WriteFile(path, b, 0o600)
	h.reload()

	s := h.session(h.admin, protocol.ScopeRead)
	expectErr(t, h.call(s.sign(h.payload("signers.list", nil))), protocol.CodeForbidden, "not allowed")

	// A routine admin action over the wire...
	expectOK(t, h.call(h.webauthn(h.admin, h.payload("signers.add", newPasskey(t, protocol.AlgEdDSA).signer(RoleViewer)), assertOpts{})))
	h.reload()

	pol := h.a.cfg.Policy.withDefaults()
	if len(pol.AllowSessionScopes) != 0 || len(pol.Containers.AllowedCapabilities) != 0 || len(pol.Containers.BindMountPrefixes) != 0 {
		t.Errorf("root-only policy widened by signers.add: scopes=%v caps=%v binds=%v",
			pol.AllowSessionScopes, pol.Containers.AllowedCapabilities, pol.Containers.BindMountPrefixes)
	}
	r := h.call(h.session(h.admin, protocol.ScopeRead).sign(h.payload("signers.list", nil)))
	if r.Ok {
		t.Error("session keys were disabled by root but are accepted after signers.add")
	}
}

// F4a: failed read-level requests are audited with their full args (up to
// ~512 KiB, x6 after JSON HTML-escaping). One viewer request pushes every
// earlier entry out of audit.read's 512 KiB window.
func TestReviewAuditReadBlindedByViewer(t *testing.T) {
	viewer := newPasskey(t, protocol.AlgES256)
	h := newHarness(t, viewer.signer(RoleViewer))
	expectOK(t, h.call(h.webauthn(h.admin, h.payload("signers.add", newPasskey(t, protocol.AlgEdDSA).signer(RoleAdmin)), assertOpts{})))

	s := h.session(viewer, protocol.ScopeRead)
	r := h.call(s.sign(rawPayload(h, "containers.inspect", map[string]string{"id": strings.Repeat("<", 400_000)})))
	expectErr(t, r, protocol.CodeBadRequest, "not a valid identifier")

	r = h.call(h.webauthn(h.admin, h.payload("audit.read", map[string]int{"lines": 1000}), assertOpts{}))
	expectOK(t, r)
	if !strings.Contains(string(r.Result), `"op":"signers.add"`) {
		t.Fatalf("audit.read no longer shows the admin's signers.add after one viewer request (%d bytes returned)", len(r.Result))
	}
}

// F4b: with one rotation generation and no per-entry cap, a viewer's read
// session erases the whole audit history in ~20 automated requests.
func TestReviewAuditHistoryFlushedByViewer(t *testing.T) {
	viewer := newPasskey(t, protocol.AlgES256)
	h := newHarness(t, viewer.signer(RoleViewer))
	expectOK(t, h.call(h.webauthn(h.admin, h.payload("signers.add", newPasskey(t, protocol.AlgEdDSA).signer(RoleAdmin)), assertOpts{})))
	s := h.session(viewer, protocol.ScopeRead)
	for i := 0; i < 20; i++ {
		expectErr(t, h.call(s.sign(rawPayload(h, "containers.inspect", map[string]string{"id": strings.Repeat("<", 400_000)}))), protocol.CodeBadRequest, "not a valid identifier")
	}
	a, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl"))
	b, _ := os.ReadFile(filepath.Join(h.dir, "audit.jsonl.1"))
	if !strings.Contains(string(a)+string(b), `"op":"signers.add"`) {
		t.Fatal("admin's signers.add entry was erased from audit.jsonl and audit.jsonl.1 by a viewer")
	}
}

// rawPayload is h.payload without HTML-escaping, as a JS client would send it
// ('<' stays one byte in the signed payload, ~400 KB < 512 KiB).
func rawPayload(h *harness, op string, args any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(args)
	var r protocol.Request
	json.Unmarshal(h.payload(op, nil), &r)
	r.Args = nil
	head, _ := json.Marshal(r)
	return append(append(append(head[:len(head)-1], `,"args":`...), bytes.TrimSpace(buf.Bytes())...), '}')
}

// F6: the strict decoder still accepts case-variant duplicate keys (last one
// wins, unlike JSON.parse) and trailing bytes after the signed object.
func TestReviewStrictDecodeParserDifferential(t *testing.T) {
	var r protocol.Request
	err := decodeStrict([]byte(`{"v":1,"typ":"nodescale.request","op":"containers.list","OP":"containers.remove"}`), &r)
	if err == nil {
		t.Errorf("case-variant duplicate key accepted: op=%q (JSON.parse sees containers.list)", r.Op)
	}
	var c protocol.SessionCert
	err = decodeStrict([]byte(`{"v":1,"typ":"nodescale.session","scope":"read","Scope":"operate"}`), &c)
	if err == nil {
		t.Errorf("session cert scope=%q accepted (JSON.parse sees read)", c.Scope)
	}
	if err := decodeStrict([]byte(`{"v":1} {"x":2}`), &r); err == nil {
		t.Error("trailing data after the payload object accepted")
	}
}
