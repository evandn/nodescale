package gate

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/evandn/nodescale/gate/internal/docker"
)

// fakeDocker is a minimal in-process Docker Engine API on a unix socket. It
// never touches a real daemon.
type fakeDocker struct {
	mu         sync.Mutex
	events     []string
	containers []map[string]any          // GET /containers/json
	inspect    map[string]map[string]any // GET /containers/{id}/json
}

func newFakeDocker(t *testing.T, g *Gate) *fakeDocker {
	t.Helper()
	dir, err := os.MkdirTemp("", "fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDocker{inspect: map[string]map[string]any{}}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	g.docker = docker.New(sock)
	return f
}

func (f *fakeDocker) log(e string) {
	f.mu.Lock()
	f.events = append(f.events, e)
	f.mu.Unlock()
}

func (f *fakeDocker) index(e string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, x := range f.events {
		if x == e {
			return i
		}
	}
	return -1
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeDocker) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case r.Method == "GET" && p == "/containers/json":
		f.mu.Lock()
		out := f.containers
		f.mu.Unlock()
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, 200, out)
	case r.Method == "GET" && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
		f.mu.Lock()
		doc, ok := f.inspect[id]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "No such container: " + id})
			return
		}
		writeJSON(w, 200, doc)
	case r.Method == "GET" && strings.HasPrefix(p, "/networks/"):
		writeJSON(w, 200, map[string]any{"Name": strings.TrimPrefix(p, "/networks/")})
	case r.Method == "GET" && strings.HasPrefix(p, "/images/"):
		writeJSON(w, 200, map[string]any{"Id": "sha256:fakeimage"})
	case r.Method == "POST" && p == "/containers/create":
		name := r.URL.Query().Get("name")
		f.log("create " + name)
		writeJSON(w, 201, map[string]any{"Id": "new-" + name})
	case r.Method == "POST" && strings.HasPrefix(p, "/networks/") && strings.HasSuffix(p, "/connect"):
		writeJSON(w, 200, map[string]any{})
	case r.Method == "POST" && strings.HasPrefix(p, "/containers/"):
		parts := strings.Split(strings.TrimPrefix(p, "/containers/"), "/")
		f.log(parts[1] + " " + parts[0])
		if parts[1] == "exec" {
			// Reaching Docker at all means the policy let the exec through.
			writeJSON(w, 500, map[string]string{"message": "fake daemon: exec reached docker"})
			return
		}
		w.WriteHeader(204)
	case r.Method == "DELETE" && strings.HasPrefix(p, "/containers/"):
		f.log("remove " + strings.TrimPrefix(p, "/containers/"))
		w.WriteHeader(204)
	default:
		writeJSON(w, 404, map[string]string{"message": "fake daemon: unhandled " + r.Method + " " + p})
	}
}
