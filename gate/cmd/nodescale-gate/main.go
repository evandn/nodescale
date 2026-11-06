// Command nodescale-gate is the login shell of the restricted "nodescale"
// user on every managed server. It is not a daemon: Tailscale SSH starts it
// once per request, it verifies the passkey signature, talks to the Docker
// Engine API on the local socket, prints a signed response and exits.
//
// Installed as root:docker mode 2755 (setgid docker) so it alone, and not the
// "nodescale" user, can reach /var/run/docker.sock and nodescale's state.
//
//	nodescale-gate [-c anything]   handle one request from stdin (login shell)
//	nodescale-gate init            (root) create the identity key, fix permissions
//	nodescale-gate id              (root) print the server identity
//	nodescale-gate check           (root) verify the installation
//	nodescale-gate version
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/evandn/nodescale/gate/internal/gate"
	"github.com/evandn/nodescale/gate/internal/protocol"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version":
			fmt.Println(gate.Version)
			return
		case "init", "id", "check":
			// Real UID: root running this setgid binary gains egid docker,
			// which is fine; anyone else is refused.
			if os.Getuid() != 0 {
				fmt.Fprintln(os.Stderr, "this command must be run as root")
				os.Exit(1)
			}
			os.Exit(admin(args[0]))
		}
	}
	// Anything else (no arguments, "-c <command>", "-l"…) is a login-shell
	// invocation. The command line is deliberately ignored.
	os.Exit(shell())
}

func shell() int {
	syscall.Umask(0o007)
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "This account only accepts signed nodescale requests. Interactive login is disabled.")
		return 1
	}
	req, err := io.ReadAll(io.LimitReader(os.Stdin, gate.MaxRequestBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "nodescale-gate: read:", err)
		return 2
	}
	if len(req) == 0 {
		// e.g. `su -l nodescale -c true` capability probes.
		return 0
	}
	g, err := gate.New(gate.Options{Paths: gate.ResolvePaths(), CreateIdentity: !gate.Privileged()})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nodescale-gate: not configured:", err)
		return 3
	}
	var out []byte
	if len(req) > gate.MaxRequestBytes {
		out = gate.UnsignedError("", protocol.Errorf(protocol.CodeBadRequest, "request too large"))
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 14*time.Minute)
		defer cancel()
		out = g.Handle(ctx, req)
	}
	_, _ = os.Stdout.Write(append(out, '\n'))
	return 0
}

func admin(cmd string) int {
	paths := gate.ResolvePaths()
	switch cmd {
	case "init":
		priv, err := gate.LoadIdentity(paths.Identity, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		fixPermissions(paths)
		printID(priv.Public())
		return 0
	case "id":
		priv, err := gate.LoadIdentity(paths.Identity, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, "id:", err)
			return 1
		}
		printID(priv.Public())
		return 0
	case "check":
		return check(paths)
	}
	return 2
}

func printID(pub crypto.PublicKey) {
	k := pub.(ed25519.PublicKey)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"agent": protocol.AgentID(k), "publicKey": protocol.B64(k)})
}

func dockerGID() (int, error) {
	g, err := user.LookupGroup("docker")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}

// fixPermissions makes state reachable only by root and the setgid gate.
func fixPermissions(p gate.Paths) {
	gid, err := dockerGID()
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: docker group not found:", err)
		return
	}
	for _, dir := range []string{filepath.Dir(p.Config), p.State, filepath.Join(p.State, "nonces")} {
		_ = os.MkdirAll(dir, 0o770)
		_ = os.Chown(dir, 0, gid)
		_ = os.Chmod(dir, 0o770|os.ModeSetgid)
	}
	// Files the gate created are owned by the nodescale user; the 2770
	// directories already make them unreachable, but normalise them to root
	// for defence in depth.
	for _, dir := range []string{filepath.Dir(p.Config), p.State} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return nil
			}
			mode := os.FileMode(0o660)
			if path == p.Identity {
				mode = 0o640
			}
			fixFile(path, gid, mode)
			return nil
		})
	}
}

// fixFile changes ownership and mode through a file descriptor opened with
// O_NOFOLLOW, so a symlink swapped in after the directory walk cannot
// redirect root's chown/chmod to another file.
func fixFile(path string, gid int, mode os.FileMode) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return
	}
	_ = f.Chown(0, gid)
	_ = f.Chmod(mode)
}

func check(p gate.Paths) int {
	failed := 0
	report := func(ok bool, what string, detail ...any) {
		mark := "ok  "
		if !ok {
			mark = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %s %s\n", mark, what, fmt.Sprint(detail...))
	}
	gid, err := dockerGID()
	report(err == nil, "docker group exists", err)

	self, _ := os.Executable()
	if st, err := os.Stat(self); err == nil {
		sys := st.Sys().(*syscall.Stat_t)
		report(st.Mode()&os.ModeSetgid != 0 && int(sys.Gid) == gid && sys.Uid == 0, "gate binary is root:docker setgid", self, " ", st.Mode())
		report(st.Mode().Perm()&0o022 == 0, "gate binary is not group/world writable")
	}

	u, err := user.Lookup("nodescale")
	report(err == nil, "user nodescale exists", err)
	if err == nil {
		gids, _ := u.GroupIds()
		inDocker := false
		for _, g := range gids {
			if g == strconv.Itoa(gid) {
				inDocker = true
			}
		}
		report(!inDocker, "user nodescale is not in the docker group")
	}

	for _, dir := range []string{filepath.Dir(p.Config), p.State} {
		st, err := os.Stat(dir)
		if err != nil {
			report(false, "directory", dir, ": ", err)
			continue
		}
		sys := st.Sys().(*syscall.Stat_t)
		report(sys.Uid == 0 && int(sys.Gid) == gid && st.Mode().Perm()&0o007 == 0, "directory ", dir, " is root:docker without access for others (", st.Mode(), ")")
	}
	for _, dir := range []string{filepath.Dir(p.Config), p.State} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || path == dir {
				return nil
			}
			st, err := os.Lstat(path)
			if err != nil {
				return nil
			}
			sys := st.Sys().(*syscall.Stat_t)
			if st.Mode()&os.ModeSymlink != 0 {
				report(false, "no symlinks in state directories: ", path)
			} else if st.Mode().Perm()&0o007 != 0 || int(sys.Gid) != gid {
				report(false, "file is group docker without access for others: ", path, " (", st.Mode(), ")")
			}
			return nil
		})
	}
	_, err = gate.LoadConfig(p.Config)
	report(err == nil, "configuration is valid ", p.Config, " ", err)
	priv, err := gate.LoadIdentity(p.Identity, false)
	report(err == nil, "identity key present", err)
	if err == nil {
		fmt.Println("       server identity:", protocol.AgentID(priv.Public().(ed25519.PublicKey)))
	}
	if st, err := os.Stat(p.Docker); err == nil {
		sys := st.Sys().(*syscall.Stat_t)
		report(int(sys.Gid) == gid && st.Mode().Perm()&0o006 == 0, "docker socket is group docker and not world accessible")
	} else {
		report(false, "docker socket", err)
	}
	if failed > 0 {
		fmt.Printf("%d check(s) failed\n", failed)
		return 1
	}
	fmt.Println("all checks passed")
	return 0
}
