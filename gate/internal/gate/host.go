package gate

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// HostInfo is a lightweight snapshot of the host, read from /proc without
// any privileges.
type HostInfo struct {
	Hostname  string     `json:"hostname"`
	OS        string     `json:"os"`
	Kernel    string     `json:"kernel"`
	Arch      string     `json:"arch"`
	CPUs      int        `json:"cpus"`
	Uptime    float64    `json:"uptime"`
	Load      [3]float64 `json:"load"`
	MemTotal  uint64     `json:"memTotal"`
	MemAvail  uint64     `json:"memAvailable"`
	SwapTotal uint64     `json:"swapTotal"`
	SwapFree  uint64     `json:"swapFree"`
	Disks     []DiskInfo `json:"disks"`
}

// DiskInfo is filesystem usage for a path.
type DiskInfo struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

func hostInfo() HostInfo {
	h := HostInfo{CPUs: runtime.NumCPU(), Arch: runtime.GOARCH, Disks: []DiskInfo{}}
	h.Hostname, _ = os.Hostname()
	var u syscall.Utsname
	if syscall.Uname(&u) == nil {
		h.Kernel = utsString(u.Release[:])
	}
	if f, err := os.Open("/etc/os-release"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
				h.OS = strings.Trim(v, `"`)
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			h.Uptime, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			h.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				h.MemTotal = kb * 1024
			case "MemAvailable:":
				h.MemAvail = kb * 1024
			case "SwapTotal:":
				h.SwapTotal = kb * 1024
			case "SwapFree:":
				h.SwapFree = kb * 1024
			}
		}
		f.Close()
	}
	for _, p := range []string{"/", "/var/lib/docker"} {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) == nil {
			d := DiskInfo{Path: p, Total: st.Blocks * uint64(st.Bsize), Free: st.Bavail * uint64(st.Bsize)}
			if len(h.Disks) > 0 && h.Disks[0].Total == d.Total && h.Disks[0].Free == d.Free {
				continue // same filesystem
			}
			h.Disks = append(h.Disks, d)
		}
	}
	return h
}

func utsString[T int8 | uint8](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
