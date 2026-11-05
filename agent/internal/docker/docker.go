// Package docker is a deliberately small Docker Engine API client that talks
// to the local daemon over its unix socket. It has no third-party
// dependencies so that the only code with access to the Docker socket is code
// in this repository and the Go standard library.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Client talks to the Docker Engine API.
type Client struct {
	http *http.Client
}

// New returns a client for the daemon listening on socketPath.
func New(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{http: &http.Client{Transport: tr}}
}

// APIError is a non-2xx response from the daemon.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("docker: %s (HTTP %d)", e.Message, e.Status) }

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

var refPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,127}$`)
var imagePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.\-/:@]{0,254}$`)

// ValidRef reports whether s is a safe container/image/network identifier.
func ValidRef(s string) bool { return refPattern.MatchString(s) }

// ValidImage reports whether s is a safe image reference.
func ValidImage(s string) bool { return imagePattern.MatchString(s) }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &m) != nil || m.Message == "" {
			m.Message = string(bytes.TrimSpace(b))
		}
		return nil, &APIError{Status: resp.StatusCode, Message: m.Message}
	}
	return resp, nil
}

func (c *Client) json(ctx context.Context, method, path string, q url.Values, body, out any) error {
	resp, err := c.do(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

// Raw performs a request and decodes the JSON result into a generic value.
func (c *Client) Raw(ctx context.Context, method, path string, q url.Values, body any) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.json(ctx, method, path, q, body, &out)
	return out, err
}

// ContainerSummary is the subset of /containers/json we expose.
type ContainerSummary struct {
	ID       string            `json:"id"`
	Names    []string          `json:"names"`
	Image    string            `json:"image"`
	ImageID  string            `json:"imageId"`
	Command  string            `json:"command"`
	Created  int64             `json:"created"`
	State    string            `json:"state"`
	Status   string            `json:"status"`
	Labels   map[string]string `json:"labels"`
	Ports    []Port            `json:"ports"`
	Networks []string          `json:"networks"`
}

// Port is a published port.
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

// ListContainers lists containers.
func (c *Client) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		ImageID string            `json:"ImageID"`
		Command string            `json:"Command"`
		Created int64             `json:"Created"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	if err := c.json(ctx, http.MethodGet, "/containers/json", q, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ContainerSummary, 0, len(raw))
	for _, r := range raw {
		s := ContainerSummary{
			ID: r.ID, Names: r.Names, Image: r.Image, ImageID: r.ImageID, Command: r.Command,
			Created: r.Created, State: r.State, Status: r.Status, Labels: r.Labels,
			Ports: []Port{}, Networks: []string{},
		}
		for _, p := range r.Ports {
			s.Ports = append(s.Ports, Port{IP: p.IP, PrivatePort: p.PrivatePort, PublicPort: p.PublicPort, Type: p.Type})
		}
		for n := range r.NetworkSettings.Networks {
			s.Networks = append(s.Networks, n)
		}
		out = append(out, s)
	}
	return out, nil
}

// InspectContainer returns the raw inspect document.
func (c *Client) InspectContainer(ctx context.Context, id string) (json.RawMessage, error) {
	return c.Raw(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil)
}

// ContainerLabels returns a container's labels and whether it uses a TTY.
func (c *Client) ContainerLabels(ctx context.Context, id string) (map[string]string, bool, error) {
	var v struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
			Tty    bool              `json:"Tty"`
		} `json:"Config"`
	}
	if err := c.json(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil, nil, &v); err != nil {
		return nil, false, err
	}
	return v.Config.Labels, v.Config.Tty, nil
}

// Start starts a container.
func (c *Client) Start(ctx context.Context, id string) error {
	return c.json(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// Stop stops a container.
func (c *Client) Stop(ctx context.Context, id string, timeout int) error {
	q := url.Values{}
	if timeout > 0 {
		q.Set("t", strconv.Itoa(timeout))
	}
	return c.json(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop", q, nil, nil)
}

// Restart restarts a container.
func (c *Client) Restart(ctx context.Context, id string, timeout int) error {
	q := url.Values{}
	if timeout > 0 {
		q.Set("t", strconv.Itoa(timeout))
	}
	return c.json(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/restart", q, nil, nil)
}

// Remove removes a container.
func (c *Client) Remove(ctx context.Context, id string, force, volumes bool) error {
	q := url.Values{}
	q.Set("force", strconv.FormatBool(force))
	q.Set("v", strconv.FormatBool(volumes))
	return c.json(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), q, nil, nil)
}

// LogLine is one line of container output.
type LogLine struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// Logs returns the last tail lines of a container's logs.
func (c *Client) Logs(ctx context.Context, id string, tail int, since int64, tty bool) ([]LogLine, error) {
	q := url.Values{}
	q.Set("stdout", "1")
	q.Set("stderr", "1")
	q.Set("timestamps", "1")
	q.Set("tail", strconv.Itoa(tail))
	if since > 0 {
		q.Set("since", strconv.FormatInt(since, 10))
	}
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs", q, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 16<<20)
	lines := []LogLine{}
	if tty {
		sc := bufio.NewScanner(body)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			lines = append(lines, LogLine{Stream: "stdout", Text: sc.Text()})
		}
		return lines, sc.Err()
	}
	// Multiplexed stream: 8-byte header [stream, 0, 0, 0, size(be32)] then payload.
	hdr := make([]byte, 8)
	partial := map[string]string{}
	for {
		if _, err := io.ReadFull(body, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				break
			}
			return nil, err
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > 4<<20 {
			return nil, errors.New("docker: log frame too large")
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(body, buf); err != nil {
			return nil, err
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		text := partial[stream] + string(buf)
		for {
			i := bytes.IndexByte([]byte(text), '\n')
			if i < 0 {
				break
			}
			lines = append(lines, LogLine{Stream: stream, Text: text[:i]})
			text = text[i+1:]
		}
		partial[stream] = text
	}
	for s, t := range partial {
		if t != "" {
			lines = append(lines, LogLine{Stream: s, Text: t})
		}
	}
	return lines, nil
}

// Stats returns a one-shot stats sample.
func (c *Client) Stats(ctx context.Context, id string) (json.RawMessage, error) {
	q := url.Values{}
	q.Set("stream", "false")
	return c.Raw(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/stats", q, nil)
}

// Pull pulls an image and returns once the pull has finished.
func (c *Client) Pull(ctx context.Context, image string) error {
	q := url.Values{}
	q.Set("fromImage", image)
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msg.Error != "" {
			return &APIError{Status: 500, Message: msg.Error}
		}
	}
}

// CreateContainer creates a container and returns its ID.
func (c *Client) CreateContainer(ctx context.Context, name string, spec any) (string, error) {
	q := url.Values{}
	if name != "" {
		q.Set("name", name)
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := c.json(ctx, http.MethodPost, "/containers/create", q, spec, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// ImageSummary is the subset of /images/json we expose.
type ImageSummary struct {
	ID       string   `json:"id"`
	RepoTags []string `json:"repoTags"`
	Created  int64    `json:"created"`
	Size     int64    `json:"size"`
}

// ListImages lists images.
func (c *Client) ListImages(ctx context.Context) ([]ImageSummary, error) {
	var raw []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Created  int64    `json:"Created"`
		Size     int64    `json:"Size"`
	}
	if err := c.json(ctx, http.MethodGet, "/images/json", nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]ImageSummary, 0, len(raw))
	for _, r := range raw {
		tags := r.RepoTags
		if tags == nil {
			tags = []string{}
		}
		out = append(out, ImageSummary{ID: r.ID, RepoTags: tags, Created: r.Created, Size: r.Size})
	}
	return out, nil
}

// RemoveImage removes an image.
func (c *Client) RemoveImage(ctx context.Context, id string, force bool) error {
	q := url.Values{}
	q.Set("force", strconv.FormatBool(force))
	return c.json(ctx, http.MethodDelete, "/images/"+url.PathEscape(id), q, nil, nil)
}

// NetworkSummary is the subset of /networks we expose.
type NetworkSummary struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

// ListNetworks lists networks.
func (c *Client) ListNetworks(ctx context.Context) ([]NetworkSummary, error) {
	var raw []struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Driver string `json:"Driver"`
		Scope  string `json:"Scope"`
	}
	if err := c.json(ctx, http.MethodGet, "/networks", nil, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]NetworkSummary, 0, len(raw))
	for _, r := range raw {
		out = append(out, NetworkSummary(r))
	}
	return out, nil
}

// Info is the subset of /info we expose.
type Info struct {
	Name              string `json:"name"`
	ServerVersion     string `json:"serverVersion"`
	OperatingSystem   string `json:"operatingSystem"`
	KernelVersion     string `json:"kernelVersion"`
	Architecture      string `json:"architecture"`
	NCPU              int    `json:"ncpu"`
	MemTotal          int64  `json:"memTotal"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containersRunning"`
	ContainersStopped int    `json:"containersStopped"`
	Images            int    `json:"images"`
}

// Info returns daemon and host information.
func (c *Client) Info(ctx context.Context) (*Info, error) {
	var raw struct {
		Name              string `json:"Name"`
		ServerVersion     string `json:"ServerVersion"`
		OperatingSystem   string `json:"OperatingSystem"`
		KernelVersion     string `json:"KernelVersion"`
		Architecture      string `json:"Architecture"`
		NCPU              int    `json:"NCPU"`
		MemTotal          int64  `json:"MemTotal"`
		Containers        int    `json:"Containers"`
		ContainersRunning int    `json:"ContainersRunning"`
		ContainersStopped int    `json:"ContainersStopped"`
		Images            int    `json:"Images"`
	}
	if err := c.json(ctx, http.MethodGet, "/info", nil, nil, &raw); err != nil {
		return nil, err
	}
	i := Info(raw)
	return &i, nil
}
