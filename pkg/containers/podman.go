package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	defaultPodmanSockets = []string{
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock",
	}
)

// PodmanRuntime implements Runtime for Podman using REST API
// It can manage multiple sockets (root + user sockets)
type PodmanRuntime struct {
	sockets []string
	clients map[string]*http.Client
}

// NewPodmanRuntime creates a new Podman runtime client
func NewPodmanRuntime(socketPath string) *PodmanRuntime {
	var sockets []string

	if socketPath != "" {
		sockets = append(sockets, socketPath)
	} else {
		// Check root sockets
		for _, path := range defaultPodmanSockets {
			if _, err := os.Stat(path); err == nil {
				sockets = append(sockets, path)
				break // Only need one root socket
			}
		}

		// Scan for user sockets in /run/user/*/podman/podman.sock
		userSockets := findUserPodmanSockets()
		sockets = append(sockets, userSockets...)
	}

	return &PodmanRuntime{
		sockets: sockets,
		clients: make(map[string]*http.Client),
	}
}

// findUserPodmanSockets scans /run/user/ for Podman sockets
func findUserPodmanSockets() []string {
	var sockets []string

	entries, err := os.ReadDir("/run/user")
	if err != nil {
		return sockets
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		socketPath := fmt.Sprintf("/run/user/%s/podman/podman.sock", entry.Name())
		if _, err := os.Stat(socketPath); err == nil {
			sockets = append(sockets, socketPath)
		}
	}

	return sockets
}

// Name returns the runtime name
func (p *PodmanRuntime) Name() string {
	return "podman"
}

// Available checks if Podman is available
func (p *PodmanRuntime) Available() bool {
	return len(p.sockets) > 0
}

// getClient returns an HTTP client for the given socket
func (p *PodmanRuntime) getClient(socketPath string) *http.Client {
	if client, ok := p.clients[socketPath]; ok {
		return client
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
	p.clients[socketPath] = client
	return client
}

// podmanContainer represents a container from Podman's API
type podmanContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	Labels map[string]string `json:"Labels"`
	State  string            `json:"State"`
}

// podmanInspect represents the inspect response
type podmanInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Pid int32 `json:"Pid"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Image string `json:"Image"`
}

// podmanTop represents the top response
type podmanTop struct {
	Titles    []string   `json:"Titles"`
	Processes [][]string `json:"Processes"`
}

// ListContainers returns all running Podman containers from all sockets
func (p *PodmanRuntime) ListContainers() ([]*ContainerInfo, error) {
	var result []*ContainerInfo
	seenIDs := make(map[string]bool)

	for _, socketPath := range p.sockets {
		containers, err := p.listContainersFromSocket(socketPath)
		if err != nil {
			continue // Try other sockets
		}
		for _, c := range containers {
			if !seenIDs[c.ID] {
				seenIDs[c.ID] = true
				result = append(result, c)
			}
		}
	}

	return result, nil
}

// listContainersFromSocket lists containers from a specific socket
func (p *PodmanRuntime) listContainersFromSocket(socketPath string) ([]*ContainerInfo, error) {
	client := p.getClient(socketPath)

	resp, err := client.Get("http://podman/v4.0.0/libpod/containers/json?all=false")
	if err != nil {
		return nil, fmt.Errorf("failed to list Podman containers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Podman returned status %d", resp.StatusCode)
	}

	var containers []podmanContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("failed to decode Podman response: %w", err)
	}

	var result []*ContainerInfo
	for _, c := range containers {
		if c.State != "running" {
			continue
		}

		info, err := p.getContainerInfoFromSocket(socketPath, c.ID)
		if err != nil {
			continue
		}
		result = append(result, info)
	}

	return result, nil
}

// GetContainerByPID returns container info for a given PID
func (p *PodmanRuntime) GetContainerByPID(pid int32) (*ContainerInfo, error) {
	containers, err := p.ListContainers()
	if err != nil {
		return nil, err
	}

	for _, container := range containers {
		for _, containerPid := range container.PIDs {
			if containerPid == pid {
				return container, nil
			}
		}
	}

	return nil, nil
}

// getContainerInfoFromSocket fetches detailed info for a container from a specific socket
func (p *PodmanRuntime) getContainerInfoFromSocket(socketPath, containerID string) (*ContainerInfo, error) {
	client := p.getClient(socketPath)

	resp, err := client.Get(fmt.Sprintf("http://podman/v4.0.0/libpod/containers/%s/json", containerID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Podman returned status %d", resp.StatusCode)
	}

	var inspect podmanInspect
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		return nil, err
	}

	// For Podman, we use the main PID from inspect (State.Pid) which is the host PID
	// The top command returns namespace PIDs which don't match host PIDs
	pids := []int32{inspect.State.Pid}

	// Container ID (first 12 chars)
	id := containerID
	if len(id) > 12 {
		id = id[:12]
	}

	// Get container name (remove leading /)
	name := strings.TrimPrefix(inspect.Name, "/")

	return &ContainerInfo{
		ID:      id,
		Name:    name,
		Image:   inspect.Image,
		Runtime: "podman",
		Labels:  inspect.Config.Labels,
		PIDs:    pids,
	}, nil
}

// getContainerPIDsFromSocket returns all PIDs for a container from a specific socket
func (p *PodmanRuntime) getContainerPIDsFromSocket(socketPath, containerID string) ([]int32, error) {
	client := p.getClient(socketPath)

	resp, err := client.Get(fmt.Sprintf("http://podman/v4.0.0/libpod/containers/%s/top", containerID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Podman returned status %d", resp.StatusCode)
	}

	var top podmanTop
	if err := json.NewDecoder(resp.Body).Decode(&top); err != nil {
		return nil, err
	}

	// Find PID column
	pidCol := -1
	for i, title := range top.Titles {
		if title == "PID" {
			pidCol = i
			break
		}
	}
	if pidCol == -1 {
		return nil, fmt.Errorf("PID column not found")
	}

	var pids []int32
	for _, proc := range top.Processes {
		if pidCol < len(proc) {
			pid, err := strconv.ParseInt(proc[pidCol], 10, 32)
			if err == nil {
				pids = append(pids, int32(pid))
			}
		}
	}

	return pids, nil
}

// Close is a no-op for Podman
func (p *PodmanRuntime) Close() error {
	return nil
}
