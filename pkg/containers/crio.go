package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	defaultCrioSocket = "/var/run/crio/crio.sock"
)

// CrioRuntime implements Runtime for CRI-O
type CrioRuntime struct {
	socketPath string
	client     *http.Client
}

// NewCrioRuntime creates a new CRI-O runtime client
func NewCrioRuntime(socketPath string) *CrioRuntime {
	if socketPath == "" {
		socketPath = defaultCrioSocket
	}
	return &CrioRuntime{
		socketPath: socketPath,
	}
}

// Name returns the runtime name
func (c *CrioRuntime) Name() string {
	return "cri-o"
}

// Available checks if CRI-O is available
func (c *CrioRuntime) Available() bool {
	_, err := os.Stat(c.socketPath)
	return err == nil
}

// connect creates an HTTP client for the CRI-O socket
func (c *CrioRuntime) connect() {
	if c.client != nil {
		return
	}

	c.client = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", c.socketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
}

// crioContainer represents a container from CRI-O's API
type crioContainer struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	Labels      map[string]string `json:"labels"`
	Pid         int32             `json:"pid"`
	Status      string            `json:"status"`
	Annotations map[string]string `json:"annotations"`
}

// crioContainerList represents the list response
type crioContainerList struct {
	Containers []crioContainer `json:"containers"`
}

// ListContainers returns all running CRI-O containers
func (c *CrioRuntime) ListContainers() ([]*ContainerInfo, error) {
	c.connect()

	resp, err := c.client.Get("http://crio/containers")
	if err != nil {
		return nil, fmt.Errorf("failed to list CRI-O containers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRI-O returned status %d", resp.StatusCode)
	}

	var list crioContainerList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, fmt.Errorf("failed to decode CRI-O response: %w", err)
	}

	var result []*ContainerInfo
	for _, container := range list.Containers {
		if container.Status != "running" {
			continue
		}

		id := container.ID
		if len(id) > 12 {
			id = id[:12]
		}

		// Get name from annotations (Kubernetes pod name) or use container name
		name := container.Name
		if podName, ok := container.Annotations["io.kubernetes.pod.name"]; ok {
			name = podName
		}

		info := &ContainerInfo{
			ID:      id,
			Name:    name,
			Image:   container.Image,
			Runtime: "cri-o",
			Labels:  container.Labels,
			PIDs:    []int32{container.Pid},
		}

		// Try to get all PIDs for this container
		if pids, err := c.getContainerPIDs(container.ID); err == nil {
			info.PIDs = pids
		}

		result = append(result, info)
	}

	return result, nil
}

// GetContainerByPID returns container info for a given PID
func (c *CrioRuntime) GetContainerByPID(pid int32) (*ContainerInfo, error) {
	containers, err := c.ListContainers()
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

// getContainerPIDs gets all PIDs for a container
func (c *CrioRuntime) getContainerPIDs(containerID string) ([]int32, error) {
	c.connect()

	resp, err := c.client.Get(fmt.Sprintf("http://crio/containers/%s", containerID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRI-O returned status %d", resp.StatusCode)
	}

	var container crioContainer
	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		return nil, err
	}

	// CRI-O only provides the main PID directly
	// For child processes, we'd need to read /proc or use cgroups
	return []int32{container.Pid}, nil
}

// Close is a no-op for CRI-O (HTTP client doesn't need closing)
func (c *CrioRuntime) Close() error {
	return nil
}

