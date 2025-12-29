package containers

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

const (
	defaultDockerSocket = "/var/run/docker.sock"
)

// DockerRuntime implements Runtime for Docker
type DockerRuntime struct {
	socketPath string
	client     *client.Client
}

// NewDockerRuntime creates a new Docker runtime client
func NewDockerRuntime(socketPath string) *DockerRuntime {
	if socketPath == "" {
		socketPath = defaultDockerSocket
	}
	return &DockerRuntime{
		socketPath: socketPath,
	}
}

// Name returns the runtime name
func (d *DockerRuntime) Name() string {
	return "docker"
}

// Available checks if Docker is available
func (d *DockerRuntime) Available() bool {
	_, err := os.Stat(d.socketPath)
	return err == nil
}

// connect creates a Docker client if not already connected
func (d *DockerRuntime) connect() error {
	if d.client != nil {
		return nil
	}

	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+d.socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}
	d.client = cli
	return nil
}

// ListContainers returns all running Docker containers
func (d *DockerRuntime) ListContainers() ([]*ContainerInfo, error) {
	if err := d.connect(); err != nil {
		return nil, err
	}

	ctx := context.Background()
	containers, err := d.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var result []*ContainerInfo
	for _, c := range containers {
		info, err := d.getContainerInfo(ctx, c.ID)
		if err != nil {
			continue // Skip containers we can't inspect
		}
		result = append(result, info)
	}

	return result, nil
}

// GetContainerByPID returns container info for a given PID
func (d *DockerRuntime) GetContainerByPID(pid int32) (*ContainerInfo, error) {
	containers, err := d.ListContainers()
	if err != nil {
		return nil, err
	}

	for _, c := range containers {
		for _, containerPid := range c.PIDs {
			if containerPid == pid {
				return c, nil
			}
		}
	}

	return nil, nil // Not in a container
}

// getContainerInfo fetches detailed info for a container
func (d *DockerRuntime) getContainerInfo(ctx context.Context, containerID string) (*ContainerInfo, error) {
	inspect, err := d.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}

	// Get PIDs from container top
	pids, err := d.getContainerPIDs(ctx, containerID)
	if err != nil {
		pids = []int32{} // Continue without PIDs if we can't get them
	}

	name := strings.TrimPrefix(inspect.Name, "/")

	return &ContainerInfo{
		ID:      containerID[:12], // Short ID
		Name:    name,
		Image:   inspect.Config.Image,
		Runtime: "docker",
		Labels:  inspect.Config.Labels,
		PIDs:    pids,
	}, nil
}

// getContainerPIDs returns all PIDs running in a container
func (d *DockerRuntime) getContainerPIDs(ctx context.Context, containerID string) ([]int32, error) {
	top, err := d.client.ContainerTop(ctx, containerID, []string{})
	if err != nil {
		return nil, err
	}

	// Find PID column index
	pidCol := -1
	for i, title := range top.Titles {
		if title == "PID" {
			pidCol = i
			break
		}
	}
	if pidCol == -1 {
		return nil, fmt.Errorf("PID column not found in container top output")
	}

	var pids []int32
	for _, proc := range top.Processes {
		if pidCol < len(proc) {
			var pid int32
			if _, err := fmt.Sscanf(proc[pidCol], "%d", &pid); err == nil {
				pids = append(pids, pid)
			}
		}
	}

	return pids, nil
}

// Close closes the Docker client
func (d *DockerRuntime) Close() error {
	if d.client != nil {
		return d.client.Close()
	}
	return nil
}
