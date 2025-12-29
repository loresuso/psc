package containers

import (
	"context"
	"fmt"
	"os"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
)

const (
	defaultContainerdSocket = "/run/containerd/containerd.sock"
)

// ContainerdRuntime implements Runtime for containerd
type ContainerdRuntime struct {
	socketPath string
	client     *containerd.Client
}

// NewContainerdRuntime creates a new containerd runtime client
func NewContainerdRuntime(socketPath string) *ContainerdRuntime {
	if socketPath == "" {
		socketPath = defaultContainerdSocket
	}
	return &ContainerdRuntime{
		socketPath: socketPath,
	}
}

// Name returns the runtime name
func (c *ContainerdRuntime) Name() string {
	return "containerd"
}

// Available checks if containerd is available
func (c *ContainerdRuntime) Available() bool {
	_, err := os.Stat(c.socketPath)
	return err == nil
}

// connect creates a containerd client if not already connected
func (c *ContainerdRuntime) connect() error {
	if c.client != nil {
		return nil
	}

	client, err := containerd.New(c.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create containerd client: %w", err)
	}
	c.client = client
	return nil
}

// ListContainers returns all running containerd containers
func (c *ContainerdRuntime) ListContainers() ([]*ContainerInfo, error) {
	if err := c.connect(); err != nil {
		return nil, err
	}

	var result []*ContainerInfo

	// containerd uses namespaces, we need to check common ones
	namespacesList := []string{"default", "moby", "k8s.io"}

	for _, ns := range namespacesList {
		ctx := namespaces.WithNamespace(context.Background(), ns)

		containers, err := c.client.Containers(ctx)
		if err != nil {
			continue // Skip namespaces we can't access
		}

		for _, container := range containers {
			info, err := c.getContainerInfo(ctx, container)
			if err != nil {
				continue
			}
			result = append(result, info)
		}
	}

	return result, nil
}

// GetContainerByPID returns container info for a given PID
func (c *ContainerdRuntime) GetContainerByPID(pid int32) (*ContainerInfo, error) {
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

// getContainerInfo fetches detailed info for a container
func (c *ContainerdRuntime) getContainerInfo(ctx context.Context, container containerd.Container) (*ContainerInfo, error) {
	info, err := container.Info(ctx)
	if err != nil {
		return nil, err
	}

	// Get the task to find PIDs
	task, err := container.Task(ctx, nil)
	if err != nil {
		// Container might not be running
		return nil, err
	}

	// Get container PIDs
	pids, err := c.getTaskPIDs(ctx, task)
	if err != nil {
		pids = []int32{}
	}

	// Get image name
	image := info.Image

	// Container ID (first 12 chars)
	id := container.ID()
	if len(id) > 12 {
		id = id[:12]
	}

	// Try to get a friendly name from labels (Docker uses these)
	name := id
	if dockerName, ok := info.Labels["com.docker.compose.service"]; ok {
		name = dockerName
	} else if k8sName, ok := info.Labels["io.kubernetes.container.name"]; ok {
		name = k8sName
	} else if len(container.ID()) > 12 {
		name = container.ID()[:12]
	}

	return &ContainerInfo{
		ID:      id,
		Name:    name,
		Image:   image,
		Runtime: "containerd",
		Labels:  info.Labels,
		PIDs:    pids,
	}, nil
}

// getTaskPIDs returns all PIDs for a task
func (c *ContainerdRuntime) getTaskPIDs(ctx context.Context, task containerd.Task) ([]int32, error) {
	pids, err := task.Pids(ctx)
	if err != nil {
		return nil, err
	}

	var result []int32
	for _, p := range pids {
		result = append(result, int32(p.Pid))
	}
	return result, nil
}

// Close closes the containerd client
func (c *ContainerdRuntime) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}


