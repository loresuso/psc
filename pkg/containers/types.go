package containers

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID      string            `cel:"id"`      // Container ID (short or full)
	Name    string            `cel:"name"`    // Container name
	Image   string            `cel:"image"`   // Image name
	Runtime string            `cel:"runtime"` // Runtime type (e.g., "docker", "containerd", "cri-o")
	Labels  map[string]string `cel:"labels"`  // Container labels
	PIDs    []int32           `cel:"pids"`    // PIDs running in this container
}

// EmptyContainer is used for processes not running in a container.
// This allows CEL expressions to safely access container fields without nil checks.
// Use container.id != "" to check if a process is containerized.
var EmptyContainer = &ContainerInfo{
	Labels: make(map[string]string),
}

// HasLabel checks if the container has a label with the given key
func (c *ContainerInfo) HasLabel(key string) bool {
	if c == nil || c.Labels == nil {
		return false
	}
	_, ok := c.Labels[key]
	return ok
}

// LabelValue returns the value of a label, or empty string if not found
func (c *ContainerInfo) LabelValue(key string) string {
	if c == nil || c.Labels == nil {
		return ""
	}
	return c.Labels[key]
}

// IsEmpty returns true if this is the empty container (process not in container)
func (c *ContainerInfo) IsEmpty() bool {
	return c == nil || c.ID == ""
}

// Runtime is the interface that container runtimes must implement
type Runtime interface {
	// Name returns the runtime name (e.g., "docker", "containerd")
	Name() string

	// Available checks if the runtime is available on the system
	Available() bool

	// ListContainers returns all running containers
	ListContainers() ([]*ContainerInfo, error)

	// GetContainerByPID returns container info for a given PID, or nil if not in a container
	GetContainerByPID(pid int32) (*ContainerInfo, error)
}
