package containers

// ContainerInfo holds information about a container
type ContainerInfo struct {
	ID      string            // Container ID (short or full)
	Name    string            // Container name
	Image   string            // Image name
	Runtime string            // Runtime type (e.g., "docker", "containerd", "cri-o")
	Labels  map[string]string // Container labels
	PIDs    []int32           // PIDs running in this container
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
