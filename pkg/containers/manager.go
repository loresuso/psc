package containers

// Manager manages multiple container runtimes and provides a unified interface
type Manager struct {
	runtimes       []Runtime
	containers     map[string]*ContainerInfo // containerID -> info
	pidToContainer map[int32]*ContainerInfo  // PID -> container info
}

// NewManager creates a new container manager with the given runtimes
func NewManager(runtimes ...Runtime) *Manager {
	return &Manager{
		runtimes:       runtimes,
		containers:     make(map[string]*ContainerInfo),
		pidToContainer: make(map[int32]*ContainerInfo),
	}
}

// NewDefaultManager creates a manager with all available runtimes
func NewDefaultManager() *Manager {
	var runtimes []Runtime

	// Try Docker
	docker := NewDockerRuntime("")
	if docker.Available() {
		runtimes = append(runtimes, docker)
	}

	// Try containerd
	containerd := NewContainerdRuntime("")
	if containerd.Available() {
		runtimes = append(runtimes, containerd)
	}

	// Try CRI-O
	crio := NewCrioRuntime("")
	if crio.Available() {
		runtimes = append(runtimes, crio)
	}

	// Try Podman
	podman := NewPodmanRuntime("")
	if podman.Available() {
		runtimes = append(runtimes, podman)
	}

	return NewManager(runtimes...)
}

// Refresh queries all runtimes and builds the container/PID mappings
// Runtimes are queried in order, with earlier runtimes taking priority
// for duplicate PIDs (Docker should come before containerd for better names)
func (m *Manager) Refresh() error {
	m.containers = make(map[string]*ContainerInfo)
	m.pidToContainer = make(map[int32]*ContainerInfo)

	for _, runtime := range m.runtimes {
		containers, err := runtime.ListContainers()
		if err != nil {
			// Log but continue with other runtimes
			// fmt.Printf("Warning: failed to list containers from %s: %v\n", runtime.Name(), err)
			continue
		}

		for _, c := range containers {
			// Only add if not already present (earlier runtimes take priority)
			if _, exists := m.containers[c.ID]; !exists {
				m.containers[c.ID] = c
			}
			for _, pid := range c.PIDs {
				// Only add if not already mapped (earlier runtimes take priority)
				if _, exists := m.pidToContainer[pid]; !exists {
					m.pidToContainer[pid] = c
				}
			}
		}
	}

	return nil
}

// GetContainerByPID returns container info for a PID, or nil if not in a container
func (m *Manager) GetContainerByPID(pid int32) *ContainerInfo {
	return m.pidToContainer[pid]
}

// PropagateToChildren associates child processes with their parent's container.
// This should be called after Refresh() with a map of PID -> PPID relationships.
func (m *Manager) PropagateToChildren(pidToPpid map[int32]int32) {
	// Build a map of parent -> children
	children := make(map[int32][]int32)
	for pid, ppid := range pidToPpid {
		children[ppid] = append(children[ppid], pid)
	}

	// For each known container PID, propagate to all descendants
	for pid, container := range m.pidToContainer {
		m.propagateToDescendants(pid, container, children)
	}
}

// propagateToDescendants recursively marks all descendants with the container info
func (m *Manager) propagateToDescendants(pid int32, container *ContainerInfo, children map[int32][]int32) {
	for _, childPid := range children[pid] {
		// Only set if not already set (don't override)
		if _, exists := m.pidToContainer[childPid]; !exists {
			m.pidToContainer[childPid] = container
		}
		// Recurse to grandchildren
		m.propagateToDescendants(childPid, container, children)
	}
}

// GetContainer returns container info by ID
func (m *Manager) GetContainer(id string) *ContainerInfo {
	return m.containers[id]
}

// ListContainers returns all known containers
func (m *Manager) ListContainers() []*ContainerInfo {
	result := make([]*ContainerInfo, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}
	return result
}

// RuntimeCount returns the number of available runtimes
func (m *Manager) RuntimeCount() int {
	return len(m.runtimes)
}

// RuntimeNames returns the names of available runtimes
func (m *Manager) RuntimeNames() []string {
	names := make([]string, len(m.runtimes))
	for i, r := range m.runtimes {
		names[i] = r.Name()
	}
	return names
}
