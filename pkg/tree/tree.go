package tree

import (
	"fmt"
	"sort"

	"github.com/loresuso/psc/pkg/unmarshal"
)

// ProcessTree represents a tree of processes indexed by PID.
type ProcessTree struct {
	nodes    map[int32]*unmarshal.TaskDescriptor
	children map[int32][]int32 // parent PID -> list of child PIDs
}

// New creates a new empty ProcessTree.
func New() *ProcessTree {
	return &ProcessTree{
		nodes:    make(map[int32]*unmarshal.TaskDescriptor),
		children: make(map[int32][]int32),
	}
}

// Add inserts a process into the tree.
func (pt *ProcessTree) Add(td *unmarshal.TaskDescriptor) {
	pt.nodes[td.Pid] = td
	pt.children[td.Ppid] = append(pt.children[td.Ppid], td.Pid)
}

// Get returns a process by PID, or nil if not found.
func (pt *ProcessTree) Get(pid int32) *unmarshal.TaskDescriptor {
	return pt.nodes[pid]
}

// Children returns the child PIDs of a given process.
func (pt *ProcessTree) Children(pid int32) []int32 {
	return pt.children[pid]
}

// ChildrenSorted returns the child PIDs sorted numerically.
func (pt *ProcessTree) ChildrenSorted(pid int32) []int32 {
	children := make([]int32, len(pt.children[pid]))
	copy(children, pt.children[pid])
	sort.Slice(children, func(i, j int) bool {
		return children[i] < children[j]
	})
	return children
}

// Size returns the number of processes in the tree.
func (pt *ProcessTree) Size() int {
	return len(pt.nodes)
}

// GetLineage returns the ancestry of a process from root to the given PID.
func (pt *ProcessTree) GetLineage(pid int32) ([]*unmarshal.TaskDescriptor, error) {
	if _, ok := pt.nodes[pid]; !ok {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	var lineage []*unmarshal.TaskDescriptor
	current := pid

	for {
		td := pt.nodes[current]
		if td == nil {
			break
		}
		lineage = append([]*unmarshal.TaskDescriptor{td}, lineage...)
		if td.Ppid == 0 || td.Ppid == td.Pid {
			break
		}
		current = td.Ppid
	}

	return lineage, nil
}

// FindRoots returns PIDs of processes that are tree roots.
// A root is a process whose parent is not in the tree.
func (pt *ProcessTree) FindRoots() []int32 {
	var roots []int32
	for pid, td := range pt.nodes {
		if _, hasParent := pt.nodes[td.Ppid]; !hasParent {
			roots = append(roots, pid)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i] < roots[j]
	})
	return roots
}

// BuildLineageSubtree creates a new tree containing only nodes in the lineages of the given PIDs.
func (pt *ProcessTree) BuildLineageSubtree(pids []int32) (*ProcessTree, error) {
	lineageNodes := make(map[int32]bool)
	for _, pid := range pids {
		lineage, err := pt.GetLineage(pid)
		if err != nil {
			continue
		}
		for _, td := range lineage {
			lineageNodes[td.Pid] = true
		}
	}

	if len(lineageNodes) == 0 {
		return nil, fmt.Errorf("no valid PIDs found")
	}

	subtree := New()
	for pid := range lineageNodes {
		td := pt.nodes[pid]
		if td != nil {
			subtree.nodes[pid] = td
			if lineageNodes[td.Ppid] {
				subtree.children[td.Ppid] = append(subtree.children[td.Ppid], pid)
			}
		}
	}

	return subtree, nil
}

// All returns all TaskDescriptors in the tree.
func (pt *ProcessTree) All() []*unmarshal.TaskDescriptor {
	result := make([]*unmarshal.TaskDescriptor, 0, len(pt.nodes))
	for _, td := range pt.nodes {
		result = append(result, td)
	}
	return result
}
