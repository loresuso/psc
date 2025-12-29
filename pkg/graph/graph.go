package graph

import (
	"fmt"
	"io"
	"sort"

	"github.com/loresuso/psc/pkg"
)

// ProcessTree represents a tree of processes indexed by PID.
type ProcessTree struct {
	nodes    map[int32]*pkg.TaskDescriptor
	children map[int32][]int32 // parent PID -> list of child PIDs
}

// New creates a new empty ProcessTree.
func New() *ProcessTree {
	return &ProcessTree{
		nodes:    make(map[int32]*pkg.TaskDescriptor),
		children: make(map[int32][]int32),
	}
}

// Add inserts a process into the tree.
func (pt *ProcessTree) Add(td *pkg.TaskDescriptor) {
	pt.nodes[td.Pid] = td
	pt.children[td.Ppid] = append(pt.children[td.Ppid], td.Pid)
}

// Get returns a process by PID, or nil if not found.
func (pt *ProcessTree) Get(pid int32) *pkg.TaskDescriptor {
	return pt.nodes[pid]
}

// Children returns the child PIDs of a given process.
func (pt *ProcessTree) Children(pid int32) []int32 {
	return pt.children[pid]
}

// PrintTree prints the entire process tree to the writer.
func (pt *ProcessTree) PrintTree(w io.Writer) {
	// Find root processes (those whose parent is not in the tree, or PID 0/1)
	roots := pt.findRoots()

	for _, pid := range roots {
		pt.printNode(w, pid, "", true, true)
	}
}

// PrintSubtree prints the subtree rooted at the given PID.
func (pt *ProcessTree) PrintSubtree(w io.Writer, pid int32) error {
	if _, ok := pt.nodes[pid]; !ok {
		return fmt.Errorf("process %d not found", pid)
	}
	pt.printNode(w, pid, "", true, true)
	return nil
}

// PrintLineage prints the ancestry of a process from root to the given PID.
func (pt *ProcessTree) PrintLineage(w io.Writer, pid int32) error {
	lineage, err := pt.GetLineage(pid)
	if err != nil {
		return err
	}

	for i, td := range lineage {
		indent := ""
		for j := 0; j < i; j++ {
			indent += "    "
		}
		if i == len(lineage)-1 {
			fmt.Fprintf(w, "%s└── [%d] %s\n", indent, td.Pid, td.Comm)
		} else {
			fmt.Fprintf(w, "%s├── [%d] %s\n", indent, td.Pid, td.Comm)
		}
	}
	return nil
}

// GetLineage returns the ancestry of a process from root to the given PID.
func (pt *ProcessTree) GetLineage(pid int32) ([]*pkg.TaskDescriptor, error) {
	if _, ok := pt.nodes[pid]; !ok {
		return nil, fmt.Errorf("process %d not found", pid)
	}

	var lineage []*pkg.TaskDescriptor
	current := pid

	for {
		td := pt.nodes[current]
		if td == nil {
			break
		}
		lineage = append([]*pkg.TaskDescriptor{td}, lineage...)
		if td.Ppid == 0 || td.Ppid == td.Pid {
			break
		}
		current = td.Ppid
	}

	return lineage, nil
}

// PrintLineages prints the merged lineages of multiple PIDs, deduplicating common ancestors.
func (pt *ProcessTree) PrintLineages(w io.Writer, pids []int32) error {
	if len(pids) == 0 {
		return nil
	}

	// Collect all nodes that are part of any lineage
	lineageNodes := make(map[int32]bool)
	for _, pid := range pids {
		lineage, err := pt.GetLineage(pid)
		if err != nil {
			fmt.Fprintf(w, "Warning: %v\n", err)
			continue
		}
		for _, td := range lineage {
			lineageNodes[td.Pid] = true
		}
	}

	if len(lineageNodes) == 0 {
		return fmt.Errorf("no valid PIDs found")
	}

	// Build a subtree with only lineage nodes
	subtree := New()
	for pid := range lineageNodes {
		td := pt.nodes[pid]
		if td != nil {
			subtree.nodes[pid] = td
			// Only add parent-child relationship if parent is also in lineage
			if lineageNodes[td.Ppid] {
				subtree.children[td.Ppid] = append(subtree.children[td.Ppid], pid)
			}
		}
	}

	// Print the subtree
	subtree.PrintTree(w)
	return nil
}

// findRoots returns PIDs of processes that are tree roots.
func (pt *ProcessTree) findRoots() []int32 {
	var roots []int32
	for pid, td := range pt.nodes {
		// A root is a process whose parent is not in the tree
		if _, hasParent := pt.nodes[td.Ppid]; !hasParent {
			roots = append(roots, pid)
		}
	}
	sort.Slice(roots, func(i, j int) bool {
		return roots[i] < roots[j]
	})
	return roots
}

// printNode recursively prints a node and its children.
func (pt *ProcessTree) printNode(w io.Writer, pid int32, prefix string, isRoot bool, isLast bool) {
	td := pt.nodes[pid]
	if td == nil {
		return
	}

	if isRoot {
		fmt.Fprintf(w, "[%d] %s\n", td.Pid, td.Comm)
	} else {
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		fmt.Fprintf(w, "%s%s[%d] %s\n", prefix, connector, td.Pid, td.Comm)
	}

	// Get and sort children
	children := pt.children[pid]
	sort.Slice(children, func(i, j int) bool {
		return children[i] < children[j]
	})

	// Determine new prefix for children
	var newPrefix string
	if isRoot {
		newPrefix = ""
	} else if isLast {
		newPrefix = prefix + "    "
	} else {
		newPrefix = prefix + "│   "
	}

	for i, childPid := range children {
		isLastChild := i == len(children)-1
		pt.printNode(w, childPid, newPrefix, false, isLastChild)
	}
}

// Size returns the number of processes in the tree.
func (pt *ProcessTree) Size() int {
	return len(pt.nodes)
}
