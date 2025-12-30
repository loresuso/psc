package tree

import (
	"fmt"
	"io"
	"sort"

	"github.com/fatih/color"
	"github.com/loresuso/psc/pkg/containers"
)

// Printer handles tree printing with various options.
type Printer struct {
	tree         *ProcessTree
	containerMgr *containers.Manager
	colored      bool
}

// Color definitions for tree output (bright/high-intensity variants)
var (
	pidColor       = color.New(color.FgHiCyan, color.Bold)
	commColor      = color.New(color.FgHiWhite)
	containerColor = color.New(color.FgHiGreen, color.Bold)
	treeColor      = color.New(color.FgHiBlack)
)

type PrintOption func(*Printer) *Printer

// NewPrinter creates a new Printer for the given tree.
func NewPrinter(pt *ProcessTree, opts ...PrintOption) *Printer {
	p := &Printer{
		tree:    pt,
		colored: true,
	}
	for _, opt := range opts {
		p = opt(p)
	}
	return p
}

// WithContainers returns an option that sets the container manager for container labels.
func WithContainers(mgr *containers.Manager) PrintOption {
	return func(p *Printer) *Printer {
		p.containerMgr = mgr
		return p
	}
}

// WithColors returns an option that enables or disables colored output.
func WithColors(colored bool) PrintOption {
	return func(p *Printer) *Printer {
		p.colored = colored
		return p
	}
}

// PrintTree prints the entire process tree.
func (p *Printer) PrintTree(w io.Writer) {
	roots := p.tree.FindRoots()
	for _, pid := range roots {
		p.printNode(w, pid, "", true, true)
	}
}

// PrintSubtree prints the subtree rooted at the given PID.
func (p *Printer) PrintSubtree(w io.Writer, pid int32) error {
	if p.tree.Get(pid) == nil {
		return fmt.Errorf("process %d not found", pid)
	}
	p.printNode(w, pid, "", true, true)
	return nil
}

// PrintLineages prints merged lineages of multiple PIDs.
func (p *Printer) PrintLineages(w io.Writer, pids []int32) error {
	subtree, err := p.tree.BuildLineageSubtree(pids)
	if err != nil {
		return err
	}

	subPrinter := NewPrinter(subtree, WithContainers(p.containerMgr), WithColors(p.colored))
	subPrinter.PrintTree(w)
	return nil
}

// PrintFiltered prints only the specified PIDs and their descendants.
func (p *Printer) PrintFiltered(w io.Writer, pidSet map[int32]bool) {
	if len(pidSet) == 0 {
		return
	}

	// Find root processes among the specified PIDs
	var roots []int32
	for pid := range pidSet {
		td := p.tree.Get(pid)
		if td == nil {
			continue
		}
		if !pidSet[td.Ppid] {
			roots = append(roots, pid)
		}
	}

	sort.Slice(roots, func(i, j int) bool {
		return roots[i] < roots[j]
	})

	for _, rootPid := range roots {
		p.printNodeFiltered(w, rootPid, "", true, true, pidSet)
	}
}

// printNode recursively prints a node and its children.
func (p *Printer) printNode(w io.Writer, pid int32, prefix string, isRoot bool, isLast bool) {
	td := p.tree.Get(pid)
	if td == nil {
		return
	}

	containerLabel := p.getContainerLabel(pid)
	p.printNodeContent(w, td.Pid, td.Comm, containerLabel, prefix, isRoot, isLast)

	children := p.tree.ChildrenSorted(pid)
	newPrefix := p.nextPrefix(prefix, isRoot, isLast)

	for i, childPid := range children {
		isLastChild := i == len(children)-1
		p.printNode(w, childPid, newPrefix, false, isLastChild)
	}
}

// printNodeFiltered prints a node and only children in the filter set.
func (p *Printer) printNodeFiltered(w io.Writer, pid int32, prefix string, isRoot bool, isLast bool, filter map[int32]bool) {
	td := p.tree.Get(pid)
	if td == nil {
		return
	}

	containerLabel := p.getContainerLabel(pid)
	p.printNodeContent(w, td.Pid, td.Comm, containerLabel, prefix, isRoot, isLast)

	// Get filtered children
	var filteredChildren []int32
	for _, childPid := range p.tree.Children(pid) {
		if filter[childPid] {
			filteredChildren = append(filteredChildren, childPid)
		}
	}
	sort.Slice(filteredChildren, func(i, j int) bool {
		return filteredChildren[i] < filteredChildren[j]
	})

	newPrefix := p.nextPrefix(prefix, isRoot, isLast)

	for i, childPid := range filteredChildren {
		isLastChild := i == len(filteredChildren)-1
		p.printNodeFiltered(w, childPid, newPrefix, false, isLastChild, filter)
	}
}

// printNodeContent prints the content of a single node.
func (p *Printer) printNodeContent(w io.Writer, pid int32, comm string, containerLabel string, prefix string, isRoot bool, isLast bool) {
	if p.colored {
		p.printNodeColored(w, pid, comm, containerLabel, prefix, isRoot, isLast)
	} else {
		p.printNodePlain(w, pid, comm, containerLabel, prefix, isRoot, isLast)
	}
}

// printNodePlain prints a node without colors.
func (p *Printer) printNodePlain(w io.Writer, pid int32, comm string, containerLabel string, prefix string, isRoot bool, isLast bool) {
	if isRoot {
		if containerLabel != "" {
			fmt.Fprintf(w, "[%d] %s (%s)\n", pid, comm, containerLabel)
		} else {
			fmt.Fprintf(w, "[%d] %s\n", pid, comm)
		}
	} else {
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		if containerLabel != "" {
			fmt.Fprintf(w, "%s%s[%d] %s (%s)\n", prefix, connector, pid, comm, containerLabel)
		} else {
			fmt.Fprintf(w, "%s%s[%d] %s\n", prefix, connector, pid, comm)
		}
	}
}

// printNodeColored prints a node with colors.
func (p *Printer) printNodeColored(w io.Writer, pid int32, comm string, containerLabel string, prefix string, isRoot bool, isLast bool) {
	if isRoot {
		fmt.Fprint(w, "[")
		pidColor.Fprint(w, pid)
		fmt.Fprint(w, "] ")
		commColor.Fprint(w, comm)
		if containerLabel != "" {
			fmt.Fprint(w, " ")
			containerColor.Fprintf(w, "(%s)", containerLabel)
		}
		fmt.Fprintln(w)
	} else {
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		treeColor.Fprint(w, prefix, connector)
		fmt.Fprint(w, "[")
		pidColor.Fprint(w, pid)
		fmt.Fprint(w, "] ")
		commColor.Fprint(w, comm)
		if containerLabel != "" {
			fmt.Fprint(w, " ")
			containerColor.Fprintf(w, "(%s)", containerLabel)
		}
		fmt.Fprintln(w)
	}
}

// getContainerLabel returns the container label for a PID.
func (p *Printer) getContainerLabel(pid int32) string {
	if p.containerMgr == nil {
		return ""
	}
	c := p.containerMgr.GetContainerByPID(pid)
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", c.Name, c.ID, c.Runtime)
}

// nextPrefix calculates the prefix for child nodes.
func (p *Printer) nextPrefix(prefix string, isRoot bool, isLast bool) string {
	if isRoot {
		return ""
	}
	if isLast {
		return prefix + "    "
	}
	return prefix + "│   "
}
