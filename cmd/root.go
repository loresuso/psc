package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/loresuso/psc/pkg"
	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/tree"
	"github.com/spf13/cobra"
)

var (
	treeFlag    bool
	lineageFlag bool
)

// Color definitions (bright/high-intensity variants)
var (
	pidColor       = color.New(color.FgHiCyan, color.Bold)
	commColor      = color.New(color.FgHiWhite)
	containerColor = color.New(color.FgHiGreen, color.Bold)
	headerColor    = color.New(color.FgHiYellow, color.Bold)
	separatorColor = color.New(color.FgHiBlack)
	stateColor     = color.New(color.FgHiMagenta)
	cpuColor       = color.New(color.FgHiYellow)
	memColor       = color.New(color.FgHiBlue)
)

// bootTime is cached at startup for CPU% and start time calculations
var bootTime time.Time

func init() {
	bootTime = getBootTime()
}

// BPFLoader is a function type for loading BPF and returning a task reader
type BPFLoader func() (io.ReadCloser, func(), error)

var bpfLoader BPFLoader

// SetBPFLoader sets the BPF loader function (called from main)
func SetBPFLoader(loader BPFLoader) {
	bpfLoader = loader
}

var rootCmd = &cobra.Command{
	Use:   "psc [pid|container...]",
	Short: "Process scanner using eBPF",
	Long: `A tool to list and visualize processes using eBPF iterators.

Arguments can be PIDs (integers), container IDs (full or prefix), or container names.

If no arguments are specified, all processes are shown.
If PIDs are specified, only those processes are shown.
If container IDs/names are specified, only processes in those containers are shown.

Flags:
  --tree (-t)     Display processes as a tree structure
  --lineage (-l)  Show all ancestors of specified PIDs in a table (mutually exclusive with --tree)

Examples:
  # List all processes
  psc

  # Show all processes as a tree
  psc --tree

  # Show details for specific PIDs
  psc 1234 5678

  # Show all processes in a container (by name)
  psc nginx

  # Show all processes in a container (by ID prefix)
  psc a1b2c3

  # Show container processes as a tree
  psc nginx --tree

  # Show full ancestry (lineage) of a process
  psc 1234 --lineage

  # Combine multiple containers and PIDs
  psc nginx redis 9999`,
	RunE: run,
}

func init() {
	rootCmd.Flags().BoolVarP(&treeFlag, "tree", "t", false, "Print processes as a tree")
	rootCmd.Flags().BoolVarP(&lineageFlag, "lineage", "l", false, "Show full lineage (ancestors) for specified PIDs")
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	if bpfLoader == nil {
		return fmt.Errorf("BPF loader not initialized")
	}

	// Initialize container manager and refresh container info first
	// (needed to resolve container names/IDs in arguments)
	containerMgr := containers.NewDefaultManager()
	if err := containerMgr.Refresh(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to refresh container info: %v\n", err)
	}

	// Parse arguments: can be PIDs (integers) or container IDs/names (strings)
	var pids []int32
	var containerFilters []*containers.ContainerInfo

	for _, arg := range args {
		// Try to parse as PID first
		if pid, err := strconv.ParseInt(arg, 10, 32); err == nil {
			pids = append(pids, int32(pid))
			continue
		}

		// Otherwise, try to find a container by ID or name
		container := containerMgr.GetContainerByIDOrName(arg)
		if container != nil {
			containerFilters = append(containerFilters, container)
		} else {
			return fmt.Errorf("argument %q is not a valid PID or known container ID/name", arg)
		}
	}

	reader, cleanup, err := bpfLoader()
	if err != nil {
		return err
	}
	defer cleanup()
	defer reader.Close()

	tasks, err := collectTasks(reader)
	if err != nil {
		return err
	}

	// Build process tree (needed for both tree output and filtering)
	pt := tree.New()
	pidToPpid := make(map[int32]int32)
	for _, td := range tasks {
		pt.Add(td)
		pidToPpid[td.Pid] = td.Ppid
	}

	// Propagate container info to child processes
	containerMgr.PropagateToChildren(pidToPpid)

	// If container filters are specified, get all PIDs for those containers
	if len(containerFilters) > 0 {
		for _, c := range containerFilters {
			containerPids := containerMgr.GetPIDsForContainer(c.ID)
			pids = append(pids, containerPids...)
		}
	}

	// Validate mutually exclusive flags
	if lineageFlag && treeFlag {
		return fmt.Errorf("--lineage and --tree are mutually exclusive")
	}

	// Handle output based on flags
	if len(pids) > 0 {
		// Specific PIDs or containers requested
		if lineageFlag {
			// Show table with all processes in the lineage
			printLineageTable(pt, pids, containerMgr)
		} else if treeFlag {
			// Show tree for specified PIDs/containers
			printContainerTree(pt, pids, containerMgr)
		} else {
			// Show table for specified PIDs
			printFilteredTable(pt, pids, containerMgr)
		}
	} else {
		// All processes
		if lineageFlag {
			return fmt.Errorf("--lineage requires at least one PID argument")
		}
		if treeFlag {
			pt.PrintTreeWithContainersColored(os.Stdout, containerMgr)
		} else {
			printTable(tasks, containerMgr)
		}
	}

	return nil
}

func collectTasks(reader io.Reader) ([]*pkg.TaskDescriptor, error) {
	var tasks []*pkg.TaskDescriptor
	buf := make([]byte, pkg.TaskDescriptor{}.Size())

	for {
		_, err := io.ReadFull(reader, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read from iterator: %w", err)
		}

		var td pkg.TaskDescriptor
		if err := td.Unmarshal(buf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal task descriptor: %w", err)
		}

		// Only include processes, not threads
		if td.Tid != td.Pid {
			continue
		}

		// Read cmdline and resolve username (BPF iterators can't read userspace memory)
		td.Enrich()

		tdCopy := td
		tasks = append(tasks, &tdCopy)
	}

	return tasks, nil
}

func getContainerLabel(pid int32, mgr *containers.Manager) string {
	if mgr == nil {
		return ""
	}
	c := mgr.GetContainerByPID(pid)
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", c.Name, c.ID, c.Runtime)
}

// getBootTime reads the system boot time from /proc/stat
func getBootTime() time.Time {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return time.Now()
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				btime, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return time.Unix(btime, 0)
				}
			}
		}
	}
	return time.Now()
}

func printTableHeader() {
	headerColor.Printf("%-10s %-8s %-8s %-8s %-2s %5s %8s %8s %-11s %-16s %s\n",
		"USER", "PID", "TID", "PPID", "S", "%CPU", "VSZ", "RSS", "START", "COMM", "CMDLINE (CONTAINER)")
	separatorColor.Println("---------- -------- -------- -------- -- ----- -------- -------- ----------- ---------------- -------------------")
}

func printTableRow(td *pkg.TaskDescriptor, container string) {
	// Truncate username if too long
	user := td.User
	if len(user) > 10 {
		user = user[:9] + "+"
	}
	fmt.Printf("%-10s ", user)
	pidColor.Printf("%-8d ", td.Pid)
	fmt.Printf("%-8d %-8d ", td.Tid, td.Ppid)
	stateColor.Printf("%-2s ", td.State.StateChar())
	cpuColor.Printf("%5.1f ", td.CpuPercent(bootTime))
	memColor.Printf("%8s %8s ", pkg.FormatMemory(td.Vsz), pkg.FormatMemory(td.Rss))
	fmt.Printf("%-11s ", td.FormatStartTime(bootTime))
	commColor.Printf("%-16s ", td.Comm)
	// Print cmdline (variable length)
	fmt.Printf("%s", td.Cmdline)
	// Print container at the end if present
	if container != "" {
		containerColor.Printf(" (%s)", container)
	}
	fmt.Println()
}

func printTable(tasks []*pkg.TaskDescriptor, mgr *containers.Manager) {
	printTableHeader()

	for _, td := range tasks {
		container := getContainerLabel(td.Pid, mgr)
		printTableRow(td, container)
	}
}

func printFilteredTable(pt *tree.ProcessTree, pids []int32, mgr *containers.Manager) {
	printTableHeader()

	for _, pid := range pids {
		td := pt.Get(pid)
		if td == nil {
			fmt.Fprintf(os.Stderr, "Warning: PID %d not found\n", pid)
			continue
		}
		container := getContainerLabel(td.Pid, mgr)
		printTableRow(td, container)
	}
}

// printLineageTable prints a table containing all processes in the lineage of the specified PIDs
func printLineageTable(pt *tree.ProcessTree, pids []int32, mgr *containers.Manager) {
	// Collect all PIDs in the lineages
	lineagePids := make(map[int32]bool)
	for _, pid := range pids {
		lineage, err := pt.GetLineage(pid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			continue
		}
		for _, td := range lineage {
			lineagePids[td.Pid] = true
		}
	}

	if len(lineagePids) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no valid PIDs found\n")
		return
	}

	// Convert to sorted slice for consistent output
	var sortedPids []int32
	for pid := range lineagePids {
		sortedPids = append(sortedPids, pid)
	}
	sort.Slice(sortedPids, func(i, j int) bool {
		return sortedPids[i] < sortedPids[j]
	})

	printTableHeader()
	for _, pid := range sortedPids {
		td := pt.Get(pid)
		if td != nil {
			container := getContainerLabel(td.Pid, mgr)
			printTableRow(td, container)
		}
	}
}

// printContainerTree prints a tree showing only the specified PIDs and their descendants
func printContainerTree(pt *tree.ProcessTree, pids []int32, mgr *containers.Manager) {
	// Create a set of PIDs to include
	pidSet := make(map[int32]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	// Print tree for processes in the set
	pt.PrintSubtreeWithContainersColored(os.Stdout, pidSet, mgr)
}
