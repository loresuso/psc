package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/table"
	"github.com/loresuso/psc/pkg/tree"
	"github.com/loresuso/psc/pkg/unmarshal"
	"github.com/spf13/cobra"
)

var (
	treeFlag    bool
	lineageFlag bool
	noColorFlag bool
)

// bootTime is cached at startup for CPU% and start time calculations
var bootTime time.Time

func init() {
	bootTime = getBootTime()
}

// BPFLoader is a function type for loading BPF and returning a reader
type BPFLoader func() (io.ReadCloser, func(), error)

// BPFLoaders holds the different BPF loader functions
type BPFLoaders struct {
	Task BPFLoader
	File BPFLoader
}

var loaders BPFLoaders

// SetBPFLoaders sets the BPF loader functions (called from main)
func SetBPFLoaders(l BPFLoaders) {
	loaders = l
}

// GetTaskLoader returns the task BPF loader
func GetTaskLoader() BPFLoader {
	return loaders.Task
}

// GetFileLoader returns the file BPF loader
func GetFileLoader() BPFLoader {
	return loaders.File
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
	rootCmd.Flags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
	rootCmd.MarkFlagsMutuallyExclusive("tree", "lineage")
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	if loaders.Task == nil {
		return fmt.Errorf("BPF task loader not initialized")
	}
	if loaders.File == nil {
		return fmt.Errorf("BPF file loader not initialized")
	}

	reader, cleanup, err := loaders.File()
	if err != nil {
		return err
	}
	defer cleanup()
	defer reader.Close()
	buf := make([]byte, unmarshal.FileDescriptor{}.Size())
	for {
		_, err := io.ReadFull(reader, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read from iterator: %w", err)
		}
		var fd unmarshal.FileDescriptor
		if err := fd.Unmarshal(buf); err != nil {
			return fmt.Errorf("failed to unmarshal file descriptor: %w", err)
		}
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

	taskReader, taskCleanup, err := loaders.Task()
	if err != nil {
		return err
	}
	defer taskCleanup()
	defer reader.Close()

	tasks, err := collectTasks(taskReader)
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

	// Create printers with options
	tablePrinter := table.NewPrinter(os.Stdout, bootTime,
		table.WithContainers(containerMgr),
		table.WithColors(!noColorFlag),
	)
	treePrinter := tree.NewPrinter(pt,
		tree.WithContainers(containerMgr),
		tree.WithColors(!noColorFlag),
	)

	// Handle output based on flags
	if len(pids) > 0 {
		// Specific PIDs or containers requested
		if lineageFlag {
			// Collect all PIDs in the lineages
			lineagePids := collectLineagePids(pt, pids)
			tablePrinter.PrintLineage(tasks, lineagePids)
		} else if treeFlag {
			// Show tree for specified PIDs/containers
			pidSet := make(map[int32]bool)
			for _, pid := range pids {
				pidSet[pid] = true
			}
			treePrinter.PrintFiltered(os.Stdout, pidSet)
		} else {
			// Show table for specified PIDs
			tablePrinter.PrintPIDs(tasks, pids)
		}
	} else {
		// All processes
		if lineageFlag {
			return fmt.Errorf("--lineage requires at least one PID argument")
		}
		if treeFlag {
			treePrinter.PrintTree(os.Stdout)
		} else {
			tablePrinter.PrintAll(tasks)
		}
	}

	return nil
}

// collectLineagePids collects all PIDs in the lineages of the given PIDs.
func collectLineagePids(pt *tree.ProcessTree, pids []int32) map[int32]bool {
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
	return lineagePids
}

func collectTasks(reader io.Reader) ([]*unmarshal.TaskDescriptor, error) {
	var tasks []*unmarshal.TaskDescriptor
	buf := make([]byte, unmarshal.TaskDescriptor{}.Size())

	for {
		_, err := io.ReadFull(reader, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read from iterator: %w", err)
		}

		var td unmarshal.TaskDescriptor
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
