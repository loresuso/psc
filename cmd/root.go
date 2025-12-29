package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/fatih/color"
	"github.com/loresuso/psc/pkg"
	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/tree"
	"github.com/spf13/cobra"
)

var treeFlag bool

// Color definitions (bright/high-intensity variants)
var (
	pidColor       = color.New(color.FgHiCyan, color.Bold)
	commColor      = color.New(color.FgHiWhite)
	containerColor = color.New(color.FgHiGreen, color.Bold)
	headerColor    = color.New(color.FgHiYellow, color.Bold)
	separatorColor = color.New(color.FgHiBlack)
)

// BPFLoader is a function type for loading BPF and returning a task reader
type BPFLoader func() (io.ReadCloser, func(), error)

var bpfLoader BPFLoader

// SetBPFLoader sets the BPF loader function (called from main)
func SetBPFLoader(loader BPFLoader) {
	bpfLoader = loader
}

var rootCmd = &cobra.Command{
	Use:   "psc [pid...]",
	Short: "Process scanner using eBPF",
	Long: `A tool to list and visualize processes using eBPF iterators.

If no PIDs are specified, all processes are shown.
If PIDs are specified, only those processes are shown.
With --tree and PIDs, the lineage of each PID is displayed.`,
	RunE: run,
}

func init() {
	rootCmd.Flags().BoolVarP(&treeFlag, "tree", "t", false, "Print processes as a tree")
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func run(cmd *cobra.Command, args []string) error {
	if bpfLoader == nil {
		return fmt.Errorf("BPF loader not initialized")
	}

	// Parse PID arguments
	var pids []int32
	for _, arg := range args {
		pid, err := strconv.ParseInt(arg, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid PID %q: %w", arg, err)
		}
		pids = append(pids, int32(pid))
	}

	// Initialize container manager and refresh container info
	containerMgr := containers.NewDefaultManager()
	if err := containerMgr.Refresh(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to refresh container info: %v\n", err)
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

	if len(pids) > 0 {
		// Specific PIDs requested
		if treeFlag {
			printLineages(pt, pids, containerMgr)
		} else {
			printFilteredTable(pt, pids, containerMgr)
		}
	} else {
		// All processes
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

func printTableHeader() {
	headerColor.Printf("%-8s %-8s %-8s %-16s %s\n", "PID", "TID", "PPID", "COMM", "CONTAINER")
	separatorColor.Println("-------- -------- -------- ---------------- --------------------")
}

func printTableRow(td *pkg.TaskDescriptor, container string) {
	pidColor.Printf("%-8d ", td.Pid)
	fmt.Printf("%-8d %-8d ", td.Tid, td.Ppid)
	commColor.Printf("%-16s ", td.Comm)
	if container != "" {
		containerColor.Printf("%s", container)
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

func printLineages(pt *tree.ProcessTree, pids []int32, mgr *containers.Manager) {
	if err := pt.PrintLineagesWithContainersColored(os.Stdout, pids, mgr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}
