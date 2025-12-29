package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/loresuso/psc/pkg"
	"github.com/loresuso/psc/pkg/graph"
	"github.com/spf13/cobra"
)

var treeFlag bool

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
	pt := graph.New()
	for _, td := range tasks {
		pt.Add(td)
	}

	if len(pids) > 0 {
		// Specific PIDs requested
		if treeFlag {
			printLineages(pt, pids)
		} else {
			printFilteredTable(pt, pids)
		}
	} else {
		// All processes
		if treeFlag {
			pt.PrintTree(os.Stdout)
		} else {
			printTable(tasks)
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

func printTable(tasks []*pkg.TaskDescriptor) {
	fmt.Printf("%-8s %-8s %-8s %s\n", "PID", "TID", "PPID", "COMM")
	fmt.Println("-------- -------- -------- ----------------")

	for _, td := range tasks {
		fmt.Printf("%-8d %-8d %-8d %s\n", td.Pid, td.Tid, td.Ppid, td.Comm)
	}
}

func printFilteredTable(pt *graph.ProcessTree, pids []int32) {
	fmt.Printf("%-8s %-8s %-8s %s\n", "PID", "TID", "PPID", "COMM")
	fmt.Println("-------- -------- -------- ----------------")

	for _, pid := range pids {
		td := pt.Get(pid)
		if td == nil {
			fmt.Fprintf(os.Stderr, "Warning: PID %d not found\n", pid)
			continue
		}
		fmt.Printf("%-8d %-8d %-8d %s\n", td.Pid, td.Tid, td.Ppid, td.Comm)
	}
}

func printLineages(pt *graph.ProcessTree, pids []int32) {
	for i, pid := range pids {
		if i > 0 {
			fmt.Println()
		}
		if err := pt.PrintLineage(os.Stdout, pid); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}
}
