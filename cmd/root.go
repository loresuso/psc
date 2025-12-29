package cmd

import (
	"fmt"
	"io"
	"os"

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
	Use:   "psc",
	Short: "Process scanner using eBPF",
	Long:  "A tool to list and visualize processes using eBPF iterators.",
	RunE:  run,
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

	if treeFlag {
		printTree(tasks)
	} else {
		printTable(tasks)
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

func printTree(tasks []*pkg.TaskDescriptor) {
	pt := graph.New()
	for _, td := range tasks {
		pt.Add(td)
	}
	pt.PrintTree(os.Stdout)
}

