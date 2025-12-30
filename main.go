package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/loresuso/psc/cmd"
)

// Generate with: make generate

func main() {
	cmd.SetBPFLoaders(cmd.BPFLoaders{
		Task: loadTasksBPF,
		File: loadFilesBPF,
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadTasksBPF() (io.ReadCloser, func(), error) {
	// Remove memory lock limit for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load the compiled BPF objects
	objs := tasksObjects{}
	if err := loadTasksObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	// Create a task iterator link from the BPF program
	taskIter, err := link.AttachIter(link.IterOptions{
		Program: objs.PsTask,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("failed to attach task iterator: %w", err)
	}

	// Open the task iterator to read from it
	reader, err := taskIter.Open()
	if err != nil {
		taskIter.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("failed to open task iterator: %w", err)
	}

	cleanup := func() {
		taskIter.Close()
		objs.Close()
	}

	return reader, cleanup, nil
}

func loadFilesBPF() (io.ReadCloser, func(), error) {
	// Remove memory lock limit for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load the compiled BPF objects
	objs := filesObjects{}
	if err := loadFilesObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	// Create a file iterator link from the BPF program
	fileIter, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTaskFile,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("failed to attach file iterator: %w", err)
	}

	// Open the file iterator to read from it
	reader, err := fileIter.Open()
	if err != nil {
		fileIter.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("failed to open file iterator: %w", err)
	}

	cleanup := func() {
		fileIter.Close()
		objs.Close()
	}

	return reader, cleanup, nil
}
