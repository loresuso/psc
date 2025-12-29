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
	cmd.SetBPFLoader(loadBPF)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadBPF() (io.ReadCloser, func(), error) {
	// Remove memory lock limit for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load the compiled BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("failed to load BPF objects: %w", err)
	}

	// Create an iterator link from the BPF program
	iter, err := link.AttachIter(link.IterOptions{
		Program: objs.PsTask,
	})
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("failed to attach iterator: %w", err)
	}

	// Open the iterator to read from it
	reader, err := iter.Open()
	if err != nil {
		iter.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("failed to open iterator: %w", err)
	}

	cleanup := func() {
		iter.Close()
		objs.Close()
	}

	return reader, cleanup, nil
}
