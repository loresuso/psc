package main

import (
	"fmt"
	"io"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/loresuso/psc/pkg"
)

// Generate with: make generate

func main() {
	// Remove memory lock limit for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled BPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Create an iterator link from the BPF program
	iter, err := link.AttachIter(link.IterOptions{
		Program: objs.PsTask,
	})
	if err != nil {
		log.Fatalf("Failed to attach iterator: %v", err)
	}
	defer iter.Close()

	// Open the iterator to read from it
	reader, err := iter.Open()
	if err != nil {
		log.Fatalf("Failed to open iterator: %v", err)
	}
	defer reader.Close()

	// Print table header
	fmt.Printf("%-8s %-8s %-8s %s\n", "PID", "TID", "PPID", "COMM")
	fmt.Println("-------- -------- -------- ----------------")

	// Read and unmarshal task descriptors
	buf := make([]byte, pkg.TaskDescriptor{}.Size())
	for {
		_, err := io.ReadFull(reader, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to read from iterator: %v", err)
		}

		var td pkg.TaskDescriptor
		if err := td.Unmarshal(buf); err != nil {
			log.Fatalf("Failed to unmarshal task descriptor: %v", err)
		}

		// Print only processes, not threads
		if td.Tid != td.Pid {
			continue
		}

		fmt.Printf("%-8d %-8d %-8d %s\n", td.Pid, td.Tid, td.Ppid, td.Comm)
	}
}
