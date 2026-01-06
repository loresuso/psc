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
	"github.com/loresuso/psc/pkg/filter"
	"github.com/loresuso/psc/pkg/table"
	"github.com/loresuso/psc/pkg/tree"
	"github.com/loresuso/psc/pkg/unmarshal"
	"github.com/spf13/cobra"
)

var (
	treeFlag    bool
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
	Use:   "psc [expression]",
	Short: "Process scanner using eBPF with CEL filtering",
	Long: `A tool to list and filter processes using eBPF iterators and CEL expressions.

If no expression is provided, all processes are shown.
Otherwise, processes are filtered using the Google Common Expression Language (CEL).

Available Variables:
  process   - Process information
  container - Container information (nil if not in container)
  file      - File descriptor information  
  socket    - Socket information (alias for file)

Process Fields (process.X):
  name      - Process name (string)
  pid       - Process ID (int)
  ppid      - Parent process ID (int)
  tid       - Thread ID (int)
  euid      - Effective user ID (int)
  user      - Username (string)
  cmdline   - Full command line (string)
  state     - Process state (uint)

Container Fields (container.X):
  id        - Container ID, empty if not in container (string)
  name      - Container name (string)
  image     - Container image (string)
  runtime   - Runtime (string), compare with: docker, containerd, crio, podman
  labels    - Container labels (map[string]string)

File/Socket Fields (socket.X or file.X):
  path      - File path (string)
  fd        - File descriptor number (int)
  srcPort   - Source port (uint)
  dstPort   - Destination port (uint)
  sockType  - Socket type, compare with: tcp, udp
  sockState - TCP state, compare with: listen, established, close_wait, etc.
  sockFamily- Address family, compare with: unix, inet, inet6
  unixPath  - Unix socket path (string)
  fdType    - FD type, compare with: file_type, socket_type

Available Constants (no quotes needed):
  Runtimes:    docker, containerd, crio, podman
  Socket types: tcp, udp
  Families:    unix, inet, inet6
  TCP states:  established, listen, syn_sent, syn_recv, fin_wait1, fin_wait2,
               time_wait, close, close_wait, last_ack, closing
  FD types:    file_type, socket_type

String Functions:
  .contains("substr")     - Check if string contains substring
  .startsWith("prefix")   - Check if string starts with prefix
  .endsWith("suffix")     - Check if string ends with suffix

Examples:
  # List all processes
  psc

  # Show all processes as a tree
  psc --tree

  # Filter by process name
  psc 'process.name == "nginx"'

  # Filter by user
  psc 'process.user == "root"'

  # Filter using OR conditions
  psc 'process.name == "bash" || process.name == "zsh"'

  # Filter by cmdline content
  psc 'process.cmdline.contains("--config")'

  # Filter by name prefix
  psc 'process.name.startsWith("systemd")'

  # Filter by PID
  psc 'process.pid == 1234'

  # Filter by parent PID
  psc 'process.ppid == 1'

  # Filter only containerized processes
  psc 'container.id != ""'

  # Filter by container name
  psc 'container.name == "nginx"'

  # Filter by container runtime (no quotes needed!)
  psc 'container.runtime == docker'

  # Filter by container image
  psc 'container.image.contains("nginx")'

  # Filter listening TCP sockets
  psc 'socket.sockType == tcp && socket.sockState == listen'

  # Filter established connections
  psc 'socket.sockState == established'

  # Filter Unix sockets
  psc 'socket.sockFamily == unix'

  # Complex filter with tree output
  psc 'process.user == "root" && process.pid > 1000' --tree`,
	RunE: run,
	Args: cobra.MaximumNArgs(1),
}

func init() {
	rootCmd.Flags().BoolVarP(&treeFlag, "tree", "t", false, "Print processes as a tree")
	rootCmd.Flags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")
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

	// Compile CEL filter expression if provided
	var celFilter *filter.Filter
	if len(args) > 0 && args[0] != "" {
		var err error
		celFilter, err = filter.New(args[0])
		if err != nil {
			return fmt.Errorf("invalid CEL expression: %w", err)
		}
	}

	// Initialize container manager for container info display
	containerMgr := containers.NewDefaultManager()
	if err := containerMgr.Refresh(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to refresh container info: %v\n", err)
	}

	// Collect tasks
	taskReader, taskCleanup, err := loaders.Task()
	if err != nil {
		return err
	}
	defer taskCleanup()
	defer taskReader.Close()

	tasks, err := collectTasks(taskReader)
	if err != nil {
		return err
	}

	// Build PID->PPID map and propagate container info BEFORE filtering
	// This allows CEL expressions to filter by container attributes
	pidToPpid := make(map[int32]int32)
	for _, td := range tasks {
		pidToPpid[td.Pid] = td.Ppid
	}
	containerMgr.PropagateToChildren(pidToPpid)

	// Associate container info with each task (for CEL filtering)
	for _, task := range tasks {
		if c := containerMgr.GetContainerByPID(task.Pid); c != nil {
			task.SetContainer(c)
		}
	}

	// Collect files and group by PID BEFORE filtering
	// This allows CEL expressions to filter by socket/file attributes
	filesByPid, err := collectFilesByPid()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to collect file descriptors: %v\n", err)
	}

	// Associate files with tasks BEFORE filtering
	for _, task := range tasks {
		if files, ok := filesByPid[task.Pid]; ok {
			task.SetFiles(files)
		}
	}

	// Apply CEL filter if provided
	if celFilter != nil {
		tasks, err = celFilter.FilterProcesses(tasks)
		if err != nil {
			return fmt.Errorf("filter evaluation failed: %w", err)
		}
	}

	// Build process tree (after filtering for tree output)
	pt := tree.New()
	for _, td := range tasks {
		pt.Add(td)
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

	// Output results
	if treeFlag {
		treePrinter.PrintTree(os.Stdout)
	} else {
		tablePrinter.PrintAll(tasks)
	}

	return nil
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

// collectFilesByPid collects file descriptors and groups them by PID
func collectFilesByPid() (map[int32][]*unmarshal.FileDescriptor, error) {
	fileReader, fileCleanup, err := loaders.File()
	if err != nil {
		return nil, err
	}
	defer fileCleanup()
	defer fileReader.Close()

	filesByPid := make(map[int32][]*unmarshal.FileDescriptor)
	buf := make([]byte, unmarshal.FileDescriptor{}.Size())

	for {
		_, err := io.ReadFull(fileReader, buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read from file iterator: %w", err)
		}

		var fd unmarshal.FileDescriptor
		if err := fd.Unmarshal(buf); err != nil {
			return nil, fmt.Errorf("failed to unmarshal file descriptor: %w", err)
		}

		// Group by process (not thread)
		fdCopy := fd
		filesByPid[fd.Pid] = append(filesByPid[fd.Pid], &fdCopy)
	}

	return filesByPid, nil
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
