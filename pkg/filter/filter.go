package filter

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/unmarshal"
)

// Filter holds a compiled CEL expression for filtering processes and files
type Filter struct {
	env        *cel.Env
	program    cel.Program
	expression string
}

// Type names for CEL - derived from Go's reflect package
var (
	taskType      = reflect.TypeFor[unmarshal.TaskDescriptor]()
	fileType      = reflect.TypeFor[unmarshal.FileDescriptor]()
	containerType = reflect.TypeFor[containers.ContainerInfo]()
)

// NewEnv creates a shared CEL environment with registered types.
// This can be reused across multiple filter compilations.
func NewEnv() (*cel.Env, error) {
	return cel.NewEnv(
		// Register native Go types for direct struct access
		// ParseStructTags enables using `cel:"fieldname"` struct tags
		ext.NativeTypes(
			ext.ParseStructTags(true),
			taskType,
			fileType,
			containerType,
		),

		// Declare the "process" variable as TaskDescriptor
		// Allows expressions like: process.name == "nginx"
		// Container info accessible via: process.container.name
		cel.Variable("process", cel.ObjectType(taskType.String())),

		// Declare "file" for file descriptor filtering
		// Allows expressions like: file.path.startsWith("/etc")
		cel.Variable("file", cel.ObjectType(fileType.String())),

		// Declare "socket" as an alias for file (for network filtering clarity)
		// Allows expressions like: socket.dstPort == 443
		cel.Variable("socket", cel.ObjectType(fileType.String())),

		// Declare "container" as a direct alias for process.container
		// Allows expressions like: container.name == "nginx"
		cel.Variable("container", cel.ObjectType(containerType.String())),

		// Container runtime constants
		// Usage: container.runtime == docker
		cel.Constant("docker", cel.StringType, types.String("docker")),
		cel.Constant("containerd", cel.StringType, types.String("containerd")),
		cel.Constant("crio", cel.StringType, types.String("cri-o")),
		cel.Constant("podman", cel.StringType, types.String("podman")),

		// Socket type constants (matches unmarshal.SockStream, SockDgram)
		// Usage: socket.sockType == tcp
		cel.Constant("tcp", cel.UintType, types.Uint(unmarshal.SockStream)),
		cel.Constant("udp", cel.UintType, types.Uint(unmarshal.SockDgram)),

		// Socket family constants
		// Usage: socket.sockFamily == unix
		cel.Constant("unix", cel.UintType, types.Uint(unmarshal.AfUnix)),
		cel.Constant("inet", cel.UintType, types.Uint(unmarshal.AfInet)),
		cel.Constant("inet6", cel.UintType, types.Uint(unmarshal.AfInet6)),

		// TCP state constants
		// Usage: socket.sockState == listen
		cel.Constant("established", cel.UintType, types.Uint(unmarshal.TcpEstablished)),
		cel.Constant("listen", cel.UintType, types.Uint(unmarshal.TcpListen)),
		cel.Constant("syn_sent", cel.UintType, types.Uint(unmarshal.TcpSynSent)),
		cel.Constant("syn_recv", cel.UintType, types.Uint(unmarshal.TcpSynRecv)),
		cel.Constant("fin_wait1", cel.UintType, types.Uint(unmarshal.TcpFinWait1)),
		cel.Constant("fin_wait2", cel.UintType, types.Uint(unmarshal.TcpFinWait2)),
		cel.Constant("time_wait", cel.UintType, types.Uint(unmarshal.TcpTimeWait)),
		cel.Constant("close", cel.UintType, types.Uint(unmarshal.TcpClose)),
		cel.Constant("close_wait", cel.UintType, types.Uint(unmarshal.TcpCloseWait)),
		cel.Constant("last_ack", cel.UintType, types.Uint(unmarshal.TcpLastAck)),
		cel.Constant("closing", cel.UintType, types.Uint(unmarshal.TcpClosing)),

		// File descriptor type constants
		// Usage: file.fdType == socket_type
		cel.Constant("file_type", cel.UintType, types.Uint(unmarshal.FdTypeFile)),
		cel.Constant("socket_type", cel.UintType, types.Uint(unmarshal.FdTypeSocket)),

		// Enable useful string extensions
		// Adds: .contains(), .startsWith(), .endsWith(), .split(), etc.
		ext.Strings(),
	)
}

// New compiles a CEL expression into a Filter.
// The expression should return a boolean value.
//
// Available variables:
//   - process: TaskDescriptor with fields: name, pid, ppid, tid, euid, user, cmdline, state, files, etc.
//   - file: FileDescriptor with fields: path, fd, srcPort, dstPort, protocol, etc.
//   - socket: Alias for file, use for network-related filtering
//
// Example expressions:
//   - process.name == "nginx"
//   - process.name == "bash" || process.name == "zsh"
//   - process.user == "root" && process.pid > 1000
//   - file.path.startsWith("/etc/")
//   - socket.dstPort == 443
//   - socket.Protocol() == "tcp" && socket.IsListening()
func New(expression string) (*Filter, error) {
	env, err := NewEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return NewWithEnv(env, expression)
}

// NewWithEnv compiles a CEL expression using a pre-created environment.
// Use this when compiling multiple filters to avoid recreating the environment.
func NewWithEnv(env *cel.Env, expression string) (*Filter, error) {
	// Parse and type-check the expression
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	// Ensure expression returns bool
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("expression must return bool, got %s", ast.OutputType())
	}

	// Create the executable program
	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return &Filter{
		env:        env,
		program:    program,
		expression: expression,
	}, nil
}

// Expression returns the original CEL expression string
func (f *Filter) Expression() string {
	return f.expression
}

// MatchProcess evaluates the filter against a TaskDescriptor.
// Use this for process-only filtering expressions.
func (f *Filter) MatchProcess(task *unmarshal.TaskDescriptor) (bool, error) {
	// Use EmptyContainer for non-containerized processes to allow safe field access
	container := task.Container
	if container == nil {
		container = containers.EmptyContainer
	}

	result, _, err := f.program.Eval(map[string]any{
		"process":   task,
		"container": container, // Always provide a valid container (empty if not containerized)
		// Provide empty file/socket to allow safe field access
		"file":   unmarshal.EmptyFileDescriptor,
		"socket": unmarshal.EmptyFileDescriptor,
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	b, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result type: %T", result.Value())
	}
	return b, nil
}

// MatchFile evaluates the filter against a FileDescriptor.
// Use this for file/socket-only filtering expressions.
func (f *Filter) MatchFile(file *unmarshal.FileDescriptor) (bool, error) {
	// Ensure file is not nil
	if file == nil {
		file = unmarshal.EmptyFileDescriptor
	}

	result, _, err := f.program.Eval(map[string]any{
		"file":      file,
		"socket":    file, // socket is an alias for file
		"process":   &unmarshal.TaskDescriptor{Container: containers.EmptyContainer},
		"container": containers.EmptyContainer,
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	b, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result type: %T", result.Value())
	}
	return b, nil
}

// MatchProcessWithFile evaluates the filter with both process and file context.
// Use this for combined expressions like: process.name == "nginx" && socket.dstPort == 80
func (f *Filter) MatchProcessWithFile(task *unmarshal.TaskDescriptor, file *unmarshal.FileDescriptor) (bool, error) {
	// Use EmptyContainer for non-containerized processes
	container := task.Container
	if container == nil {
		container = containers.EmptyContainer
	}

	result, _, err := f.program.Eval(map[string]any{
		"process":   task,
		"container": container,
		"file":      file,
		"socket":    file, // socket is an alias for file
	})
	if err != nil {
		return false, fmt.Errorf("CEL evaluation error: %w", err)
	}

	b, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result type: %T", result.Value())
	}
	return b, nil
}

// FilterProcesses filters a slice of TaskDescriptors, returning only those that match.
// If a process has files/sockets, the filter is evaluated against each file.
// A process matches if:
//   - The process-only filter matches, OR
//   - Any of the process's files match when evaluated with MatchProcessWithFile
func (f *Filter) FilterProcesses(tasks []*unmarshal.TaskDescriptor) ([]*unmarshal.TaskDescriptor, error) {
	var result []*unmarshal.TaskDescriptor
	for _, task := range tasks {
		matched := false

		// If task has files, try matching with each file
		if len(task.Files) > 0 {
			for _, file := range task.Files {
				match, err := f.MatchProcessWithFile(task, file)
				if err != nil {
					// If file matching fails, fall back to process-only match
					break
				}
				if match {
					matched = true
					break
				}
			}
		}

		// If no file matched (or no files), try process-only match
		if !matched {
			match, err := f.MatchProcess(task)
			if err != nil {
				return nil, err
			}
			matched = match
		}

		if matched {
			result = append(result, task)
		}
	}
	return result, nil
}

// FilterFiles filters a slice of FileDescriptors, returning only those that match.
func (f *Filter) FilterFiles(files []*unmarshal.FileDescriptor) ([]*unmarshal.FileDescriptor, error) {
	var result []*unmarshal.FileDescriptor
	for _, file := range files {
		match, err := f.MatchFile(file)
		if err != nil {
			return nil, err
		}
		if match {
			result = append(result, file)
		}
	}
	return result, nil
}

// Validate checks if a CEL expression is valid without creating a full Filter.
// Returns nil if valid, or an error describing the problem.
func Validate(expression string) error {
	env, err := NewEnv()
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid expression: %w", issues.Err())
	}

	if ast.OutputType() != cel.BoolType {
		return fmt.Errorf("expression must return bool, got %s", ast.OutputType())
	}

	return nil
}
