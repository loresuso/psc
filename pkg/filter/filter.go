package filter

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
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
	taskType = reflect.TypeFor[unmarshal.TaskDescriptor]()
	fileType = reflect.TypeFor[unmarshal.FileDescriptor]()
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
		),

		// Declare the "process" variable as TaskDescriptor
		// Allows expressions like: process.name == "nginx"
		cel.Variable("process", cel.ObjectType(taskType.String())),

		// Declare "file" for file descriptor filtering
		// Allows expressions like: file.path.startsWith("/etc")
		cel.Variable("file", cel.ObjectType(fileType.String())),

		// Declare "socket" as an alias for file (for network filtering clarity)
		// Allows expressions like: socket.dstPort == 443
		cel.Variable("socket", cel.ObjectType(fileType.String())),

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
	result, _, err := f.program.Eval(map[string]any{
		"process": task,
		// Provide nil for file/socket to allow process-only expressions
		"file":   (*unmarshal.FileDescriptor)(nil),
		"socket": (*unmarshal.FileDescriptor)(nil),
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
	result, _, err := f.program.Eval(map[string]any{
		"file":    file,
		"socket":  file, // socket is an alias for file
		"process": (*unmarshal.TaskDescriptor)(nil),
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
	result, _, err := f.program.Eval(map[string]any{
		"process": task,
		"file":    file,
		"socket":  file, // socket is an alias for file
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
func (f *Filter) FilterProcesses(tasks []*unmarshal.TaskDescriptor) ([]*unmarshal.TaskDescriptor, error) {
	var result []*unmarshal.TaskDescriptor
	for _, task := range tasks {
		match, err := f.MatchProcess(task)
		if err != nil {
			return nil, err
		}
		if match {
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
