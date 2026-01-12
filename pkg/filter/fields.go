package filter

import (
	"fmt"
	"reflect"
	"time"

	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/unmarshal"
)

// FieldInfo describes a CEL-accessible field
type FieldInfo struct {
	Name     string       // Full qualified name (e.g., "process.pid", "socket.srcPort")
	CELName  string       // CEL field name from struct tag
	GoName   string       // Go field name
	Type     reflect.Type // Go type
	CELType  string       // CEL-friendly type description
	Variable string       // Parent variable name (process, container, file, socket)
	GetValue FieldGetter  // Function to extract value from match result
}

// FieldGetter extracts a field value from a MatchResult and file index
type FieldGetter func(result *MatchResult, fileIdx int, bootTime time.Time) string

// VariableInfo describes a CEL variable
type VariableInfo struct {
	Name        string      // Variable name (e.g., "process", "container")
	Description string      // Human-readable description
	Fields      []FieldInfo // Available fields
}

// ConstantInfo describes a CEL constant
type ConstantInfo struct {
	Name        string // Constant name (e.g., "docker", "tcp")
	Type        string // CEL type
	Description string // Human-readable description
}

// CELSchema contains all available CEL variables, fields, and constants
type CELSchema struct {
	Variables []VariableInfo
	Constants []ConstantInfo
	// FieldMap provides fast lookup by qualified name (e.g., "process.pid")
	FieldMap map[string]FieldInfo
}

// schema is the cached CEL schema
var schema *CELSchema

// GetCELSchema returns the complete CEL schema with all variables, fields, and constants
func GetCELSchema() *CELSchema {
	if schema != nil {
		return schema
	}

	schema = &CELSchema{
		Variables: []VariableInfo{
			{
				Name:        "process",
				Description: "Process information",
				Fields:      extractFieldsWithGetters("process", reflect.TypeFor[unmarshal.TaskDescriptor](), processFieldGetters),
			},
			{
				Name:        "process.capabilities",
				Description: "Process capabilities (effective, permitted, inheritable)",
				Fields:      extractFieldsWithGetters("process.capabilities", reflect.TypeFor[unmarshal.Capabilities](), capabilitiesFieldGetters),
			},
			{
				Name:        "process.namespaces",
				Description: "Process namespace inode numbers",
				Fields:      extractFieldsWithGetters("process.namespaces", reflect.TypeFor[unmarshal.Namespaces](), namespacesFieldGetters),
			},
			{
				Name:        "container",
				Description: "Container information (empty if not in container)",
				Fields:      extractFieldsWithGetters("container", reflect.TypeFor[containers.ContainerInfo](), containerFieldGetters),
			},
			{
				Name:        "file",
				Description: "File descriptor information",
				Fields:      extractFieldsWithGetters("file", reflect.TypeFor[unmarshal.FileDescriptor](), fileFieldGetters),
			},
			{
				Name:        "socket",
				Description: "Socket information (alias for file)",
				Fields:      extractFieldsWithGetters("socket", reflect.TypeFor[unmarshal.FileDescriptor](), socketFieldGetters),
			},
		},
		Constants: []ConstantInfo{
			// Container runtimes
			{Name: "docker", Type: "string", Description: "Docker runtime"},
			{Name: "containerd", Type: "string", Description: "containerd runtime"},
			{Name: "crio", Type: "string", Description: "CRI-O runtime"},
			{Name: "podman", Type: "string", Description: "Podman runtime"},
			// Socket types
			{Name: "tcp", Type: "uint", Description: "TCP socket type"},
			{Name: "udp", Type: "uint", Description: "UDP socket type"},
			// Socket families
			{Name: "unix", Type: "uint", Description: "Unix socket family"},
			{Name: "inet", Type: "uint", Description: "IPv4 socket family"},
			{Name: "inet6", Type: "uint", Description: "IPv6 socket family"},
			// TCP states
			{Name: "established", Type: "uint", Description: "TCP established state"},
			{Name: "listen", Type: "uint", Description: "TCP listen state"},
			{Name: "syn_sent", Type: "uint", Description: "TCP SYN sent state"},
			{Name: "syn_recv", Type: "uint", Description: "TCP SYN received state"},
			{Name: "fin_wait1", Type: "uint", Description: "TCP FIN wait 1 state"},
			{Name: "fin_wait2", Type: "uint", Description: "TCP FIN wait 2 state"},
			{Name: "time_wait", Type: "uint", Description: "TCP time wait state"},
			{Name: "close", Type: "uint", Description: "TCP close state"},
			{Name: "close_wait", Type: "uint", Description: "TCP close wait state"},
			{Name: "last_ack", Type: "uint", Description: "TCP last ACK state"},
			{Name: "closing", Type: "uint", Description: "TCP closing state"},
			// FD types
			{Name: "file_type", Type: "uint", Description: "Regular file descriptor type"},
			{Name: "socket_type", Type: "uint", Description: "Socket file descriptor type"},
		},
		FieldMap: make(map[string]FieldInfo),
	}

	// Build field map for fast lookup
	for _, v := range schema.Variables {
		for _, f := range v.Fields {
			schema.FieldMap[f.Name] = f
		}
	}

	return schema
}

// GetField returns field info by qualified name (e.g., "process.pid")
func GetField(name string) (FieldInfo, bool) {
	schema := GetCELSchema()
	f, ok := schema.FieldMap[name]
	return f, ok
}

// HasFileFields returns true if any of the field names refer to file/socket fields
func HasFileFields(fieldNames []string) bool {
	for _, name := range fieldNames {
		if f, ok := GetField(name); ok {
			if f.Variable == "file" || f.Variable == "socket" {
				return true
			}
		}
	}
	return false
}

// extractFieldsWithGetters uses reflection to extract CEL field information from a struct type
func extractFieldsWithGetters(variable string, t reflect.Type, getters map[string]FieldGetter) []FieldInfo {
	var fields []FieldInfo

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Get the cel tag
		celTag := field.Tag.Get("cel")
		if celTag == "" || celTag == "-" {
			continue
		}

		qualifiedName := variable + "." + celTag
		getter := getters[celTag]

		fields = append(fields, FieldInfo{
			Name:     qualifiedName,
			CELName:  celTag,
			GoName:   field.Name,
			Type:     field.Type,
			CELType:  goCELType(field.Type),
			Variable: variable,
			GetValue: getter,
		})
	}

	return fields
}

// goCELType converts a Go type to a CEL-friendly type description
func goCELType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "int"
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Bool:
		return "bool"
	case reflect.Float32, reflect.Float64:
		return "double"
	case reflect.Slice:
		elemType := goCELType(t.Elem())
		return fmt.Sprintf("list(%s)", elemType)
	case reflect.Map:
		keyType := goCELType(t.Key())
		valType := goCELType(t.Elem())
		return fmt.Sprintf("map(%s, %s)", keyType, valType)
	case reflect.Ptr:
		return goCELType(t.Elem())
	case reflect.Struct:
		return t.Name()
	default:
		return t.String()
	}
}

// Field getters for process fields
var processFieldGetters = map[string]FieldGetter{
	"pid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Pid)
	},
	"ppid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ppid)
	},
	"tid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Tid)
	},
	"euid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Euid)
	},
	"ruid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ruid)
	},
	"suid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Suid)
	},
	"user": func(r *MatchResult, _ int, _ time.Time) string {
		return r.Task.User
	},
	"name": func(r *MatchResult, _ int, _ time.Time) string {
		return r.Task.Comm
	},
	"cmdline": func(r *MatchResult, _ int, _ time.Time) string {
		return r.Task.Cmdline
	},
	"state": func(r *MatchResult, _ int, _ time.Time) string {
		return r.Task.State.StateChar()
	},
	"startTime": func(r *MatchResult, _ int, bootTime time.Time) string {
		return r.Task.FormatStartTime(bootTime)
	},
	"utime": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Utime)
	},
	"stime": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Stime)
	},
	"vsz": func(r *MatchResult, _ int, _ time.Time) string {
		return unmarshal.FormatMemory(r.Task.Vsz)
	},
	"rss": func(r *MatchResult, _ int, _ time.Time) string {
		return unmarshal.FormatMemory(r.Task.Rss)
	},
}

// Field getters for capabilities (accessed via process.capabilities.X)
var capabilitiesFieldGetters = map[string]FieldGetter{
	"effective": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("0x%016x", r.Task.Caps.Effective)
	},
	"permitted": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("0x%016x", r.Task.Caps.Permitted)
	},
	"inheritable": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("0x%016x", r.Task.Caps.Inheritable)
	},
}

// Field getters for namespaces (accessed via process.namespaces.X)
var namespacesFieldGetters = map[string]FieldGetter{
	"uts": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Uts)
	},
	"ipc": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Ipc)
	},
	"mnt": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Mnt)
	},
	"pid": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Pid)
	},
	"net": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Net)
	},
	"cgroup": func(r *MatchResult, _ int, _ time.Time) string {
		return fmt.Sprintf("%d", r.Task.Ns.Cgroup)
	},
}

// Field getters for container fields
var containerFieldGetters = map[string]FieldGetter{
	"id": func(r *MatchResult, _ int, _ time.Time) string {
		if r.Task.Container == nil {
			return ""
		}
		return r.Task.Container.ID
	},
	"name": func(r *MatchResult, _ int, _ time.Time) string {
		if r.Task.Container == nil {
			return ""
		}
		return r.Task.Container.Name
	},
	"image": func(r *MatchResult, _ int, _ time.Time) string {
		if r.Task.Container == nil {
			return ""
		}
		return r.Task.Container.Image
	},
	"runtime": func(r *MatchResult, _ int, _ time.Time) string {
		if r.Task.Container == nil {
			return ""
		}
		return r.Task.Container.Runtime
	},
}

// getFileFromResult safely gets the file at index, or nil
func getFileFromResult(r *MatchResult, idx int) *unmarshal.FileDescriptor {
	if idx < 0 || idx >= len(r.MatchedFiles) {
		return nil
	}
	return r.MatchedFiles[idx]
}

// Field getters for file fields
var fileFieldGetters = map[string]FieldGetter{
	"path": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil {
			return ""
		}
		return f.Path
	},
	"fd": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil {
			return ""
		}
		return fmt.Sprintf("%d", f.Fd)
	},
	"fdType": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil {
			return ""
		}
		switch f.FdType {
		case unmarshal.FdTypeFile:
			return "file"
		case unmarshal.FdTypeSocket:
			return "socket"
		default:
			return "other"
		}
	},
	"family": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket {
			return ""
		}
		switch f.SockFamily {
		case unmarshal.AfUnix:
			return "unix"
		case unmarshal.AfInet:
			return "inet"
		case unmarshal.AfInet6:
			return "inet6"
		default:
			return ""
		}
	},
	"type": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket {
			return ""
		}
		switch f.SockType {
		case unmarshal.SockStream:
			return "tcp"
		case unmarshal.SockDgram:
			return "udp"
		default:
			return ""
		}
	},
	"state": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket {
			return ""
		}
		return f.StateString()
	},
	"srcPort": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket {
			return ""
		}
		if f.SockFamily == unmarshal.AfUnix {
			return ""
		}
		return fmt.Sprintf("%d", f.SrcPort)
	},
	"dstPort": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket {
			return ""
		}
		if f.SockFamily == unmarshal.AfUnix {
			return ""
		}
		return fmt.Sprintf("%d", f.DstPort)
	},
	"srcAddr": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket || f.SrcAddr == nil {
			return ""
		}
		return f.SrcAddr.String()
	},
	"dstAddr": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil || f.FdType != unmarshal.FdTypeSocket || f.DstAddr == nil {
			return ""
		}
		return f.DstAddr.String()
	},
	"unixPath": func(r *MatchResult, idx int, _ time.Time) string {
		f := getFileFromResult(r, idx)
		if f == nil {
			return ""
		}
		return f.UnixPath
	},
}

// socketFieldGetters are the same as fileFieldGetters (socket is an alias)
var socketFieldGetters = fileFieldGetters
