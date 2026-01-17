package filter

import (
	"testing"

	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/unmarshal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name        string
		expression  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid simple expression",
			expression: `process.name == "nginx"`,
			wantErr:    false,
		},
		{
			name:       "valid OR expression",
			expression: `process.name == "bash" || process.name == "zsh"`,
			wantErr:    false,
		},
		{
			name:       "valid AND expression",
			expression: `process.user == "root" && process.pid > 1000`,
			wantErr:    false,
		},
		{
			name:       "valid file expression",
			expression: `file.path.startsWith("/etc/")`,
			wantErr:    false,
		},
		{
			name:       "valid socket expression",
			expression: `socket.dstPort == 443`,
			wantErr:    false,
		},
		{
			name:       "valid socket type check with constant",
			expression: `socket.type == tcp`,
			wantErr:    false,
		},
		{
			name:        "invalid - non-boolean return",
			expression:  `process.name`,
			wantErr:     true,
			errContains: "must return bool",
		},
		{
			name:        "invalid - unknown field",
			expression:  `process.unknown_field == "test"`,
			wantErr:     true,
			errContains: "compilation error",
		},
		{
			name:        "invalid - syntax error",
			expression:  `process.name ==`,
			wantErr:     true,
			errContains: "compilation error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, f)
			assert.Equal(t, tt.expression, f.Expression())
		})
	}
}

func TestMatchProcess(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		task       *unmarshal.TaskDescriptor
		want       bool
	}{
		{
			name:       "match by name",
			expression: `process.name == "nginx"`,
			task:       &unmarshal.TaskDescriptor{Comm: "nginx"},
			want:       true,
		},
		{
			name:       "no match by name",
			expression: `process.name == "nginx"`,
			task:       &unmarshal.TaskDescriptor{Comm: "apache"},
			want:       false,
		},
		{
			name:       "match by pid",
			expression: `process.pid == 1234`,
			task:       &unmarshal.TaskDescriptor{Pid: 1234},
			want:       true,
		},
		{
			name:       "match by user",
			expression: `process.user == "root"`,
			task:       &unmarshal.TaskDescriptor{User: "root"},
			want:       true,
		},
		{
			name:       "match OR expression",
			expression: `process.name == "bash" || process.name == "zsh"`,
			task:       &unmarshal.TaskDescriptor{Comm: "zsh"},
			want:       true,
		},
		{
			name:       "match AND expression",
			expression: `process.user == "root" && process.pid > 100`,
			task:       &unmarshal.TaskDescriptor{User: "root", Pid: 1000},
			want:       true,
		},
		{
			name:       "no match AND expression",
			expression: `process.user == "root" && process.pid > 100`,
			task:       &unmarshal.TaskDescriptor{User: "root", Pid: 50},
			want:       false,
		},
		{
			name:       "match contains",
			expression: `process.cmdline.contains("--config")`,
			task:       &unmarshal.TaskDescriptor{Cmdline: "nginx --config /etc/nginx.conf"},
			want:       true,
		},
		{
			name:       "match startsWith",
			expression: `process.name.startsWith("system")`,
			task:       &unmarshal.TaskDescriptor{Comm: "systemd"},
			want:       true,
		},
		{
			name:       "match ppid",
			expression: `process.ppid == 1`,
			task:       &unmarshal.TaskDescriptor{Ppid: 1},
			want:       true,
		},
		{
			name:       "complex expression",
			expression: `(process.name == "nginx" || process.name == "httpd") && process.user != "root"`,
			task:       &unmarshal.TaskDescriptor{Comm: "nginx", User: "www-data"},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			got, err := f.MatchProcess(tt.task)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchFile(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		file       *unmarshal.FileDescriptor
		want       bool
	}{
		{
			name:       "match by path",
			expression: `file.path == "/etc/passwd"`,
			file:       &unmarshal.FileDescriptor{Path: "/etc/passwd", FdType: unmarshal.FdTypeFile},
			want:       true,
		},
		{
			name:       "match path startsWith",
			expression: `file.path.startsWith("/etc/")`,
			file:       &unmarshal.FileDescriptor{Path: "/etc/nginx/nginx.conf", FdType: unmarshal.FdTypeFile},
			want:       true,
		},
		{
			name:       "match fd number",
			expression: `file.fd == 3`,
			file:       &unmarshal.FileDescriptor{Fd: 3},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			got, err := f.MatchFile(tt.file)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchSocket(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		file       *unmarshal.FileDescriptor
		want       bool
	}{
		{
			name:       "match dstPort",
			expression: `socket.dstPort == 443`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockStream,
				DstPort:    443,
			},
			want: true,
		},
		{
			name:       "match srcPort",
			expression: `socket.srcPort == 80`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockStream,
				SrcPort:    80,
			},
			want: true,
		},
		{
			name:       "match TCP by type with constant",
			expression: `socket.type == tcp`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockStream,
			},
			want: true,
		},
		{
			name:       "match UDP by type with constant",
			expression: `socket.type == udp`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockDgram,
			},
			want: true,
		},
		{
			name:       "match listening state with constant",
			expression: `socket.state == listen`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockStream,
				SockState:  unmarshal.TcpListen,
			},
			want: true,
		},
		{
			name:       "match established state with constant",
			expression: `socket.state == established`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SockType:   unmarshal.SockStream,
				SockState:  unmarshal.TcpEstablished,
			},
			want: true,
		},
		{
			name:       "match unix socket family with constant",
			expression: `socket.family == unix`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfUnix,
			},
			want: true,
		},
		{
			name:       "match port range",
			expression: `socket.dstPort >= 80 && socket.dstPort <= 443`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				DstPort:    443,
			},
			want: true,
		},
		{
			name:       "match socket with unixPath",
			expression: `socket.unixPath.contains("docker")`,
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfUnix,
				UnixPath:   "/var/run/docker.sock",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			got, err := f.MatchFile(tt.file)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchProcessWithFile(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		task       *unmarshal.TaskDescriptor
		file       *unmarshal.FileDescriptor
		want       bool
	}{
		{
			name:       "match process and socket",
			expression: `process.name == "nginx" && socket.srcPort == 80`,
			task:       &unmarshal.TaskDescriptor{Comm: "nginx"},
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SrcPort:    80,
			},
			want: true,
		},
		{
			name:       "process matches but socket doesn't",
			expression: `process.name == "nginx" && socket.srcPort == 80`,
			task:       &unmarshal.TaskDescriptor{Comm: "nginx"},
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				SrcPort:    443,
			},
			want: false,
		},
		{
			name:       "match process or socket",
			expression: `process.name == "nginx" || socket.dstPort == 443`,
			task:       &unmarshal.TaskDescriptor{Comm: "apache"},
			file: &unmarshal.FileDescriptor{
				FdType:     unmarshal.FdTypeSocket,
				SockFamily: unmarshal.AfInet,
				DstPort:    443,
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			got, err := f.MatchProcessWithFile(tt.task, tt.file)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFilterProcesses(t *testing.T) {
	tasks := []*unmarshal.TaskDescriptor{
		{Pid: 1, Comm: "systemd", User: "root"},
		{Pid: 100, Comm: "nginx", User: "www-data"},
		{Pid: 101, Comm: "nginx", User: "www-data"},
		{Pid: 200, Comm: "apache", User: "www-data"},
		{Pid: 300, Comm: "sshd", User: "root"},
	}

	tests := []struct {
		name       string
		expression string
		wantPids   []int32
	}{
		{
			name:       "filter by name",
			expression: `process.name == "nginx"`,
			wantPids:   []int32{100, 101},
		},
		{
			name:       "filter by user",
			expression: `process.user == "root"`,
			wantPids:   []int32{1, 300},
		},
		{
			name:       "filter by pid range",
			expression: `process.pid >= 100 && process.pid < 200`,
			wantPids:   []int32{100, 101},
		},
		{
			name:       "filter by name pattern",
			expression: `process.name.startsWith("ng") || process.name.startsWith("ap")`,
			wantPids:   []int32{100, 101, 200},
		},
		{
			name:       "no matches",
			expression: `process.name == "postgres"`,
			wantPids:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			result, err := f.FilterProcesses(tasks)
			require.NoError(t, err)

			var gotPids []int32
			for _, task := range result {
				gotPids = append(gotPids, task.Pid)
			}
			assert.Equal(t, tt.wantPids, gotPids)
		})
	}
}

func TestFilterFiles(t *testing.T) {
	files := []*unmarshal.FileDescriptor{
		{Fd: 0, Path: "/dev/null", FdType: unmarshal.FdTypeFile},
		{Fd: 1, Path: "/etc/passwd", FdType: unmarshal.FdTypeFile},
		{Fd: 2, Path: "/etc/shadow", FdType: unmarshal.FdTypeFile},
		{Fd: 3, FdType: unmarshal.FdTypeSocket, SockFamily: unmarshal.AfInet, SrcPort: 80},
		{Fd: 4, FdType: unmarshal.FdTypeSocket, SockFamily: unmarshal.AfInet, SrcPort: 443},
	}

	tests := []struct {
		name       string
		expression string
		wantFds    []int32
	}{
		{
			name:       "filter etc files",
			expression: `file.path.startsWith("/etc/")`,
			wantFds:    []int32{1, 2},
		},
		{
			name:       "filter sockets",
			expression: `file.fdType == uint(2)`, // FdTypeSocket
			wantFds:    []int32{3, 4},
		},
		{
			name:       "filter by port",
			expression: `socket.srcPort == 80`,
			wantFds:    []int32{3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			result, err := f.FilterFiles(files)
			require.NoError(t, err)

			var gotFds []int32
			for _, file := range result {
				gotFds = append(gotFds, file.Fd)
			}
			assert.Equal(t, tt.wantFds, gotFds)
		})
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantErr    bool
	}{
		{
			name:       "valid expression",
			expression: `process.name == "nginx"`,
			wantErr:    false,
		},
		{
			name:       "invalid - syntax error",
			expression: `process.name ==`,
			wantErr:    true,
		},
		{
			name:       "invalid - unknown field",
			expression: `process.unknown == "test"`,
			wantErr:    true,
		},
		{
			name:       "invalid - non-boolean",
			expression: `process.pid`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.expression)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewEnv(t *testing.T) {
	// Test that environment can be created and reused
	env, err := NewEnv()
	require.NoError(t, err)

	// Create multiple filters with the same env
	f1, err := NewWithEnv(env, `process.name == "nginx"`)
	require.NoError(t, err)

	f2, err := NewWithEnv(env, `process.pid > 100`)
	require.NoError(t, err)

	// Both filters should work
	task := &unmarshal.TaskDescriptor{Comm: "nginx", Pid: 200}

	match1, err := f1.MatchProcess(task)
	require.NoError(t, err)
	assert.True(t, match1)

	match2, err := f2.MatchProcess(task)
	require.NoError(t, err)
	assert.True(t, match2)
}

func TestMatchContainer(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		task       *unmarshal.TaskDescriptor
		want       bool
	}{
		{
			name:       "match container name",
			expression: `container.name == "nginx"`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:   "abc123",
					Name: "nginx",
				},
			},
			want: true,
		},
		{
			name:       "match container id",
			expression: `container.id.startsWith("abc")`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:   "abc123def456",
					Name: "nginx",
				},
			},
			want: true,
		},
		{
			name:       "match container image",
			expression: `container.image.contains("nginx")`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:    "abc123",
					Name:  "web",
					Image: "nginx:latest",
				},
			},
			want: true,
		},
		{
			name:       "match container runtime with constant",
			expression: `container.runtime == docker`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:      "abc123",
					Name:    "web",
					Runtime: "docker",
				},
			},
			want: true,
		},
		{
			name:       "check if in container using id != empty",
			expression: `container.id != ""`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:   "abc123",
					Name: "nginx",
				},
			},
			want: true,
		},
		{
			name:       "not in container - id is empty",
			expression: `container.id != ""`,
			task: &unmarshal.TaskDescriptor{
				Comm:      "nginx",
				Container: nil,
			},
			want: false,
		},
		{
			name:       "combined process and container filter",
			expression: `process.name == "nginx" && container.image.contains("nginx")`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:    "abc123",
					Name:  "web",
					Image: "nginx:1.21",
				},
			},
			want: true,
		},
		{
			name:       "container labels access",
			expression: `"app" in container.labels`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:     "abc123",
					Name:   "web",
					Labels: map[string]string{"app": "nginx", "env": "prod"},
				},
			},
			want: true,
		},
		{
			name:       "no match - wrong container name",
			expression: `container.name == "redis"`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				Container: &containers.ContainerInfo{
					ID:   "abc123",
					Name: "nginx",
				},
			},
			want: false,
		},
		{
			name:       "filter containerized processes only",
			expression: `container.id != "" && process.user == "root"`,
			task: &unmarshal.TaskDescriptor{
				Comm: "nginx",
				User: "root",
				Container: &containers.ContainerInfo{
					ID:   "abc123",
					Name: "nginx",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.expression)
			require.NoError(t, err)

			got, err := f.MatchProcess(tt.task)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Benchmark tests
func BenchmarkMatchProcess(b *testing.B) {
	f, _ := New(`process.name == "nginx" && process.user == "root"`)
	task := &unmarshal.TaskDescriptor{Comm: "nginx", User: "root", Pid: 1234}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.MatchProcess(task)
	}
}

func BenchmarkFilterProcesses(b *testing.B) {
	tasks := make([]*unmarshal.TaskDescriptor, 1000)
	for i := range tasks {
		tasks[i] = &unmarshal.TaskDescriptor{
			Pid:  int32(i),
			Comm: "process",
			User: "user",
		}
	}
	// Make some match
	for i := 0; i < 100; i++ {
		tasks[i*10].Comm = "nginx"
	}

	f, _ := New(`process.name == "nginx"`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.FilterProcesses(tasks)
	}
}
