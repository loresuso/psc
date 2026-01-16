# psc

**psc** (ps container) is a fast process scanner that uses eBPF iterators and Google CEL to query system state with precision and full container context.

## Why psc?

### Fast Kernel-Level Access with eBPF Iterators

psc uses eBPF iterators to read process and file descriptor information directly from kernel data structures. This approach is:

- **Fast**: eBPF iterators are highly efficient compared to the proc filesystem, where traditional tooling spends most of its time executing system calls
- **Complete**: Access kernel information not traditionally exposed through `/proc`. I plan to add also a way to access certain fields of the `task_struct` on demand for advanced use, but this is just an idea
- **Tamper-resistant**: Bypasses the `/proc` filesystem entirely, providing visibility that cannot be subverted by userland rootkits or `LD_PRELOAD` tricks

### Readable Queries with CEL

Traditional Linux tools like `ps`, `lsof`, and `ss` are powerful but inflexible. They output fixed formats that require extensive piping through `grep`, `awk`, and `sed`:

```bash
# Traditional: Find nginx processes owned by root
ps aux | grep nginx | grep root | grep -v grep

# psc: Express exactly what you mean
psc 'process.name == "nginx" && process.user == "root"'
```

```bash
# Traditional: Find processes with established connections on port 443
ss -tnp | grep ESTAB | grep :443 | awk '{print $6}' | cut -d'"' -f2

# psc: One clear expression
psc 'socket.state == established && socket.dstPort == 443'
```

psc uses the [Common Expression Language (CEL)](https://github.com/google/cel-go) to filter processes. CEL expressions read almost like natural language, making your scripts self-documenting and maintainable. No more deciphering complex pipelines of `grep | awk | sed | xargs`.

The `-o` flag lets you output exactly the fields you need, eliminating post-processing entirely:

```bash
psc 'socket.state == listen' -o process.name,socket.srcPort
```

Output presets are also available to quickly print common information:
```bash
psc 'socket.type == tcp && socket.dstPort == 443' -o sockets 
```

### Native Container Context

Traditional tools have no concept of containers. Getting container information requires parsing cgroup paths, querying container runtimes, and correlating PIDs manually:

```bash
# Traditional: Find containerized processes (fragile, incomplete)
ps aux | xargs -I{} sh -c 'cat /proc/{}/cgroup 2>/dev/null | grep -q docker && echo {}'

# psc: Native container support
psc 'container.runtime == docker'
```

psc extracts container context (ID, name, image, runtime, labels) automatically for Docker, containerd, CRI-O, and Podman. Debug any container's processes, files, and network connections directly from the host:

```bash
# Show all processes in a specific container
psc 'container.name == "my-app"' --tree

# Find containers running as root
psc 'container.runtime == docker && process.user == "root"'

# List containers with their images
psc 'container.id != ""' -o process.pid,process.name,container.name,container.image
```


## Building

### Requirements

- Linux kernel 5.8 or later (eBPF iterators were introduced in this version)
- Go 1.25 or later
- Clang and LLVM
- libbpf development headers
- Linux kernel headers
- bpftool (for generating vmlinux.h)

### Install Dependencies

On Debian/Ubuntu:

```bash
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-$(uname -r)
```

On Fedora/RHEL:

```bash
sudo dnf install clang llvm libbpf-devel kernel-devel bpftool
```

### Build

```bash
# Generate vmlinux.h (required once per kernel version)
make vmlinux

# Build the binary
make build
```

Or manually:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
go generate ./...
go build -o psc
```

### Install

```bash
sudo make install
```

## Usage

psc requires **root privileges** to load eBPF programs.

### Basic Usage

```bash
# List all processes
sudo psc

# List all processes as a tree
sudo psc --tree
```

### Filtering with CEL Expressions

Pass a CEL expression as the first argument to filter processes:

```bash
# Filter by process name
psc 'process.name == "nginx"'

# Filter by user
psc 'process.user == "root"'

# Filter by command line content
psc 'process.cmdline.contains("--config")'

# Filter by PID range
psc 'process.pid > 1000 && process.pid < 2000'

# Combine conditions
psc 'process.name == "bash" || process.name == "zsh"'
```

### Container Filtering

```bash
# Show only containerized processes
psc 'container.id != ""'

# Filter by container runtime (constants: docker, containerd, crio, podman)
psc 'container.runtime == docker'

# Filter by container name
psc 'container.name == "nginx"'

# Filter by container image
psc 'container.image.contains("nginx:latest")'

# Show as tree to see container process hierarchy
psc 'container.runtime == docker' --tree
```

### Socket and File Descriptor Filtering

Understanding why a process exists often requires looking at its open file descriptors and network connections:

```bash
# Find processes with listening TCP sockets
psc 'socket.type == tcp && socket.state == listen'

# Find processes with established connections
psc 'socket.state == established'

# Find processes connected to a specific port
psc 'socket.dstPort == 443'

# Find processes using Unix sockets
psc 'socket.family == unix'

# Find processes with files open in /etc
psc 'file.path.startsWith("/etc")'
```

### Available Fields

**Process fields** (`process.X`):
- `name` - Process name (string)
- `pid` - Process ID (int)
- `ppid` - Parent process ID (int)
- `tid` - Thread ID (int)
- `euid` - Effective user ID (int)
- `ruid` - Real user ID (int)
- `suid` - Saved set-user-ID (int)
- `user` - Username (string)
- `cmdline` - Full command line (string)
- `state` - Process state (uint)

**Capability fields** (`process.capabilities.X`):
- `effective` - Effective capabilities bitmask (uint)
- `permitted` - Permitted capabilities bitmask (uint)
- `inheritable` - Inheritable capabilities bitmask (uint)

**Namespace fields** (`process.namespaces.X`):
- `net` - Network namespace inode (int)
- `pid` - PID namespace inode (int)
- `mnt` - Mount namespace inode (int)
- `uts` - UTS namespace inode (int)
- `ipc` - IPC namespace inode (int)
- `cgroup` - Cgroup namespace inode (int)

**Container fields** (`container.X`):
- `id` - Container ID (string)
- `name` - Container name (string)
- `image` - Container image (string)
- `runtime` - Container runtime (string)
- `labels` - Container labels (map)

**File/Socket fields** (`file.X` or `socket.X`):
- `path` - File path (string)
- `fd` - File descriptor number (int)
- `srcPort` - Source port (int)
- `dstPort` - Destination port (int)
- `type` - Socket type (tcp, udp)
- `state` - Socket state (for filtering, use constants like `listen`, `established`)
- `family` - Address family (unix, inet, inet6)
- `unixPath` - Unix socket path (string)
- `fdType` - FD type (file_type, socket_type)

### Available Constants

Use these without quotes in expressions:

- **Runtimes**: `docker`, `containerd`, `crio`, `podman`
- **Socket types**: `tcp`, `udp`
- **Address families**: `unix`, `inet`, `inet6`
- **Socket states** (for filtering): `established`, `listen`, `syn_sent`, `syn_recv`, `fin_wait1`, `fin_wait2`, `time_wait`, `close`, `close_wait`, `last_ack`, `closing`
- **FD types**: `file_type`, `socket_type`

> **Note**: Output uses `ss`-style state names: `ESTAB`, `LISTEN`, `SYN-SENT`, etc. For UDP sockets, only `UNCONN` (unconnected) or `ESTAB` (connected) are shown since UDP is connectionless.

### String Functions

CEL provides string manipulation functions:

- `.contains("substr")` - Check if string contains substring
- `.startsWith("prefix")` - Check if string starts with prefix
- `.endsWith("suffix")` - Check if string ends with suffix

### Options

- `--tree`, `-t` - Display processes as a tree
- `--no-color` - Disable colored output
- `-o`, `--output` - Custom output columns (comma-separated field names or preset)

### Subcommands

- `psc fields` - List all available CEL fields, constants, and output presets
- `psc version` - Show version information

### Custom Output with `-o`

The `-o` flag lets you specify exactly which fields to display. You can use **presets** for common use cases or specify individual fields.

**Presets:**
- `sockets` - Process info + full socket details (family, type, state, addresses, ports)
- `files` - Process info + file descriptor details (fd, type, path)
- `containers` - Process info + container details (name, image, runtime)
- `network` - Compact network view (pid, name, type, state, ports)

```bash
# Use a preset
psc 'socket.state == listen' -o sockets
psc 'container.id != ""' -o containers

# Or specify individual fields
psc -o process.pid,process.name,process.user
psc 'socket.state == listen' -o process.pid,process.name,socket.srcPort,socket.state
```

When the output includes file/socket fields and the filter matches multiple files per process, each match gets its own row:

```bash
$ psc 'socket.state == listen' -o network

PID      NAME      TYPE   STATE    SRCPORT   DSTPORT
1234     nginx     tcp    LISTEN   80        0
1234     nginx     tcp    LISTEN   443       0
5678     sshd      tcp    LISTEN   22        0
```

## Examples

Find all web servers:

```bash
psc 'process.name == "nginx" || process.name == "apache2" || process.name == "httpd"'
```

Find processes listening on privileged ports:

```bash
psc 'socket.state == listen && socket.srcPort < 1024'
```

Find processes in a different network namespace (useful for container/pod inspection):

```bash
psc 'process.namespaces.net != 4026531840' -o process.pid,process.name,process.namespaces.net
```

Show capabilities for privileged processes:

```bash
psc 'process.euid == 0' -o process.pid,process.name,process.capabilities.effective,process.capabilities.permitted
```

Find processes that elevated privileges via SUID binaries (real UID differs from effective UID):

```bash
psc 'process.ruid != process.euid'
```

Find processes with connections to external services:

```bash
psc 'socket.state == established && socket.dstPort == 443'
```

Show network connections with custom columns:

```bash
psc 'socket.state == established' -o process.pid,process.name,socket.srcPort,socket.dstPort,socket.dstAddr
```

## License

MIT
