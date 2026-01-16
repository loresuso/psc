package unmarshal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/loresuso/psc/pkg/containers"
)

const TaskCommLen = 16

// Capabilities holds the Linux capability sets for a process
type Capabilities struct {
	Effective   uint64 `cel:"effective"`
	Permitted   uint64 `cel:"permitted"`
	Inheritable uint64 `cel:"inheritable"`
}

// Namespaces holds the namespace inode numbers for a process
type Namespaces struct {
	Uts    int64 `cel:"uts"`
	Ipc    int64 `cel:"ipc"`
	Mnt    int64 `cel:"mnt"`
	Pid    int64 `cel:"pid"`
	Net    int64 `cel:"net"`
	Cgroup int64 `cel:"cgroup"`
}

// ProcessState represents the Linux process state
type ProcessState uint32

const (
	TaskRunning         ProcessState = 0x00000000
	TaskInterruptible   ProcessState = 0x00000001
	TaskUninterruptible ProcessState = 0x00000002
	TaskStopped         ProcessState = 0x00000004
	TaskTraced          ProcessState = 0x00000008
	ExitDead            ProcessState = 0x00000010
	ExitZombie          ProcessState = 0x00000020
	TaskParked          ProcessState = 0x00000040
	TaskDead            ProcessState = 0x00000080
	TaskWakekill        ProcessState = 0x00000100
	TaskWaking          ProcessState = 0x00000200
	TaskNoload          ProcessState = 0x00000400
	TaskNew             ProcessState = 0x00000800
	TaskRtmutexWait     ProcessState = 0x00001000
	TaskFreezing        ProcessState = 0x00002000
	TaskFrozen          ProcessState = 0x00008000
)

// StateChar returns a single character representing the process state (like ps)
func (s ProcessState) StateChar() string {
	switch {
	case s == TaskRunning:
		return "R" // Running
	case s&ExitZombie != 0:
		return "Z" // Zombie
	case s&TaskStopped != 0:
		return "T" // Stopped
	case s&TaskTraced != 0:
		return "t" // Tracing stop
	case s&ExitDead != 0:
		return "X" // Dead
	case s&TaskDead != 0:
		return "X" // Dead
	case s&TaskUninterruptible != 0:
		return "D" // Disk sleep (uninterruptible)
	case s&TaskInterruptible != 0:
		return "S" // Sleeping (interruptible)
	case s&TaskParked != 0:
		return "P" // Parked
	case s&TaskWaking != 0:
		return "W" // Waking
	default:
		return "?" // Unknown
	}
}

type TaskDescriptor struct {
	Euid      int32                     `cel:"euid"`
	Ruid      int32                     `cel:"ruid"`
	Suid      int32                     `cel:"suid"`
	Pid       int32                     `cel:"pid"`
	Tid       int32                     `cel:"tid"`
	Ppid      int32                     `cel:"ppid"`
	State     ProcessState              `cel:"state"`
	StartTime uint64                    `cel:"startTime"` // nanoseconds since boot
	Utime     uint64                    `cel:"utime"`     // user CPU time in nanoseconds
	Stime     uint64                    `cel:"stime"`     // system CPU time in nanoseconds
	Vsz       uint64                    `cel:"vsz"`       // virtual memory size in bytes
	Rss       uint64                    `cel:"rss"`       // resident set size in bytes
	Comm      string                    `cel:"name"`      // process name (comm)
	Cmdline   string                    `cel:"cmdline"`
	User      string                    `cel:"user"`         // username resolved from Euid
	Caps      Capabilities              `cel:"capabilities"` // process capabilities
	Ns        Namespaces                `cel:"namespaces"`   // process namespaces
	Files     []*FileDescriptor         `cel:"files"`        // associated file descriptors
	Container *containers.ContainerInfo `cel:"container"`    // container info (nil if not in container)
}

// SetContainer sets the container info for this task
func (t *TaskDescriptor) SetContainer(c *containers.ContainerInfo) {
	t.Container = c
}

// InContainer returns true if this process is running in a container
func (t *TaskDescriptor) InContainer() bool {
	return t.Container != nil
}

// SetFiles sets the file descriptors for this task
func (t *TaskDescriptor) SetFiles(files []*FileDescriptor) {
	t.Files = files
}

// AddFile adds a file descriptor to this task
func (t *TaskDescriptor) AddFile(f *FileDescriptor) {
	t.Files = append(t.Files, f)
}

// GetSockets returns all socket file descriptors
func (t *TaskDescriptor) GetSockets() []*FileDescriptor {
	var sockets []*FileDescriptor
	for _, f := range t.Files {
		if f.IsSocket() {
			sockets = append(sockets, f)
		}
	}
	return sockets
}

// GetTCPSockets returns all TCP socket file descriptors
func (t *TaskDescriptor) GetTCPSockets() []*FileDescriptor {
	var sockets []*FileDescriptor
	for _, f := range t.Files {
		if f.IsTCP() {
			sockets = append(sockets, f)
		}
	}
	return sockets
}

// GetUDPSockets returns all UDP socket file descriptors
func (t *TaskDescriptor) GetUDPSockets() []*FileDescriptor {
	var sockets []*FileDescriptor
	for _, f := range t.Files {
		if f.IsUDP() {
			sockets = append(sockets, f)
		}
	}
	return sockets
}

// GetUnixSockets returns all Unix socket file descriptors
func (t *TaskDescriptor) GetUnixSockets() []*FileDescriptor {
	var sockets []*FileDescriptor
	for _, f := range t.Files {
		if f.IsUnix() {
			sockets = append(sockets, f)
		}
	}
	return sockets
}

// GetRegularFiles returns all regular file descriptors (non-sockets)
func (t *TaskDescriptor) GetRegularFiles() []*FileDescriptor {
	var files []*FileDescriptor
	for _, f := range t.Files {
		if f.IsRegularFile() {
			files = append(files, f)
		}
	}
	return files
}

// rawTaskDescriptor matches the C struct layout exactly
// C struct layout (64-bit system):
//
//	int euid;                     // offset 0, 4 bytes
//	int ruid;                     // offset 4, 4 bytes
//	int suid;                     // offset 8, 4 bytes
//	int pid;                      // offset 12, 4 bytes
//	int tid;                      // offset 16, 4 bytes
//	int ppid;                     // offset 20, 4 bytes
//	unsigned int state;           // offset 24, 4 bytes
//	<padding>                     // offset 28, 4 bytes (for 8-byte alignment)
//	unsigned long start_time;     // offset 32, 8 bytes
//	unsigned long utime;          // offset 40, 8 bytes
//	unsigned long stime;          // offset 48, 8 bytes
//	unsigned long vsz;            // offset 56, 8 bytes
//	unsigned long rss;            // offset 64, 8 bytes
//	unsigned long cap_effective;  // offset 72, 8 bytes
//	unsigned long cap_permitted;  // offset 80, 8 bytes
//	unsigned long cap_inheritable;// offset 88, 8 bytes
//	unsigned int ns_uts;          // offset 96, 4 bytes
//	unsigned int ns_ipc;          // offset 100, 4 bytes
//	unsigned int ns_mnt;          // offset 104, 4 bytes
//	unsigned int ns_pid;          // offset 108, 4 bytes
//	unsigned int ns_net;          // offset 112, 4 bytes
//	unsigned int ns_cgroup;       // offset 116, 4 bytes
//	unsigned int _pad;            // offset 120, 4 bytes
//	char comm[16];                // offset 124, 16 bytes
//
// Total: 140 bytes (+ padding to 144 for alignment)
type rawTaskDescriptor struct {
	Euid           int32
	Ruid           int32
	Suid           int32
	Pid            int32
	Tid            int32
	Ppid           int32
	State          uint32
	Pad0           uint32 // padding for 8-byte alignment
	StartTime      uint64
	Utime          uint64
	Stime          uint64
	Vsz            uint64
	Rss            uint64
	CapEffective   uint64
	CapPermitted   uint64
	CapInheritable uint64
	NsUts          uint32
	NsIpc          uint32
	NsMnt          uint32
	NsPid          uint32
	NsNet          uint32
	NsCgroup       uint32
	Pad1           uint32 // padding
	Comm           [TaskCommLen]byte
	Pad2           uint32 // end padding for 8-byte struct alignment
}

func (t *TaskDescriptor) Unmarshal(data []byte) error {
	if len(data) < binary.Size(rawTaskDescriptor{}) {
		return fmt.Errorf("data too short: got %d bytes, need %d", len(data), binary.Size(rawTaskDescriptor{}))
	}

	var raw rawTaskDescriptor
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal task descriptor: %w", err)
	}

	comm := string(bytes.TrimRight(raw.Comm[:], "\x00"))

	t.Euid = raw.Euid
	t.Ruid = raw.Ruid
	t.Suid = raw.Suid
	t.Pid = raw.Pid
	t.Tid = raw.Tid
	t.Ppid = raw.Ppid
	t.State = ProcessState(raw.State)
	t.StartTime = raw.StartTime
	t.Utime = raw.Utime
	t.Stime = raw.Stime
	t.Vsz = raw.Vsz
	t.Rss = raw.Rss
	t.Comm = comm

	// Capabilities
	t.Caps = Capabilities{
		Effective:   raw.CapEffective,
		Permitted:   raw.CapPermitted,
		Inheritable: raw.CapInheritable,
	}

	// Namespaces
	t.Ns = Namespaces{
		Uts:    int64(raw.NsUts),
		Ipc:    int64(raw.NsIpc),
		Mnt:    int64(raw.NsMnt),
		Pid:    int64(raw.NsPid),
		Net:    int64(raw.NsNet),
		Cgroup: int64(raw.NsCgroup),
	}

	return nil
}

// Size returns the size of the raw task descriptor in bytes
func (TaskDescriptor) Size() int {
	return binary.Size(rawTaskDescriptor{})
}

// Enrich reads additional info that can't be obtained from BPF.
// - cmdline: BPF iterators have restrictions on reading userspace memory
// - user: resolved from euid
func (t *TaskDescriptor) Enrich() {
	t.Cmdline = readCmdlineFromProc(t.Pid)
	t.User = lookupUsername(t.Euid)
}

// readCmdlineFromProc reads cmdline from /proc/<pid>/cmdline
func readCmdlineFromProc(pid int32) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	// cmdline uses null bytes as separators
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline)
}

// usernameCache caches UID to username lookups
var usernameCache = make(map[int32]string)

// lookupUsername resolves a UID to a username
func lookupUsername(uid int32) string {
	// Check cache first
	if name, ok := usernameCache[uid]; ok {
		return name
	}

	// Look up user by UID
	u, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		// Fall back to numeric UID
		name := strconv.Itoa(int(uid))
		usernameCache[uid] = name
		return name
	}

	usernameCache[uid] = u.Username
	return u.Username
}

// FormatStartTime formats the start time as a human-readable string
func (t *TaskDescriptor) FormatStartTime(bootTime time.Time) string {
	startTime := bootTime.Add(time.Duration(t.StartTime))
	now := time.Now()

	// If started today, show time only; otherwise show date
	if startTime.YearDay() == now.YearDay() && startTime.Year() == now.Year() {
		return startTime.Format("15:04:05")
	}
	return startTime.Format("Jan02 15:04")
}

// CpuPercent calculates CPU usage percentage
// This is a rough estimate based on total CPU time / elapsed time
func (t *TaskDescriptor) CpuPercent(bootTime time.Time) float64 {
	elapsed := time.Since(bootTime.Add(time.Duration(t.StartTime)))
	if elapsed <= 0 {
		return 0
	}

	totalCpu := time.Duration(t.Utime + t.Stime)
	return (float64(totalCpu) / float64(elapsed)) * 100.0
}
