package unmarshal

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const FilePathLen = 256

type FileDescriptor struct {
	Pid  int32
	Tid  int32
	Ppid int32
	Fd   int32
	Path string
}

func (f *FileDescriptor) String() string {
	return fmt.Sprintf("PID: %d, TID: %d, PPID: %d, FD: %d, Path: %s", f.Pid, f.Tid, f.Ppid, f.Fd, f.Path)
}

// rawFileDescriptor matches the C struct layout exactly
// C struct layout:
//
//	int pid;                    // offset 0, 4 bytes
//	int tid;                    // offset 4, 4 bytes
//	int ppid;                   // offset 8, 4 bytes
//	int fd;                     // offset 12, 4 bytes
//	char path[256];             // offset 16, 256 bytes
//
// Total: 272 bytes
type rawFileDescriptor struct {
	Pid  int32
	Tid  int32
	Ppid int32
	Fd   int32
	Path [FilePathLen]byte
}

func (f *FileDescriptor) Unmarshal(data []byte) error {
	if len(data) < binary.Size(rawFileDescriptor{}) {
		return fmt.Errorf("data too short: got %d bytes, need %d", len(data), binary.Size(rawFileDescriptor{}))
	}

	var raw rawFileDescriptor
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return fmt.Errorf("failed to unmarshal file descriptor: %w", err)
	}

	path := string(bytes.TrimRight(raw.Path[:], "\x00"))

	f.Pid = raw.Pid
	f.Tid = raw.Tid
	f.Ppid = raw.Ppid
	f.Fd = raw.Fd
	f.Path = path

	fmt.Println(f)

	return nil
}

// Size returns the size of the raw file descriptor in bytes
func (FileDescriptor) Size() int {
	return binary.Size(rawFileDescriptor{})
}
