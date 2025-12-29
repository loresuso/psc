package pkg

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Unmarshaller interface {
	Unmarshal(data []byte) (interface{}, error)
}

const TaskCommLen = 16

type TaskDescriptor struct {
	Pid  int32
	Tid  int32
	Ppid int32
	Comm string
}

// rawTaskDescriptor matches the C struct layout exactly
type rawTaskDescriptor struct {
	Pid  int32
	Tid  int32
	Ppid int32
	Comm [TaskCommLen]byte
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

	t.Pid = raw.Pid
	t.Tid = raw.Tid
	t.Ppid = raw.Ppid
	t.Comm = comm

	return nil
}

// Size returns the size of the raw task descriptor in bytes
func (TaskDescriptor) Size() int {
	return binary.Size(rawTaskDescriptor{})
}
