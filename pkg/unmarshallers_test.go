package pkg

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshalTaskDescriptor(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "test")

	rtd := rawTaskDescriptor{
		Pid:  1,
		Tid:  2,
		Ppid: 3,
		Comm: comm,
	}

	data := make([]byte, binary.Size(rtd))
	binary.LittleEndian.PutUint32(data[:4], uint32(rtd.Pid))
	binary.LittleEndian.PutUint32(data[4:8], uint32(rtd.Tid))
	binary.LittleEndian.PutUint32(data[8:12], uint32(rtd.Ppid))
	copy(data[12:], rtd.Comm[:])

	var td TaskDescriptor
	err := td.Unmarshal(data)
	require.NoError(t, err)

	require.Equal(t, rtd.Pid, td.Pid)
	require.Equal(t, rtd.Tid, td.Tid)
	require.Equal(t, rtd.Ppid, td.Ppid)
	require.Equal(t, "test", td.Comm)
}
