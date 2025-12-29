package pkg

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnmarshalTaskDescriptor(t *testing.T) {
	var comm [TaskCommLen]byte
	copy(comm[:], "test")

	rtd := rawTaskDescriptor{
		Euid:      1000,
		Pid:       1,
		Tid:       2,
		Ppid:      3,
		State:     0x01, // TaskInterruptible (S)
		StartTime: 1000000000,
		Utime:     500000000,
		Stime:     250000000,
		Vsz:       4096 * 1000,
		Rss:       4096 * 500,
		Comm:      comm,
	}

	// Use binary.Write to create properly encoded data
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, &rtd)
	require.NoError(t, err)

	data := buf.Bytes()

	var td TaskDescriptor
	err = td.Unmarshal(data)
	require.NoError(t, err)

	require.Equal(t, rtd.Euid, td.Euid)
	require.Equal(t, rtd.Pid, td.Pid)
	require.Equal(t, rtd.Tid, td.Tid)
	require.Equal(t, rtd.Ppid, td.Ppid)
	require.Equal(t, ProcessState(rtd.State), td.State)
	require.Equal(t, rtd.StartTime, td.StartTime)
	require.Equal(t, rtd.Utime, td.Utime)
	require.Equal(t, rtd.Stime, td.Stime)
	require.Equal(t, rtd.Vsz, td.Vsz)
	require.Equal(t, rtd.Rss, td.Rss)
	require.Equal(t, "test", td.Comm)
	// cmdline and user are populated separately via Enrich()
	require.Equal(t, "", td.Cmdline)
	require.Equal(t, "", td.User)
}

func TestStateChar(t *testing.T) {
	tests := []struct {
		state    ProcessState
		expected string
	}{
		{TaskRunning, "R"},
		{TaskInterruptible, "S"},
		{TaskUninterruptible, "D"},
		{TaskStopped, "T"},
		{TaskTraced, "t"},
		{ExitZombie, "Z"},
		{ExitDead, "X"},
	}

	for _, tt := range tests {
		require.Equal(t, tt.expected, tt.state.StateChar())
	}
}
