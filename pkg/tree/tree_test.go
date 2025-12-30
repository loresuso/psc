package tree

import (
	"bytes"
	"testing"

	"github.com/loresuso/psc/pkg"
	"github.com/stretchr/testify/require"
)

func TestProcessTree(t *testing.T) {
	pt := New()

	// Build a simple tree:
	// init (1)
	// ├── bash (100)
	// │   └── vim (200)
	// └── sshd (101)

	pt.Add(&pkg.TaskDescriptor{Pid: 1, Ppid: 0, Comm: "init"})
	pt.Add(&pkg.TaskDescriptor{Pid: 100, Ppid: 1, Comm: "bash"})
	pt.Add(&pkg.TaskDescriptor{Pid: 200, Ppid: 100, Comm: "vim"})
	pt.Add(&pkg.TaskDescriptor{Pid: 101, Ppid: 1, Comm: "sshd"})

	require.Equal(t, 4, pt.Size())

	// Test Get
	td := pt.Get(100)
	require.NotNil(t, td)
	require.Equal(t, "bash", td.Comm)

	// Test Children
	children := pt.Children(1)
	require.Len(t, children, 2)

	// Test GetLineage
	lineage, err := pt.GetLineage(200)
	require.NoError(t, err)
	require.Len(t, lineage, 3)
	require.Equal(t, int32(1), lineage[0].Pid)
	require.Equal(t, int32(100), lineage[1].Pid)
	require.Equal(t, int32(200), lineage[2].Pid)
}

func TestPrintTree(t *testing.T) {
	pt := New()
	pt.Add(&pkg.TaskDescriptor{Pid: 1, Ppid: 0, Comm: "init"})
	pt.Add(&pkg.TaskDescriptor{Pid: 100, Ppid: 1, Comm: "bash"})
	pt.Add(&pkg.TaskDescriptor{Pid: 200, Ppid: 100, Comm: "vim"})

	var buf bytes.Buffer
	NewPrinter(pt, WithColors(false)).PrintTree(&buf)

	output := buf.String()
	require.Contains(t, output, "[1] init")
	require.Contains(t, output, "[100] bash")
	require.Contains(t, output, "[200] vim")
}

func TestPrintLineages(t *testing.T) {
	pt := New()
	pt.Add(&pkg.TaskDescriptor{Pid: 1, Ppid: 0, Comm: "init"})
	pt.Add(&pkg.TaskDescriptor{Pid: 100, Ppid: 1, Comm: "bash"})
	pt.Add(&pkg.TaskDescriptor{Pid: 200, Ppid: 100, Comm: "vim"})

	var buf bytes.Buffer
	err := NewPrinter(pt, WithColors(false)).PrintLineages(&buf, []int32{200})
	require.NoError(t, err)

	output := buf.String()
	require.Contains(t, output, "[1] init")
	require.Contains(t, output, "[100] bash")
	require.Contains(t, output, "[200] vim")
}
