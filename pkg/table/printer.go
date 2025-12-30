package table

import (
	"fmt"
	"io"
	"time"

	"github.com/fatih/color"
	"github.com/loresuso/psc/pkg/containers"
	"github.com/loresuso/psc/pkg/unmarshal"
)

// Printer handles table printing with various options.
type Printer struct {
	containerMgr *containers.Manager
	bootTime     time.Time
	colored      bool
	w            io.Writer
}

// Color definitions (bright/high-intensity variants)
var (
	pidColor       = color.New(color.FgHiCyan, color.Bold)
	commColor      = color.New(color.FgHiWhite)
	containerColor = color.New(color.FgHiGreen, color.Bold)
	headerColor    = color.New(color.FgHiYellow, color.Bold)
	separatorColor = color.New(color.FgHiBlack)
	stateColor     = color.New(color.FgHiMagenta)
	cpuColor       = color.New(color.FgHiYellow)
	memColor       = color.New(color.FgHiBlue)
)

type PrintOption func(*Printer)

// NewPrinter creates a new table Printer.
func NewPrinter(w io.Writer, bootTime time.Time, opts ...PrintOption) *Printer {
	p := &Printer{
		w:        w,
		bootTime: bootTime,
		colored:  true,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// WithContainers sets the container manager for container labels.
func WithContainers(mgr *containers.Manager) PrintOption {
	return func(p *Printer) {
		p.containerMgr = mgr
	}
}

// WithColors enables or disables colored output.
func WithColors(colored bool) PrintOption {
	return func(p *Printer) {
		p.colored = colored
	}
}

// PrintAll prints all tasks in a table.
func (p *Printer) PrintAll(tasks []*unmarshal.TaskDescriptor) {
	p.printHeader()
	for _, td := range tasks {
		p.printRow(td)
	}
}

// PrintPIDs prints only the specified PIDs.
func (p *Printer) PrintPIDs(tasks []*unmarshal.TaskDescriptor, pids []int32) {
	pidSet := make(map[int32]bool)
	for _, pid := range pids {
		pidSet[pid] = true
	}

	p.printHeader()
	for _, td := range tasks {
		if pidSet[td.Pid] {
			p.printRow(td)
		}
	}
}

// PrintLineage prints all processes in the lineage of the specified PIDs.
func (p *Printer) PrintLineage(tasks []*unmarshal.TaskDescriptor, lineagePids map[int32]bool) {
	p.printHeader()
	for _, td := range tasks {
		if lineagePids[td.Pid] {
			p.printRow(td)
		}
	}
}

func (p *Printer) printHeader() {
	if p.colored {
		headerColor.Fprintf(p.w, "%-10s %-8s %-8s %-8s %-2s %5s %8s %8s %-11s %-16s %s\n",
			"USER", "PID", "TID", "PPID", "S", "%CPU", "VSZ", "RSS", "START", "COMM", "CMDLINE (CONTAINER)")
		separatorColor.Fprintln(p.w, "---------- -------- -------- -------- -- ----- -------- -------- ----------- ---------------- -------------------")
	} else {
		fmt.Fprintf(p.w, "%-10s %-8s %-8s %-8s %-2s %5s %8s %8s %-11s %-16s %s\n",
			"USER", "PID", "TID", "PPID", "S", "%CPU", "VSZ", "RSS", "START", "COMM", "CMDLINE (CONTAINER)")
		fmt.Fprintln(p.w, "---------- -------- -------- -------- -- ----- -------- -------- ----------- ---------------- -------------------")
	}
}

func (p *Printer) printRow(td *unmarshal.TaskDescriptor) {
	user := td.User
	if len(user) > 10 {
		user = user[:9] + "+"
	}

	container := p.getContainerLabel(td.Pid)

	if p.colored {
		fmt.Fprintf(p.w, "%-10s ", user)
		pidColor.Fprintf(p.w, "%-8d ", td.Pid)
		fmt.Fprintf(p.w, "%-8d %-8d ", td.Tid, td.Ppid)
		stateColor.Fprintf(p.w, "%-2s ", td.State.StateChar())
		cpuColor.Fprintf(p.w, "%5.1f ", td.CpuPercent(p.bootTime))
		memColor.Fprintf(p.w, "%8s %8s ", unmarshal.FormatMemory(td.Vsz), unmarshal.FormatMemory(td.Rss))
		fmt.Fprintf(p.w, "%-11s ", td.FormatStartTime(p.bootTime))
		commColor.Fprintf(p.w, "%-16s ", td.Comm)
		fmt.Fprintf(p.w, "%s", td.Cmdline)
		if container != "" {
			containerColor.Fprintf(p.w, " (%s)", container)
		}
	} else {
		fmt.Fprintf(p.w, "%-10s %-8d %-8d %-8d %-2s %5.1f %8s %8s %-11s %-16s %s",
			user, td.Pid, td.Tid, td.Ppid, td.State.StateChar(),
			td.CpuPercent(p.bootTime), unmarshal.FormatMemory(td.Vsz), unmarshal.FormatMemory(td.Rss),
			td.FormatStartTime(p.bootTime), td.Comm, td.Cmdline)
		if container != "" {
			fmt.Fprintf(p.w, " (%s)", container)
		}
	}
	fmt.Fprintln(p.w)
}

func (p *Printer) getContainerLabel(pid int32) string {
	if p.containerMgr == nil {
		return ""
	}
	c := p.containerMgr.GetContainerByPID(pid)
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s", c.Name, c.ID, c.Runtime)
}
