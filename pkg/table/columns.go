package table

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/loresuso/psc/pkg/filter"
)

// ColumnPrinter prints match results with custom columns specified by -o flag
type ColumnPrinter struct {
	w        io.Writer
	bootTime time.Time
	columns  []filter.FieldInfo
}

// NewColumnPrinter creates a new column printer with the specified columns
func NewColumnPrinter(w io.Writer, bootTime time.Time, columnNames []string, _ bool) (*ColumnPrinter, error) {
	columns := make([]filter.FieldInfo, 0, len(columnNames))

	for _, name := range columnNames {
		field, ok := filter.GetField(name)
		if !ok {
			return nil, fmt.Errorf("unknown field: %s", name)
		}
		if field.GetValue == nil {
			return nil, fmt.Errorf("field %s is not supported for output", name)
		}
		columns = append(columns, field)
	}

	return &ColumnPrinter{
		w:        w,
		bootTime: bootTime,
		columns:  columns,
	}, nil
}

// HasFileColumns returns true if any column is from file/socket
func (p *ColumnPrinter) HasFileColumns() bool {
	for _, col := range p.columns {
		if col.Variable == "file" || col.Variable == "socket" {
			return true
		}
	}
	return false
}

// Print prints all match results with the configured columns
func (p *ColumnPrinter) Print(results []filter.MatchResult) {
	tw := tabwriter.NewWriter(p.w, 0, 0, 2, ' ', 0)

	// Print header
	p.printHeader(tw)

	// Print rows
	hasFileColumns := p.HasFileColumns()

	for _, result := range results {
		if hasFileColumns && len(result.MatchedFiles) > 0 {
			// One row per matched file
			for fileIdx := range result.MatchedFiles {
				p.printRow(tw, &result, fileIdx)
			}
		} else {
			// Single row for process (no file context or no matched files)
			p.printRow(tw, &result, -1)
		}
	}

	tw.Flush()
}

func (p *ColumnPrinter) printHeader(w *tabwriter.Writer) {
	headers := make([]string, len(p.columns))
	for i, col := range p.columns {
		// Use the field name as header (e.g., "process.pid" -> "PID", "socket.srcPort" -> "SRCPORT")
		header := strings.ToUpper(col.CELName)
		headers[i] = header
	}

	fmt.Fprintln(w, strings.Join(headers, "\t"))
}

func (p *ColumnPrinter) printRow(w *tabwriter.Writer, result *filter.MatchResult, fileIdx int) {
	values := make([]string, len(p.columns))
	for i, col := range p.columns {
		if col.GetValue != nil {
			values[i] = col.GetValue(result, fileIdx, p.bootTime)
		}
	}
	fmt.Fprintln(w, strings.Join(values, "\t"))
}

// OutputPresets defines common output column combinations
var OutputPresets = map[string][]string{
	"sockets": {
		"process.pid", "process.name", "process.user",
		"socket.family", "socket.type", "socket.state",
		"socket.srcAddr", "socket.srcPort", "socket.dstAddr", "socket.dstPort",
	},
	"files": {
		"process.pid", "process.name", "process.user",
		"file.fd", "file.fdType", "file.path",
	},
	"containers": {
		"process.pid", "process.name", "process.user",
		"container.name", "container.image", "container.runtime",
	},
	"network": {
		"process.pid", "process.name",
		"socket.type", "socket.state", "socket.srcPort", "socket.dstPort",
	},
}

// ValidateColumns checks if all column names are valid
func ValidateColumns(columnNames []string) error {
	for _, name := range columnNames {
		if _, ok := filter.GetField(name); !ok {
			return fmt.Errorf("unknown field: %s (use 'psc fields' to list available fields)", name)
		}
	}
	return nil
}

// ParseColumns parses a comma-separated column specification
// Supports presets: "sockets", "files", "containers", "network"
func ParseColumns(spec string) []string {
	if spec == "" {
		return nil
	}

	// Check for preset
	if preset, ok := OutputPresets[spec]; ok {
		return preset
	}

	parts := strings.Split(spec, ",")
	columns := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			columns = append(columns, p)
		}
	}
	return columns
}
