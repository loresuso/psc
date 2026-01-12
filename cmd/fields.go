package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/loresuso/psc/pkg/filter"
	"github.com/spf13/cobra"
)

var fieldsCmd = &cobra.Command{
	Use:   "fields",
	Short: "List all available fields for -o output and CEL expressions",
	Long: `Display all variables, fields, and constants available for use in:
  - CEL filter expressions (the positional argument)
  - Custom column output (-o flag)

Field names use the format: variable.field (e.g., process.pid, socket.srcPort)`,
	RunE: runFields,
}

func init() {
	rootCmd.AddCommand(fieldsCmd)
}

func runFields(cmd *cobra.Command, args []string) error {
	schema := filter.GetCELSchema()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Print(`FIELDS (use with -o or in CEL expressions)
===========================================

`)

	for _, v := range schema.Variables {
		fmt.Printf("%s - %s\n", v.Name, v.Description)
		fmt.Fprintln(w, "  FIELD\tTYPE")
		fmt.Fprintln(w, "  -----\t----")
		for _, f := range v.Fields {
			fmt.Fprintf(w, "  %s\t%s\n", f.Name, f.CELType)
		}
		w.Flush()
		fmt.Println()
	}

	fmt.Print(`CONSTANTS (use in CEL expressions without quotes)
=================================================

`)
	fmt.Fprintln(w, "NAME\tTYPE\tDESCRIPTION")
	fmt.Fprintln(w, "----\t----\t-----------")
	for _, c := range schema.Constants {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.Type, c.Description)
	}
	w.Flush()

	fmt.Print(`
OUTPUT PRESETS (use with -o)
============================

  sockets     - process.pid, process.name, process.user, socket.family,
                socket.type, socket.state, socket.srcAddr, socket.srcPort,
                socket.dstAddr, socket.dstPort
  files       - process.pid, process.name, process.user, file.fd,
                file.fdType, file.path
  containers  - process.pid, process.name, process.user, container.name,
                container.image, container.runtime
  network     - process.pid, process.name, socket.type, socket.state,
                socket.srcPort, socket.dstPort

EXAMPLES
========

  # Use a preset
  psc 'socket.state == listen' -o sockets
  psc 'container.id != ""' -o containers

  # Custom output with specific fields
  psc 'socket.state == listen' -o process.pid,process.name,socket.srcPort,socket.state

  # File info
  psc 'file.path.contains("/etc")' -o process.pid,file.path,file.fdType
`)

	return nil
}
