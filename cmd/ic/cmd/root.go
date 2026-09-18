// Package cmd wires the cobra CLI: init, check, update, watch, verify-baseline.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Exit codes per goal.md: 0 clean, 1 changes, 2 error.
const (
	ExitOK      = 0
	ExitChanges = 1
	ExitError   = 2
)

// errChangesFound signals exit code 1 (detected changes, not an error).
var errChangesFound = fmt.Errorf("changes found")

var cfgPath string

// NewRootCommand builds the full command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "integrity-check",
		Short:         "Detect tampering in files against an HMAC-signed baseline",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "config file (default $HOME/.config/integrity-check/config.yaml)")
	root.AddCommand(newInitCmd(), newCheckCmd(), newUpdateCmd(), newWatchCmd(), newVerifyBaselineCmd())
	return root
}

// Execute runs the CLI and maps errors to exit codes.
func Execute() int {
	root := NewRootCommand()
	if err := root.Execute(); err != nil {
		if err == errChangesFound {
			return ExitChanges
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitError
	}
	return ExitOK
}

// ExecuteMain is the testable entrypoint returning an exit code.
func ExecuteMain(args []string) int {
	root := NewRootCommand()
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return ExitOK
	case err == errChangesFound:
		return ExitChanges
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitError
	}
}
