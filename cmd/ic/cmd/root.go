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

// Version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// NewRootCommand builds the full command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "integrity-check",
		Short:         "Detect tampering in files against an HMAC-signed baseline",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cfgPath, "config", "", "config file (default $HOME/.config/integrity-check/config.yaml)")
	root.PersistentFlags().String("baseline", "", "baseline file path")
	root.PersistentFlags().String("algo", "", "hash algorithm: sha256|sha512|blake2b")
	root.PersistentFlags().String("format", "", "output format: text|json")
	root.PersistentFlags().Bool("color", false, "colorize output")
	root.PersistentFlags().BoolP("quiet", "q", false, "hide unmodified lines")
	root.PersistentFlags().Int("workers", 0, "hashing worker count (0 = NumCPU)")
	root.PersistentFlags().String("keyfile", "", "HMAC key file (else IC_KEY env)")
	root.PersistentFlags().String("webhook", "", "webhook URL for tamper alerts")
	root.PersistentFlags().Bool("follow-symlinks", false, "follow symlinks and hash their targets (default: record links, never follow)")
	root.PersistentFlags().StringArray("include", nil, "include globs")
	root.PersistentFlags().StringArray("exclude", nil, "exclude globs")
	root.AddCommand(newInitCmd(), newCheckCmd(), newUpdateCmd(), newWatchCmd(), newVerifyBaselineCmd())
	return root
}

// Execute runs the CLI and maps errors to exit codes.
func Execute() int {
	return ExecuteMain(os.Args[1:])
}

// ExecuteMain is the testable entrypoint returning an exit code.
func ExecuteMain(args []string) int {
	root := NewRootCommand()
	root.SetArgs(args)
	err := root.Execute()
	switch err {
	case nil:
		return ExitOK
	case errChangesFound:
		return ExitChanges
	default:
		fmt.Fprintln(os.Stderr, "error:", err)
		return ExitError
	}
}
