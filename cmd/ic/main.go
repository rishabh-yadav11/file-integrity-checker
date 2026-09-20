// Command integrity-check detects tampering in files against a signed baseline.
package main

import (
	"os"

	"github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd"
)

// exitFunc is swappable so tests can exercise main() without terminating
// the process (Q5).
var exitFunc = os.Exit

func main() {
	exitFunc(cmd.Execute())
}
