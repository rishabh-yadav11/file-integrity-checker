// Command integrity-check detects tampering in files against a signed baseline.
package main

import (
	"os"

	"github.com/rishabh-yadav11/file-integrity-checker/cmd/ic/cmd"
)

func main() {
	os.Exit(cmd.Execute())
}
