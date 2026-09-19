//go:build unix

package walk

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestScanSkipsFifoWithWarning verifies a FIFO in a scanned tree is never
// opened (which would block) and is skipped with a visible warning.
func TestScanSkipsFifoWithWarning(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "p"), 0o600); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.log"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var warns []string
	entries, err := Scan(root, Options{Warn: func(f string, a ...any) {
		warns = append(warns, fmt.Sprintf(f, a...))
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Path == "p" {
			t.Fatalf("fifo %q was recorded in entries", e.Path)
		}
	}
	if len(warns) == 0 {
		t.Fatal("expected a warning for the skipped fifo")
	}
}
