//go:build unix

package cmd

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestInitSingleFileFifoNoHang verifies single-file init of a FIFO does
// not block opening it, warns, and still exits 0 with an empty baseline.
func TestInitSingleFileFifoNoHang(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", "p", "--baseline", "b.json")
	if code != ExitOK {
		t.Fatalf("single-file fifo init = %d (must not hang), want 0:\n%s", code, out)
	}
	if !contains(out, "skipping non-regular") {
		t.Fatalf("expected a skip warning for the fifo, got: %s", out)
	}
}
