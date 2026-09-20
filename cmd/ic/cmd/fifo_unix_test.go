//go:build unix

package cmd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCheckSingleFileFifoNoHang verifies check of a single FIFO path does
// not block opening it (the Compare single-file guard must be present too,
// not just init), and reports rather than hang.
func TestCheckSingleFileFifoNoHang(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "a.log"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(logs, "p")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	env := map[string]string{"IC_KEY": "k"}
	bl := filepath.Join(dir, "b.json")
	if code, out := runCLIIn(t, dir, dir, env, "init", "logs", "--baseline", bl); code != ExitOK {
		t.Fatalf("init: %d %s", code, out)
	}
	// check of the FIFO single-file must not hang; the fifo is not
	// baselined, so it is reported (NEW) with exit 1.
	code, out := runCLIIn(t, dir, dir, env, "check", "logs/p", "--baseline", bl)
	if code != ExitChanges {
		t.Fatalf("single-file fifo check = %d (must not hang), want 1:\n%s", code, out)
	}
}

func TestInitSingleFileFifoNoHang(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "p")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("cannot create fifo: %v", err)
	}
	// A single FIFO cannot be hashed; init must refuse (exit 2) rather
	// than hang or write an empty baseline (M4).
	code, out := runCLIIn(t, dir, dir, map[string]string{"IC_KEY": "k"},
		"init", "p", "--baseline", "b.json")
	if code != ExitError {
		t.Fatalf("single-file fifo init = %d (must not hang), want 2:\n%s", code, out)
	}
	if !contains(out, "not a regular file") {
		t.Fatalf("expected a refusal for the fifo, got: %s", out)
	}
	// And no baseline must have been written.
	if _, err := os.Stat(filepath.Join(dir, "b.json")); err == nil {
		t.Fatal("fifo init must not write a (empty) baseline")
	}
}
