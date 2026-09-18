package walk

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestStatEntryOwnership verifies StatEntry records a real uid/gid on
// POSIX platforms (always nonzero for a file we just created).
func TestStatEntryOwnership(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uid/gid tracking is POSIX-only")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "f.log")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	e, err := StatEntry(f, "f.log")
	if err != nil {
		t.Fatal(err)
	}
	if e.UID == 0 || e.GID == 0 {
		t.Fatalf("uid/gid = %d/%d, want nonzero for a real file", e.UID, e.GID)
	}
}
