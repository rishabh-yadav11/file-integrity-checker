//go:build unix

package baseline

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSavePerms0600 verifies a saved baseline is 0600. POSIX-only: on
// Windows Mode().Perm() is a constant 0666, so this is guarded by the
// unix build tag (M11).
func TestSavePerms0600(t *testing.T) {
	t.Parallel()
	st, _ := New(testKey())
	path := filepath.Join(t.TempDir(), "b.json")
	if err := st.Save(path, sampleBaseline(time.Now())); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline perms = %v, want -rw-------", info.Mode().Perm())
	}
}

// TestSaveCreatesMissingParentDir verifies Save creates the baseline's
// parent directory (0700) instead of failing when it does not exist.
// POSIX-only (Mode().Perm check), guarded by the unix build tag (M11).
func TestSaveCreatesMissingParentDir(t *testing.T) {
	t.Parallel()
	st, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state", "nested", "baseline.json")
	if err := st.Save(path, sampleBaseline(time.Now().UTC())); err != nil {
		t.Fatalf("Save into missing dir: %v", err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode = %v (%v), want 0700", fi.Mode().Perm(), err)
	}
	if _, err := st.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
}
